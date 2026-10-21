"""Port discovery and Azure inventory coverage without contacting Azure or public IPs."""
import contextlib
import csv
import io
import json
from pathlib import Path
import socket
import selectors
import tempfile
import threading
import unittest
from unittest.mock import patch

from test_web_scan import scanner, local_server, response
from azure_php_scout.inventory import normalize_resources, graph_resources, discover_azure
from azure_php_scout.discovery import discover_open_ports
from azure_php_scout.report import write_html_report


class AzureInventoryTests(unittest.TestCase):
    def test_vm_nic_public_ip_and_all_platform_hostnames(self):
        records = [
            dict(id='/vm/one', name='vm1', type='Microsoft.Compute/virtualMachines', subscriptionId='s',
                 nics=[dict(id='/NIC/ONE')], os='Linux', powerState='PowerState/running'),
            dict(id='/nic/one', name='nic1', type='microsoft.network/networkinterfaces',
                 ipConfigurations=[dict(properties=dict(publicIPAddress=dict(id='/PIP/ONE')))]),
            dict(id='/pip/one', name='pip1', type='microsoft.network/publicipaddresses',
                 publicIp='192.0.2.1', publicFqdn='vm.example.test'),
            dict(id='/vm/private', name='private-vm', type='microsoft.compute/virtualmachines', subscriptionId='s'),
            dict(id='/app/one', name='app1', type='microsoft.web/sites', subscriptionId='s',
                 defaultHostName='app.azurewebsites.net', hostNames=['app.azurewebsites.net', 'shop.example.test'],
                 hostNameSslStates=[dict(name='app.scm.azurewebsites.net', hostType='Repository')],
                 phpVersion='5.6', state='Running'),
            dict(id='/static/one', name='static1', type='microsoft.web/staticSites', subscriptionId='s',
                 defaultHostName='static.azurestaticapps.net', customDomains=['www.example.test', dict(name='other.example.test')])]
        result = normalize_resources(records, [dict(id='s', name='Customer')])
        self.assertEqual(result.resources, dict(vm=2, appservice=1, staticwebapp=1))
        self.assertEqual(len(result.skipped), 1)
        self.assertEqual(len(result.rows), 7)
        self.assertEqual({row['hostname'] for row in result.rows if row['resourceType'] == 'staticwebapp'},
                         {'static.azurestaticapps.net', 'www.example.test', 'other.example.test'})
        self.assertFalse(any('.scm.' in row['hostname'] for row in result.rows))
        app = next(row for row in result.rows if row['resourceType'] == 'appservice')
        self.assertEqual(app['phpVersion'], '5.6')
        self.assertNotIn('php', app)
        self.assertTrue(all(row['subscription'] == 'Customer' for row in result.rows))

    def test_all_continuation_pages_and_subscription_context(self):
        calls = []
        def runner(args):
            calls.append(args)
            return dict(data=[dict(id='second')], total_records=2) if '--skip-token' in args else dict(
                data=[dict(id='first')], total_records=2, skip_token='next')
        records = graph_resources(['s1', 's2'], runner)
        self.assertEqual([row['id'] for row in records], ['first', 'second'])
        self.assertIn('--skip-token', calls[1])
        self.assertEqual(calls[0][-2:], ['--subscription', 's1'])

    def test_missing_page_token_is_not_silently_complete(self):
        with self.assertRaises(RuntimeError):
            graph_resources(['s'], lambda args: dict(data=[dict(id='one')], total_records=2))

    def test_expired_tenant_does_not_hide_other_tenant_results(self):
        def runner(args):
            if args[0] == 'account':
                return [dict(id='s1', name='One', tenantId='t1', state='Enabled'),
                        dict(id='s2', name='Two', tenantId='t2', state='Enabled')]
            if args[-1] == 's2':
                raise RuntimeError('Token expired')
            return dict(data=[dict(id='/app', name='app', type='microsoft.web/sites', subscriptionId='s1',
                                  defaultHostName='app.azurewebsites.net')])
        inventory = discover_azure(runner=runner)
        self.assertEqual(len(inventory.rows), 1)
        self.assertEqual(len(inventory.errors), 1)
        self.assertIn('s2', inventory.errors[0])


class PortDiscoveryTests(unittest.TestCase):
    def test_discovery_never_polls_an_empty_socket_set(self):
        class WindowsLikeSelector(selectors.SelectSelector):
            def select(self, timeout=None):
                if not self.get_map():
                    raise OSError("Windows rejects select() with no sockets")
                return super().select(timeout)

        with local_server({'/': (200, {}, 'Hello')}) as server:
            with patch('azure_php_scout.discovery.selectors.DefaultSelector', WindowsLikeSelector):
                found = list(discover_open_ports(['127.0.0.1'], [server.server_port],
                             stop=threading.Event()))
                self.assertEqual(found, [('127.0.0.1', server.server_port)])

    def test_port_ranges_and_complete_tcp_scope(self):
        self.assertEqual(scanner.parse_ports('80,443,8000-8002,80'), [80, 443, 8000, 8001, 8002])
        self.assertEqual(len(scanner.parse_ports('all')), 65535)
        for invalid in ('5-2', '-1', '65535-65536'):
            with self.subTest(value=invalid), self.assertRaises(scanner.argparse.ArgumentTypeError):
                scanner.parse_ports(invalid)

    def test_open_and_closed_ports_and_progress_are_distinct(self):
        with local_server({'/': (200, {}, 'Hello')}) as server:
            with socket.socket() as closed:
                closed.bind(('127.0.0.1', 0))
                closed_port = closed.getsockname()[1]
            # Windows can take over a second to deliver a refused connection.
            updates = []
            found = list(discover_open_ports(['127.0.0.1'], [closed_port, server.server_port],
                         workers=2, timeout=5, rate=1000, stop=threading.Event(), progress=updates.append))
            self.assertEqual(found, [('127.0.0.1', server.server_port)])
            self.assertEqual(updates[-1]['checked'], 2)
            self.assertEqual(updates[-1]['open'], 1)
            self.assertEqual(updates[-1]['closed'], 1, updates[-1])

    def test_stop_does_not_begin_new_connections(self):
        stop = threading.Event()
        stop.set()
        self.assertEqual(list(discover_open_ports(['192.0.2.1'], [80], stop=stop)), [])

    def test_discovered_nonstandard_web_port_reaches_html_and_coverage(self):
        with local_server({'/': (200, {'X-Powered-By': 'PHP/8.4.1'}, '<title>Custom port</title>')}) as server:
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'results.csv'
                with contextlib.redirect_stderr(io.StringIO()):
                    result = scanner.main(['--ip', '127.0.0.1', '--vm-ports', str(server.server_port),
                                           '--port-timeout', '0.3', '--no-probes', '-o', str(output)])
                self.assertEqual(result, 0)
                with output.open(newline='') as file:
                    rows = list(csv.DictReader(file))
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]['tcpOpen'], 'yes')
                self.assertEqual(rows[0]['resourceType'], 'vm')
                self.assertEqual(rows[0]['phpVersion'], '8.4.1')
                scope = json.loads(output.with_suffix('.coverage.json').read_text(encoding="utf-8"))
                self.assertEqual(scope['tcp']['open'], 1)
                self.assertEqual(scope['tcp']['checked'], 1)
                html = output.with_suffix('.html').read_text(encoding="utf-8")
                self.assertIn('Custom port', html)
                self.assertIn('TCP discovery:', html)

    def test_managed_hostname_uses_web_ports_without_platform_tcp_sweep(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'results.csv'
            with patch.object(scanner.Client, 'get', return_value=response()), patch.object(
                    scanner, 'discover_open_ports', side_effect=AssertionError('must not port scan shared PaaS addresses')):
                with contextlib.redirect_stderr(io.StringIO()):
                    result = scanner.main(['--hostname', 'app.example.test', '--no-probes', '-o', str(output)])
            self.assertEqual(result, 0)
            with output.open(newline='') as file:
                self.assertEqual({row['port'] for row in csv.DictReader(file)}, {'80', '443'})

    def test_coverage_escapes_errors_and_skipped_resource_names(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'results.html'
            write_html_report(output, [], status='failed', scope=dict(errors=['<script>alert(1)</script>'],
                skipped=[dict(vm='<img src=x>', reason='No IP')], vmPortScope='Full TCP range 1–65535'))
            html = output.read_text(encoding="utf-8")
            self.assertIn('Incomplete coverage', html)
            self.assertIn('&lt;script&gt;', html)
            self.assertNotIn('<img', html)
            self.assertIn('Full TCP range 1–65535', html)


if __name__ == '__main__':
    unittest.main()
