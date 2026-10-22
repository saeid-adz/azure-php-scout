"""Guest inspection tests never execute Azure commands or contact customer VMs."""
import base64
import contextlib
import csv
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from azure_php_scout import guest
from azure_php_scout.jobs import JobManager, summarize
from azure_php_scout.report import endpoint_key
from azure_php_scout.service import ScanRequest

SUBSCRIPTION = '00000000-0000-0000-0000-000000000001'
LINUX = '/subscriptions/' + SUBSCRIPTION + '/resourceGroups/example-rg/providers/Microsoft.Compute/virtualMachines/linux-private'
WINDOWS = LINUX.rsplit('/', 1)[0] + '/windows-private'
STOPPED = LINUX.rsplit('/', 1)[0] + '/stopped-private'


def encoded(value):
    return base64.b64encode(value.encode()).decode()


def output(os='Linux', version='8.2.34', path='/usr/bin/php', packages=(), limited='no', process='yes'):
    lines = ['SCOUT_GUEST_BEGIN_V1', 'OS|' + os]
    if version:
        lines.append('RUNTIME|' + version + '|' + encoded(path) + '|' + ('binary' if os == 'Linux' else 'file_metadata'))
    for name, package_version in packages:
        lines.append('PACKAGE|' + encoded(name) + '|' + encoded(package_version))
    lines.extend(['PROCESS|' + process, 'PACKAGES|' + ('dpkg' if os == 'Linux' else 'not_checked'),
                  'BINARY_ERRORS|0', 'LIMIT|' + limited, 'SCOUT_GUEST_END_V1'])
    return dict(value=[dict(code='ProvisioningState/succeeded', level='Info',
                           message='Enable succeeded:\n[stdout]\n' + '\n'.join(lines) + '\n[stderr]\n')])


def azure_reader(args):
    resource_id = args[args.index('--ids') + 1]
    if args[:2] == ['vm', 'show']:
        return dict(name=resource_id.rsplit('/', 1)[-1], resourceGroup='example-rg',
                    storageProfile=dict(osDisk=dict(osType='Windows' if resource_id == WINDOWS else 'Linux')))
    return dict(statuses=[dict(code='PowerState/running')], vmAgent=dict(statuses=[dict(code='ProvisioningState/succeeded')]))


def fleet_reader(args, machines=None):
    """Paginated synthetic subscription with no public-IP properties."""
    if args[0] == 'account':
        return [dict(id=SUBSCRIPTION, name='Synthetic subscription', tenantId='tenant', state='Enabled'),
                dict(id='00000000-0000-0000-0000-000000000002', name='Other subscription', tenantId='tenant', state='Enabled')]
    if args[0] == 'graph':
        assert args[args.index('--subscriptions') + 1:args.index('--subscription')] == [SUBSCRIPTION]
        assert args[args.index('--subscription') + 1] == SUBSCRIPTION
        assert guest.VM_QUERY in args
        machines = machines if machines is not None else [LINUX, WINDOWS, STOPPED]
        offset = int(args[args.index('--skip-token') + 1]) if '--skip-token' in args else 0
        end = offset + 30
        return dict(data=[dict(id=identifier, name=identifier.rsplit('/', 1)[-1], resourceGroup='example-rg',
                               subscriptionId=SUBSCRIPTION, os='Windows' if identifier == WINDOWS else 'Linux',
                               powerState='PowerState/deallocated' if identifier == STOPPED else 'PowerState/running')
                          for identifier in machines[offset:end]], total_records=len(machines),
                    skip_token=str(end) if end < len(machines) else None)
    if STOPPED in args and args[:2] == ['vm', 'get-instance-view']:
        return dict(statuses=[dict(code='PowerState/deallocated')])
    return azure_reader(args)


class GuestTests(unittest.TestCase):
    def test_explicit_resource_ids_are_required_and_deduplicated(self):
        self.assertEqual(guest.selected_vm_ids([LINUX, LINUX.upper()]), [guest.vm_id(LINUX.upper())])
        for value in ('--help', LINUX + '\n--debug', LINUX.replace('virtualMachines', 'sites'), LINUX.replace(SUBSCRIPTION, 'invalid')):
            with self.subTest(value=value), self.assertRaises(ValueError):
                guest.vm_id(value)
        for values in ([], [LINUX + str(index) for index in range(51)]):
            with self.assertRaises(ValueError):
                guest.selected_vm_ids(values)
        for config in (dict(mode='guest'), dict(mode='targets', targets=['127.0.0.1'], vm_ids=[LINUX]), dict(mode='guest', vm_ids=[LINUX], guest_timeout=1)):
            with self.assertRaises(ValueError):
                ScanRequest(**config)

    def test_vm_discovery_includes_both_operating_systems_without_public_ips(self):
        def reader(args):
            if args[0] == 'account':
                return [dict(id=SUBSCRIPTION, name='Synthetic subscription', tenantId='tenant', state='Enabled')]
            self.assertIn(guest.VM_QUERY, args)
            return dict(data=[dict(id=identifier, name=name, subscriptionId=SUBSCRIPTION, os=os)
                                   for identifier, name, os in [(LINUX, 'linux-private', 'Linux'), (WINDOWS, 'windows-private', 'Windows')]])
        found = guest.list_vms(runner=reader)
        self.assertEqual(len(found['vms']), 2)
        self.assertEqual({row['os'] for row in found['vms']}, {'Linux', 'Windows'})
        self.assertEqual(found['errors'], [])

    def test_subscription_scope_requires_exactly_one_valid_execution_scope(self):
        self.assertEqual(ScanRequest(mode='guest', guest_subscription=SUBSCRIPTION).guest_subscription, SUBSCRIPTION)
        for config in (dict(guest_subscription=''), dict(guest_subscription='invalid'),
                       dict(guest_subscription=SUBSCRIPTION + ',' + SUBSCRIPTION),
                       dict(guest_subscription=SUBSCRIPTION, vm_ids=[LINUX]),
                       dict(subscriptions=[SUBSCRIPTION]),
                       dict(guest_subscription=SUBSCRIPTION, subscriptions=[SUBSCRIPTION])):
            with self.subTest(config=config), self.assertRaises(ValueError):
                ScanRequest(mode='guest', **config)
        with self.assertRaises(ValueError):
            ScanRequest(mode='azure', guest_subscription=SUBSCRIPTION)

    def test_subscription_scan_pages_and_reports_more_than_fifty_private_vms(self):
        machines = [LINUX, WINDOWS, STOPPED] + [LINUX + str(i) for i in range(53)]
        submitted = []
        def invoke(identifier, os, timeout, stop):
            submitted.append(identifier)
            return output(os=os)
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / 'results.csv'
            self.assertEqual(guest.run_guest([], destination, subscription=SUBSCRIPTION,
                             runner=lambda args: fleet_reader(args, machines), invoker=invoke), 1)
            scope = json.loads(destination.with_suffix('.coverage.json').read_text())
            self.assertEqual(scope['guest']['requested'], 56)
            self.assertEqual(scope['guest']['checked'], 55)
            self.assertEqual(scope['guest']['skipped'], 1)
            self.assertEqual(scope['guest']['discoveryStatus'], 'complete')
            self.assertEqual(scope['guest']['subscriptionId'], SUBSCRIPTION)
            self.assertEqual(len(submitted), 55)
            self.assertNotIn(STOPPED, submitted)
            with destination.open(newline='', encoding='utf-8') as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual({row['resourceId'] for row in rows}, set(machines))
            self.assertTrue(all(row['subscription'] == 'Synthetic subscription' for row in rows))
            self.assertEqual(next(row['guestStatus'] for row in rows if row['resourceId'] == STOPPED), 'skipped')
            html = destination.with_suffix('.html').read_text(encoding='utf-8')
            self.assertIn('all VMs, public and private', html)
            self.assertIn(SUBSCRIPTION, html)
            self.assertIn('55 / 56 VMs checked', html)

    def test_failed_incomplete_or_cross_subscription_discovery_submits_nothing(self):
        def incomplete(args):
            if args[0] == 'account':
                return fleet_reader(args)
            return dict(data=[dict(id=LINUX, name='linux-private')], total_records=2)
        def denied(args):
            raise RuntimeError('AuthorizationFailed: inventory permission required')
        def crossed(args):
            result = fleet_reader(args)
            if args[0] == 'graph':
                result['data'][0]['id'] = LINUX.replace(SUBSCRIPTION, '00000000-0000-0000-0000-000000000002')
            return result
        for reader in (incomplete, denied, crossed):
            with self.subTest(reader=reader.__name__), tempfile.TemporaryDirectory() as folder:
                destination = Path(folder) / 'results.csv'
                invoker = Mock(side_effect=AssertionError('No commands should be submitted'))
                self.assertEqual(guest.run_guest([], destination, subscription=SUBSCRIPTION, runner=reader, invoker=invoker), 1)
                invoker.assert_not_called()
                scope = json.loads(destination.with_suffix('.coverage.json').read_text())
                self.assertEqual(scope['guest']['discoveryStatus'], 'failed')
                self.assertEqual(scope['scanStatus'], 'failed')
                self.assertTrue(scope['errors'])
                self.assertTrue(destination.with_suffix('.html').is_file())

    def test_empty_subscription_produces_a_complete_empty_report(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / 'results.csv'
            self.assertEqual(guest.run_guest([], destination, subscription=SUBSCRIPTION,
                             runner=lambda args: fleet_reader(args, []), invoker=Mock(side_effect=AssertionError('No VMs'))), 0)
            scope = json.loads(destination.with_suffix('.coverage.json').read_text())
            self.assertEqual(scope['scanStatus'], 'complete')
            self.assertEqual(scope['guest']['requested'], 0)
            self.assertIn('No VMs were returned', destination.with_suffix('.html').read_text(encoding='utf-8'))

    def test_subscription_cancellation_keeps_unsubmitted_vms_in_the_report(self):
        stop = threading.Event()
        def invoke(identifier, os, timeout, event):
            stop.set()
            return output(os=os)
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / 'results.csv'
            self.assertEqual(guest.run_guest([], destination, subscription=SUBSCRIPTION,
                             runner=fleet_reader, invoker=invoke, stop=stop), 130)
            scope = json.loads(destination.with_suffix('.coverage.json').read_text())
            self.assertEqual(scope['guest']['notSubmitted'], 2)
            self.assertEqual(scope['guest']['completed'], 1)
            with destination.open(newline='', encoding='utf-8') as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), 3)
            self.assertEqual([row['guestStatus'] for row in rows], ['checked', 'not_submitted', 'not_submitted'])

    def test_subscription_cli_dry_run_and_job_command(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(guest, 'az_json', fleet_reader):
            destination = Path(folder) / 'results.csv'
            with patch.object(guest.subprocess, 'Popen', side_effect=AssertionError('Azure execution')), contextlib.redirect_stdout(io.StringIO()) as captured:
                self.assertEqual(guest.main(['--subscription', SUBSCRIPTION, '--dry-run', '-o', str(destination)]), 0)
            plan = json.loads(captured.getvalue())
            self.assertEqual(len(plan), 3)
            self.assertEqual({item['commandId'] for item in plan}, {'RunShellScript', 'RunPowerShellScript'})
            self.assertFalse(destination.exists())
            manager = JobManager(Path(folder) / 'manager')
            try:
                command = manager.command(ScanRequest(mode='guest', guest_subscription=SUBSCRIPTION).model_dump(), Path(folder))
                self.assertIn('--subscription', command)
                self.assertEqual(command[command.index('--subscription') + 1], SUBSCRIPTION)
                self.assertNotIn('--vm-id', command)
            finally:
                manager.close()

    def test_framed_output_separates_binary_and_package_evidence(self):
        parsed = guest.parse_output(output(packages=[('php8.2-fpm', '1:8.2.29-1+deb12u2')]), 'Linux')
        rows = guest.result_rows(LINUX, azure_reader(['vm', 'show', '--ids', LINUX]), parsed)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['assessment'], 'potentially_affected')
        self.assertEqual(rows[1]['phpVersion'], '8.2.29-1+deb12u2')
        self.assertIn('does not confirm', rows[0]['assessmentBasis'])
        self.assertIn('vendor', rows[1]['remediation'])
        self.assertNotEqual(endpoint_key(rows[0]), endpoint_key(rows[1]))
        self.assertEqual(summarize(rows)['responded'], 0)
        self.assertEqual(summarize(rows)['guestChecked'], 1)

    def test_truncated_failed_mismatched_and_malformed_output_is_rejected(self):
        damaged = output()
        damaged['value'][0]['message'] = damaged['value'][0]['message'].replace('SCOUT_GUEST_BEGIN_V1', '')
        wrong = output(os='Windows')
        malformed = output()
        malformed['value'][0]['message'] = malformed['value'][0]['message'].replace(encoded('/usr/bin/php'), '%%%')
        for value in (damaged, wrong, malformed, {}, dict(value=[dict(code='ProvisioningState/failed')])):
            with self.subTest(value=value), self.assertRaises(ValueError):
                guest.parse_output(value, 'Linux')

    def test_empty_and_limited_inventory_never_claims_php_absent(self):
        vm = azure_reader(['vm', 'show', '--ids', LINUX])
        row = guest.result_rows(LINUX, vm, guest.parse_output(output(version='', process='no'), 'Linux'))[0]
        self.assertEqual(row['php'], 'unknown')
        self.assertEqual(row['assessment'], 'undetermined')
        self.assertIn('not proof', row['evidence'])
        limited = guest.result_rows(LINUX, vm, guest.parse_output(output(limited='yes'), 'Linux'))[0]
        self.assertEqual(limited['guestStatus'], 'incomplete')

    def test_windows_and_linux_choose_fixed_scripts_and_pass_preflight(self):
        calls = []
        def invoke(resource_id, os, timeout, stop):
            calls.append((resource_id, os))
            return output(os=os, path='C:\\PHP\\php.exe' if os == 'Windows' else '/usr/bin/php')
        for identifier, os in [(LINUX, 'Linux'), (WINDOWS, 'Windows')]:
            rows, remote = guest.inspect_vm(identifier, timeout=180, stop=threading.Event(), runner=azure_reader, invoker=invoke)
            self.assertFalse(remote)
            self.assertEqual(rows[0]['os'], os)
            self.assertEqual(rows[0]['guestStatus'], 'checked')
        self.assertEqual(calls, [(LINUX, 'Linux'), (WINDOWS, 'Windows')])

    def test_stopped_or_unready_vm_never_receives_a_command(self):
        for view in (dict(statuses=[dict(code='PowerState/deallocated')]), dict(statuses=[dict(code='PowerState/running')]), dict(statuses=None, vmAgent=None)):
            def reader(args):
                return azure_reader(args) if args[:2] == ['vm', 'show'] else view
            rows, _ = guest.inspect_vm(LINUX, timeout=180, stop=threading.Event(), runner=reader,
                                       invoker=Mock(side_effect=AssertionError('guest execution')))
            self.assertEqual(rows[0]['guestStatus'], 'skipped')

    def test_run_saves_guest_reports_and_continues_after_permission_failure(self):
        def invoke(identifier, os, timeout, stop):
            if os == 'Windows':
                raise guest.GuestCommandError('AuthorizationFailed: Run Command permission required')
            return output()
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / 'results.csv'
            self.assertEqual(guest.run_guest([WINDOWS, LINUX], destination, runner=azure_reader, invoker=invoke), 1)
            scope = json.loads(destination.with_suffix('.coverage.json').read_text())
            self.assertEqual(scope['guest']['checked'], 1)
            self.assertEqual(scope['guest']['failed'], 1)
            html = destination.with_suffix('.html').read_text(encoding='utf-8')
            self.assertIn('Guest inspection', html)
            self.assertIn('AuthorizationFailed', html)
            self.assertIn('CVE-2026-109618', html)
            self.assertIn('Guest package/disk inventory', html)
            self.assertIn('VMs inspected', html)
            manager = JobManager(Path(folder) / 'manager')
            try:
                command = manager.command(ScanRequest(mode='guest', vm_ids=[LINUX]).model_dump(), Path(folder))
                self.assertIn('guest', command)
                self.assertIn(LINUX, command)
                self.assertNotIn('--azure', command)
            finally:
                manager.close()

    def test_cancellation_records_remote_uncertainty_and_stops_further_submissions(self):
        stop = threading.Event()
        submitted = []
        def invoke(identifier, os, timeout, event):
            submitted.append(identifier)
            stop.set()
            raise guest.GuestCommandError('Remote command may continue', status='cancelled', remote_may_continue=True)
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / 'results.csv'
            self.assertEqual(guest.run_guest([LINUX, WINDOWS], destination, runner=azure_reader, invoker=invoke, stop=stop), 130)
            scope = json.loads(destination.with_suffix('.coverage.json').read_text())
            self.assertTrue(scope['remoteMayContinue'])
            self.assertEqual(submitted, [LINUX])
            self.assertEqual(scope['scanStatus'], 'interrupted')
            self.assertIn('cannot cancel', destination.with_suffix('.html').read_text(encoding='utf-8'))

    def test_cli_dry_run_never_submits_guest_commands_or_creates_reports(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(guest, 'az_json', azure_reader):
            destination = Path(folder) / 'results.csv'
            with patch.object(guest.subprocess, 'Popen', side_effect=AssertionError('Azure execution')), contextlib.redirect_stdout(io.StringIO()) as captured:
                self.assertEqual(guest.main(['--vm-id', LINUX, '--dry-run', '-o', str(destination)]), 0)
            self.assertEqual(json.loads(captured.getvalue())[0]['commandId'], 'RunShellScript')
            self.assertFalse(destination.exists())

    def test_invoker_uses_packaged_script_explicit_subscription_and_scrubs_token(self):
        process = Mock(returncode=0)
        process.communicate.return_value = (json.dumps(output(os='Windows')), '')
        process.poll.return_value = 0
        def spawn_fixture(args, **kwargs):
            snapshot = Path(args[args.index('--scripts') + 1][1:])
            self.assertEqual(snapshot.read_text(encoding='utf-8'), guest.script_info('Windows')['script'])
            return process
        with patch.object(guest.subprocess, 'Popen', side_effect=spawn_fixture) as spawn, patch.dict('os.environ', {'SCOUT_API_TOKEN': 'private-test-token'}):
            result = guest.invoke(WINDOWS, 'Windows', 180, threading.Event())
        args, kwargs = spawn.call_args
        self.assertEqual(args[0][:4], ['az', 'vm', 'run-command', 'invoke'])
        self.assertIn('RunPowerShellScript', args[0])
        snapshot = Path(args[0][args[0].index('--scripts') + 1][1:])
        self.assertEqual(snapshot.name, 'inspect-windows.ps1')
        self.assertFalse(snapshot.exists())
        self.assertEqual(result['_scoutScriptSha256'], guest.script_info('Windows')['sha256'])
        self.assertIn(SUBSCRIPTION, args[0])
        self.assertNotIn('SCOUT_API_TOKEN', kwargs['env'])
        self.assertNotIn('shell', kwargs)

    def test_invoker_cancellation_stops_client_and_preserves_remote_uncertainty(self):
        event = threading.Event()
        process = Mock(returncode=None)
        process.poll.return_value = None
        calls = 0
        def communicate(timeout=None):
            nonlocal calls
            calls += 1
            if calls == 1:
                event.set()
                raise subprocess.TimeoutExpired('fixture-az', timeout)
            return '', ''
        process.communicate.side_effect = communicate
        with patch.object(guest.subprocess, 'Popen', return_value=process):
            with self.assertRaises(guest.GuestCommandError) as caught:
                guest.invoke(LINUX, 'Linux', 180, event)
        self.assertEqual(caught.exception.status, 'cancelled')
        self.assertTrue(caught.exception.remote_may_continue)
        process.terminate.assert_called_once()

    def test_windows_script_emits_protocol_with_mocked_inventory(self):
        powershell = shutil.which('powershell') or shutil.which('pwsh')
        if not powershell:
            self.skipTest('PowerShell unavailable')
        # Mock OS discovery commands; never inspect the contributor's machine.
        stubs = '''function Get-CimInstance { [CmdletBinding()]param([Parameter(Position=0)][string]$ClassName, [string]$Filter, [string[]]$Property) @() }
function Get-Command { param($Name, $CommandType) @() }
function Test-Path { param($LiteralPath, $PathType) $false }
function Get-Item { param($Path) @() }
function Join-Path { param($Path, $ChildPath) '/synthetic-iis-config' }
'''
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / 'fixture.ps1'
            fixture.write_text(stubs + guest.script_info('Windows')['script'], encoding='utf-8')
            result = subprocess.run([powershell, '-NoProfile', '-NonInteractive', '-File', str(fixture)],
                                    text=True, encoding='utf-8', capture_output=True, timeout=30, check=True)
        parsed = guest.parse_output(dict(value=[dict(message=result.stdout)]), 'Windows')
        self.assertEqual(parsed['runtimes'], [])
        self.assertLess(len(result.stdout.encode()), 4096)

    def test_linux_script_has_valid_shell_syntax(self):
        shell = shutil.which('sh')
        if not shell:
            self.skipTest('POSIX shell unavailable')
        subprocess.run([shell, '-n', str(Path(guest.__file__).parent / 'scripts/inspect-linux.sh')], check=True)

    def test_windows_script_parses_without_executing_it(self):
        powershell = shutil.which('powershell') or shutil.which('pwsh')
        if not powershell:
            self.skipTest('PowerShell parser unavailable')
        script = Path(guest.__file__).parent / 'scripts/inspect-windows.ps1'
        command = "$tokens=$null; $errors=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($env:SCOUT_TEST_SCRIPT,[ref]$tokens,[ref]$errors); if ($errors.Count) { $errors | Out-String | Write-Error; exit 1 }"
        subprocess.run([powershell, '-NoProfile', '-NonInteractive', '-Command', command],
                       env=dict(os.environ, SCOUT_TEST_SCRIPT=str(script)), check=True)

    def test_windows_four_part_version_with_mocked_file_metadata(self):
        powershell = shutil.which('powershell') or shutil.which('pwsh')
        if not powershell:
            self.skipTest('PowerShell unavailable')
        stubs = r'''function Get-CimInstance { [CmdletBinding()]param([Parameter(Position=0)][string]$ClassName, [string]$Filter, [string[]]$Property) [PSCustomObject]@{ExecutablePath='C:\PHP\php.exe'} }
function Test-Path { param($LiteralPath, $PathType) $LiteralPath -eq 'C:\PHP\php.exe' }
function Get-Item { param($Path) @() }
function Join-Path { param($Path, $ChildPath) "$Path\$ChildPath" }
'''
        source = guest.script_info('Windows')['script']
        source = source.replace('[Diagnostics.FileVersionInfo]::GetVersionInfo($candidate)',
                                "([PSCustomObject]@{ProductVersion='8.2.34.0';FileVersion='8.2.34.0'})")
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / 'fixture.ps1'
            fixture.write_text(stubs + source, encoding='utf-8')
            result = subprocess.run([powershell, '-NoProfile', '-NonInteractive', '-File', str(fixture)],
                                    text=True, encoding='utf-8', capture_output=True, timeout=30, check=True)
        parsed = guest.parse_output(dict(value=[dict(message=result.stdout)]), 'Windows')
        self.assertEqual(parsed['runtimes'][0]['version'], '8.2.34+file.0')


if __name__ == '__main__':
    unittest.main()
