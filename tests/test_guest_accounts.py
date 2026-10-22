"""Automated account-wide guest scans use only synthetic Azure adapters."""
import contextlib
import csv
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from azure_php_scout import guest
from azure_php_scout.jobs import JobManager
from azure_php_scout.service import ScanRequest
from test_guest import SUBSCRIPTION, LINUX, WINDOWS, STOPPED, azure_reader, output

SECOND = '00000000-0000-0000-0000-000000000002'
DENIED = '00000000-0000-0000-0000-000000000003'
EMPTY = '00000000-0000-0000-0000-000000000004'
DISABLED = '00000000-0000-0000-0000-000000000005'
WINDOWS_SECOND = WINDOWS.replace(SUBSCRIPTION, SECOND)


def account_reader(args, *, healthy=False):
    accounts = [dict(id=SUBSCRIPTION, name='Synthetic Linux subscription', tenantId='tenant-a', state='Enabled'),
                dict(id=SECOND, name='Synthetic Windows subscription', tenantId='tenant-b', state='Enabled'),
                dict(id=EMPTY, name='Synthetic empty subscription', tenantId='tenant-a', state='Enabled')]
    if not healthy:
        accounts.extend([dict(id=DENIED, name='Synthetic denied subscription', tenantId='tenant-a', state='Enabled'),
                         dict(id=DISABLED, name='Synthetic disabled subscription', tenantId='tenant-b', state='Disabled'),
                         accounts[0].copy()])  # Account aliases must not duplicate execution.
    if args[0] == 'account':
        return accounts
    if args[0] == 'graph':
        ids = args[args.index('--subscriptions') + 1:args.index('--subscription')]
        assert args[args.index('--subscription') + 1] == ids[0]
        assert guest.VM_QUERY in args
        assert len({item['tenantId'] for item in accounts if item['id'] in ids}) == 1
        if DENIED in ids:
            raise RuntimeError('AuthorizationFailed: synthetic subscription read denied')
        machines = []
        if SUBSCRIPTION in ids:
            machines += [LINUX] if healthy else [LINUX, STOPPED]
        if SECOND in ids:
            machines.append(WINDOWS_SECOND)
        offset = int(args[args.index('--skip-token') + 1]) if '--skip-token' in args else 0
        return dict(data=[dict(id=identifier, name=identifier.split('/')[-1], subscriptionId=identifier.split('/')[2],
                              os='Windows' if identifier == WINDOWS_SECOND else 'Linux', resourceGroup='example-rg')
                          for identifier in machines[offset:offset + 1]], total_records=len(machines),
                    skip_token=str(offset + 1) if offset + 1 < len(machines) else None)
    identifier = args[args.index('--ids') + 1]
    if args[:2] == ['vm', 'show']:
        value = azure_reader(args)
        if identifier == WINDOWS_SECOND:
            value['storageProfile']['osDisk']['osType'] = 'Windows'
        return value
    if identifier == STOPPED:
        return dict(statuses=[dict(code='PowerState/deallocated')])
    return azure_reader(args)


class AccountGuestTests(unittest.TestCase):
    def test_account_scope_is_explicit_and_mutually_exclusive(self):
        self.assertTrue(ScanRequest(mode='guest', guest_all_subscriptions=True).guest_all_subscriptions)
        for config in (dict(mode='guest', guest_all_subscriptions=False),
                       dict(mode='guest', guest_all_subscriptions=True, vm_ids=[LINUX]),
                       dict(mode='guest', guest_all_subscriptions=True, guest_subscription=SUBSCRIPTION),
                       dict(mode='guest', guest_all_subscriptions=True, subscriptions=[SUBSCRIPTION]),
                       dict(mode='azure', guest_all_subscriptions=True)):
            with self.subTest(config=config), self.assertRaises(ValueError):
                ScanRequest(**config)
        with tempfile.TemporaryDirectory() as folder:
            manager = JobManager(folder)
            try:
                args = manager.command(ScanRequest(mode='guest', guest_all_subscriptions=True).model_dump(), Path(folder))
                self.assertIn('--all-subscriptions', args)
                self.assertNotIn('--vm-id', args)
                self.assertNotIn('--subscription', args)
            finally:
                manager.close()

    def test_refresh_pagination_tenant_batches_and_failed_subscription_isolation(self):
        runner = Mock(side_effect=account_reader)
        inventory = guest.all_subscription_vms(runner=runner)
        self.assertEqual(runner.call_args_list[0].args[0], ['account', 'list', '--all', '--refresh'])
        self.assertEqual({item['resourceId'] for item in inventory['vms']}, {LINUX, WINDOWS_SECOND, STOPPED})
        self.assertEqual(len(inventory['subscriptions']), 5)
        summaries = {item['id']: item for item in inventory['subscriptions']}
        self.assertEqual(summaries[SUBSCRIPTION]['requested'], 2)
        self.assertEqual(summaries[SECOND]['requested'], 1)
        self.assertEqual(summaries[EMPTY]['discoveryStatus'], 'complete')
        self.assertEqual(summaries[EMPTY]['requested'], 0)
        self.assertEqual(summaries[DENIED]['discoveryStatus'], 'failed')
        self.assertEqual(summaries[DISABLED]['discoveryStatus'], 'skipped')
        self.assertEqual(inventory['discoveryStatus'], 'partial')
        self.assertTrue(any('--skip-token' in call.args[0] for call in runner.call_args_list))

    def test_more_than_one_thousand_subscriptions_are_not_truncated(self):
        accounts = [dict(id='00000000-0000-0000-0000-{:012x}'.format(i + 1), name='Synthetic subscription '+str(i),
                         tenantId='tenant-a' if i < 700 else 'tenant-b', state='Enabled') for i in range(1003)]
        queried = []
        def reader(args):
            if args[0] == 'account':
                return accounts
            ids = args[args.index('--subscriptions') + 1:args.index('--subscription')]
            self.assertLessEqual(len(ids), 100)
            queried.extend(ids)
            return dict(data=[])
        result = guest.all_subscription_vms(runner=reader)
        self.assertEqual(result['discoveryStatus'], 'complete')
        self.assertEqual(len(queried), 1003)
        self.assertEqual(set(queried), {item['id'] for item in accounts})
        self.assertTrue(all(item['discoveryStatus'] == 'complete' for item in result['subscriptions']))

    def test_combined_report_contains_all_subscriptions_private_vms_and_failures(self):
        submitted = []
        def invoke(identifier, os, timeout, stop):
            submitted.append(identifier)
            return output(os=os)
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / 'results.csv'
            self.assertEqual(guest.run_guest([], destination, all_subscriptions=True, runner=account_reader, invoker=invoke), 1)
            scope = json.loads(destination.with_suffix('.coverage.json').read_text())
            self.assertEqual(scope['guest']['scope'], 'all_subscriptions')
            self.assertEqual(scope['subscriptions'], 5)
            self.assertEqual(scope['guest']['requested'], 3)
            self.assertEqual(scope['guest']['checked'], 2)
            self.assertEqual(scope['guest']['skipped'], 1)
            self.assertEqual(set(submitted), {LINUX, WINDOWS_SECOND})
            summaries = {item['id']: item for item in scope['guest']['subscriptionResults']}
            self.assertEqual(summaries[SUBSCRIPTION]['checked'], 1)
            self.assertEqual(summaries[SUBSCRIPTION]['skipped'], 1)
            self.assertEqual(summaries[SECOND]['checked'], 1)
            with destination.open(newline='', encoding='utf-8') as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual({item['subscriptionId'] for item in rows}, {SUBSCRIPTION, SECOND})
            html = destination.with_suffix('.html').read_text(encoding='utf-8')
            for text in ('Coverage by subscription (5 subscriptions)', 'Synthetic empty subscription',
                         'Synthetic denied subscription', 'Synthetic disabled subscription', 'AuthorizationFailed', 'stopped-private'):
                self.assertIn(text, html)

    def test_successful_account_scan_completes_and_preserves_empty_subscriptions(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / 'results.csv'
            self.assertEqual(guest.run_guest([], destination, all_subscriptions=True,
                             runner=lambda args: account_reader(args, healthy=True),
                             invoker=lambda identifier, os, timeout, stop: output(os=os)), 0)
            scope = json.loads(destination.with_suffix('.coverage.json').read_text())
            self.assertEqual(scope['scanStatus'], 'complete')
            self.assertEqual(scope['guest']['discoveryStatus'], 'complete')
            self.assertEqual(scope['guest']['checked'], 2)
            self.assertEqual(scope['subscriptions'], 3)
            self.assertEqual(scope['errors'], [])
            self.assertIn('Synthetic empty subscription', destination.with_suffix('.html').read_text(encoding='utf-8'))

    def test_run_command_denial_on_one_vm_does_not_stop_other_subscriptions(self):
        submitted = []
        def invoke(identifier, os, timeout, stop):
            submitted.append(identifier)
            if identifier == LINUX:
                raise guest.GuestCommandError('AuthorizationFailed: synthetic Run Command denial')
            return output(os=os)
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / 'results.csv'
            self.assertEqual(guest.run_guest([], destination, all_subscriptions=True,
                             runner=lambda args: account_reader(args, healthy=True), invoker=invoke), 1)
            scope = json.loads(destination.with_suffix('.coverage.json').read_text())
            self.assertEqual(scope['guest']['checked'], 1)
            self.assertEqual(scope['guest']['failed'], 1)
            self.assertEqual(set(submitted), {LINUX, WINDOWS_SECOND})

    def test_cancellation_during_discovery_never_submits_guest_commands(self):
        stop = threading.Event()
        def reader(args):
            result = account_reader(args, healthy=True)
            if args[0] == 'graph':
                stop.set()
            return result
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / 'results.csv'
            invoke = Mock(side_effect=AssertionError('Guest command after cancellation'))
            self.assertEqual(guest.run_guest([], destination, all_subscriptions=True, runner=reader, invoker=invoke, stop=stop), 130)
            invoke.assert_not_called()
            scope = json.loads(destination.with_suffix('.coverage.json').read_text())
            self.assertEqual(scope['scanStatus'], 'interrupted')
            self.assertEqual(scope['guest']['discoveryStatus'], 'interrupted')
            self.assertEqual(scope['guest']['notSubmitted'], 1)
            self.assertTrue(any(item['discoveryStatus'] == 'not_submitted' for item in scope['guest']['subscriptionResults']))

    def test_failed_account_refresh_creates_a_report_without_execution(self):
        for response in ([], [None], dict(invalid='account list')):
            with self.subTest(response=response), tempfile.TemporaryDirectory() as folder:
                destination = Path(folder) / 'results.csv'
                self.assertEqual(guest.run_guest([], destination, all_subscriptions=True, runner=Mock(return_value=response),
                                 invoker=Mock(side_effect=AssertionError('Unexpected guest execution'))), 1)
                scope = json.loads(destination.with_suffix('.coverage.json').read_text())
                self.assertEqual(scope['guest']['discoveryStatus'], 'failed')
                self.assertTrue(destination.with_suffix('.html').is_file())

    def test_dry_run_has_subscription_coverage_and_never_executes_or_writes_reports(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(guest, 'az_json', account_reader):
            destination = Path(folder) / 'results.csv'
            with patch.object(guest.subprocess, 'Popen', side_effect=AssertionError('Guest execution')), contextlib.redirect_stdout(io.StringIO()) as captured:
                self.assertEqual(guest.main(['--all-subscriptions', '--dry-run', '-o', str(destination)]), 1)
            plan = json.loads(captured.getvalue())
            self.assertEqual(len(plan['subscriptions']), 5)
            self.assertEqual(len(plan['vms']), 3)
            self.assertTrue(plan['errors'])
            self.assertFalse(destination.exists())

