"""Retry tests use synthetic reports and never contact real Azure VMs."""
import contextlib
import csv
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from azure_php_scout import guest
from azure_php_scout.jobs import summarize
from azure_php_scout.service import ScanRequest
from test_guest import LINUX, WINDOWS, STOPPED, azure_reader, output


def source_report(path, rows):
    fields = ['evidenceSource', 'resourceId', 'guestStatus', 'os', 'subscription']
    with path.open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(dict(evidenceSource='guest', resourceId=identifier, guestStatus=status,
                              os='Windows' if identifier == WINDOWS else 'Linux', subscription='Synthetic subscription')
                         for identifier, status in rows)


class GuestRetryTests(unittest.TestCase):
    def test_retry_selects_only_failed_vms_and_has_no_fifty_vm_limit(self):
        with tempfile.TemporaryDirectory() as folder:
            source, destination = Path(folder) / 'previous.csv', Path(folder) / 'retried.csv'
            failures = [LINUX + str(index) for index in range(60)]
            source_report(source, [(identifier, 'failed') for identifier in failures] +
                          [(LINUX, 'checked'), (WINDOWS, 'incomplete'), (STOPPED, 'skipped')])
            original = source.read_bytes()
            submitted = []
            def invoke(identifier, os, timeout, stop):
                submitted.append(identifier)
                return output(os=os)
            self.assertEqual(guest.run_guest([], destination, retry_from=source, runner=azure_reader, invoker=invoke), 0)
            self.assertEqual(set(submitted), set(failures))
            self.assertEqual(source.read_bytes(), original)
            scope = json.loads(destination.with_suffix('.coverage.json').read_text())
            self.assertEqual(scope['guest']['requested'], 60)
            self.assertEqual(scope['guest']['retryExcluded'], 3)
            self.assertEqual(scope['guest']['checked'], 60)
            self.assertIn('original report is preserved', destination.with_suffix('.html').read_text(encoding='utf-8'))

    def test_duplicate_versions_and_inspected_rows_prevent_unnecessary_vm_retries(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'previous.csv'
            source_report(source, [(LINUX, 'failed'), (LINUX, 'checked'), (WINDOWS, 'timeout'), (WINDOWS, 'timeout'), (STOPPED, 'not_submitted')])
            identifiers, _ = guest.retry_input(source)
            self.assertEqual(identifiers, [WINDOWS, STOPPED])
            with source.open(newline='', encoding='utf-8') as stream:
                self.assertEqual(summarize(list(csv.DictReader(stream)))['guestRetryable'], 2)

    def test_retry_rejects_external_reports_empty_selection_and_overwriting_source(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'previous.csv'
            source.write_text('target,port\n127.0.0.1,80\n', encoding='utf-8')
            with self.assertRaises(ValueError):
                guest.retry_input(source)
            source_report(source, [(LINUX, 'checked')])
            with self.assertRaises(ValueError):
                guest.retry_input(source)
            source_report(source, [(LINUX, 'failed')])
            original = source.read_bytes()
            with self.assertRaises(ValueError):
                guest.run_guest([], source, retry_from=source)
            with self.assertRaises(ValueError):
                guest.run_guest([WINDOWS], Path(folder)/'retry.csv', retry_from=source)
            self.assertEqual(source.read_bytes(), original)

    def test_expired_sign_in_stops_submission_and_keeps_rest_retryable(self):
        def reader(args):
            raise RuntimeError('AADSTS70043: Refresh token expired due to sign-in frequency. Run az login.')
        invoke = Mock(side_effect=AssertionError('Guest command after authentication failure'))
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / 'results.csv'
            self.assertEqual(guest.run_guest([LINUX, WINDOWS], destination, runner=reader, invoker=invoke), 1)
            invoke.assert_not_called()
            scope = json.loads(destination.with_suffix('.coverage.json').read_text())
            self.assertTrue(scope['guest']['authenticationRequired'])
            self.assertEqual(scope['guest']['failed'], 1)
            self.assertEqual(scope['guest']['notSubmitted'], 1)
            self.assertEqual(guest.retry_input(destination)[0], [LINUX, WINDOWS])

    def test_retry_dry_run_reads_saved_selection_without_azure_or_writing_reports(self):
        with tempfile.TemporaryDirectory() as folder:
            source, destination = Path(folder) / 'previous.csv', Path(folder) / 'retry.csv'
            source_report(source, [(LINUX, 'checked'), (WINDOWS, 'cancelled')])
            with patch.object(guest, 'az_json', side_effect=AssertionError('Azure call')), contextlib.redirect_stdout(io.StringIO()) as captured:
                self.assertEqual(guest.main(['--retry-from', str(source), '--dry-run', '-o', str(destination)]), 0)
            self.assertEqual([item['resourceId'] for item in json.loads(captured.getvalue())], [WINDOWS])
            self.assertFalse(destination.exists())

    def test_retry_scope_is_a_validated_scan_uuid_and_excludes_other_scopes(self):
        identifier = '00000000-0000-0000-0000-000000000001'
        self.assertEqual(ScanRequest(mode='guest', guest_retry_scan=identifier).guest_retry_scan, identifier)
        for config in (dict(mode='guest', guest_retry_scan='../../outside'),
                       dict(mode='guest', guest_retry_scan=identifier, vm_ids=[LINUX]),
                       dict(mode='guest', guest_retry_scan=identifier, guest_all_subscriptions=True),
                       dict(mode='azure', guest_retry_scan=identifier)):
            with self.subTest(config=config), self.assertRaises(ValueError):
                ScanRequest(**config)
