"""Report replacement must preserve snapshots during concurrent Windows reads."""
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from azure_php_scout.snapshots import replace_snapshot


class SnapshotTests(unittest.TestCase):
    def test_transient_windows_sharing_conflict_retries_without_losing_old_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            source, target = Path(folder) / 'new.tmp', Path(folder) / 'results.csv'
            source.write_text('new snapshot')
            target.write_text('previous snapshot')
            original = Path.replace
            attempts = []
            def replace(path, destination):
                attempts.append(path)
                if len(attempts) <= 2:
                    self.assertEqual(target.read_text(), 'previous snapshot')
                    error = PermissionError('Synthetic Windows sharing violation')
                    error.winerror = 32
                    raise error
                return original(path, destination)
            with patch.object(Path, 'replace', replace), patch('azure_php_scout.snapshots.time.sleep'):
                replace_snapshot(source, target)
            self.assertEqual(target.read_text(), 'new snapshot')
            self.assertFalse(source.exists())

    def test_persistent_conflict_is_bounded_and_preserves_previous_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            source, target = Path(folder) / 'new.tmp', Path(folder) / 'results.csv'
            source.write_text('new snapshot')
            target.write_text('previous snapshot')
            error = PermissionError('Synthetic persistent Windows lock')
            error.winerror = 32
            with patch.object(Path, 'replace', side_effect=error), patch('azure_php_scout.snapshots.time.sleep') as sleep:
                with self.assertRaises(PermissionError):
                    replace_snapshot(source, target)
            self.assertLessEqual(sum(call.args[0] for call in sleep.call_args_list), 1.01)
            self.assertEqual(target.read_text(), 'previous snapshot')
            self.assertTrue(source.exists())

    def test_unrelated_permission_errors_are_not_retried(self):
        with patch.object(Path, 'replace', side_effect=PermissionError('Write permission denied')), patch('azure_php_scout.snapshots.time.sleep') as sleep:
            with self.assertRaises(PermissionError):
                replace_snapshot(Path('unwritten.tmp'), Path('unwritten.csv'))
        sleep.assert_not_called()

    @unittest.skipUnless(os.name == 'nt', 'Windows file-sharing semantics')
    def test_actual_windows_reader_lock_is_released_before_retry(self):
        with tempfile.TemporaryDirectory() as folder, ThreadPoolExecutor(max_workers=1) as executor:
            source, target = Path(folder) / 'new.tmp', Path(folder) / 'results.csv'
            source.write_text('new snapshot')
            target.write_text('previous snapshot')
            conflict, released = threading.Event(), threading.Event()
            def wait_for_reader(_seconds):
                conflict.set()
                if not released.wait(5):
                    raise TimeoutError('Test reader was not released')
            with patch('azure_php_scout.snapshots.time.sleep', wait_for_reader):
                reader = target.open()
                try:
                    future = executor.submit(replace_snapshot, source, target)
                    self.assertTrue(conflict.wait(5), 'Windows did not report the held reader lock')
                    self.assertEqual(reader.read(), 'previous snapshot')
                finally:
                    reader.close()
                    released.set()
                future.result(timeout=5)
            self.assertEqual(target.read_text(), 'new snapshot')
