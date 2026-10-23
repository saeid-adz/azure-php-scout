"""Local process fixtures reproduce a CLI launcher leaving inherited pipes open."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from azure_php_scout.processes import capture, CommandCancelled, stop_tree
from azure_php_scout import guest
from test_guest import LINUX, azure_reader, output


class ProcessTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'POSIX process-group inheritance')
    def test_timeout_kills_descendant_even_after_its_launcher_has_exited(self):
        with tempfile.TemporaryDirectory() as folder:
            pid_file = Path(folder) / 'child.pid'
            launcher = '''import subprocess, sys
from pathlib import Path
child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
Path(sys.argv[1]).write_text(str(child.pid))
'''
            started = time.monotonic()
            try:
                with self.assertRaises(subprocess.TimeoutExpired):
                    capture([sys.executable, '-c', launcher, str(pid_file)], timeout=1)
                self.assertLess(time.monotonic() - started, 5, 'Inherited pipe prevented timeout cleanup')
                pid = int(pid_file.read_text())
                state = subprocess.run(['ps', '-p', str(pid), '-o', 'stat='], text=True, capture_output=True).stdout.strip()
                self.assertTrue(not state or state.startswith('Z'), 'Descendant survived the timeout')
            finally:
                if pid_file.exists():
                    try:
                        os.kill(int(pid_file.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_cancellation_interrupts_a_metadata_style_wait(self):
        stop = threading.Event()
        timer = threading.Timer(0.2, stop.set)
        timer.start()
        started = time.monotonic()
        try:
            with self.assertRaises(CommandCancelled):
                capture([sys.executable, '-c', 'import time; time.sleep(30)'], timeout=20, stop=stop)
            self.assertLess(time.monotonic() - started, 8)
        finally:
            timer.cancel()

    def test_cleanup_has_no_unbounded_pipe_wait_when_descendant_cannot_be_reaped(self):
        process = Mock(pid=987654321)
        process.poll.return_value = 0
        process.communicate.side_effect = subprocess.TimeoutExpired('synthetic detached child', 2)
        with patch('azure_php_scout.processes.os.killpg', create=True):
            stop_tree(process)
        self.assertGreaterEqual(process.communicate.call_count, 1)
        self.assertTrue(all(call.kwargs.get('timeout') is not None for call in process.communicate.call_args_list))

    def test_stages_are_persisted_before_remote_command_wait(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / 'results.csv'
            def invoke(identifier, os_name, timeout, stop):
                info = json.loads(destination.with_suffix('.coverage.json').read_text())['guest']
                self.assertEqual(info['currentStage'], 'run_command')
                self.assertTrue(info['stageStartedAt'])
                return output()
            self.assertEqual(guest.run_guest([LINUX], destination, runner=azure_reader, invoker=invoke), 0)
            self.assertNotIn('currentStage', json.loads(destination.with_suffix('.coverage.json').read_text())['guest'])
