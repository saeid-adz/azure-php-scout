import os
from pathlib import Path
import tempfile
import sys
import time
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from azure_php_scout.jobs import JobManager
from azure_php_scout.service import create_app, service_token
from test_web_scan import local_server
from test_guest import LINUX, WINDOWS, SUBSCRIPTION, azure_reader, output

TOKEN = "test-only-token-do-not-use-in-deployment-0000"
AUTH = {"Authorization": "Bearer " + TOKEN}


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.client_context = TestClient(create_app(self.directory.name, token=TOKEN), base_url="http://localhost")
        self.client = self.client_context.__enter__()

    def tearDown(self):
        self.client_context.__exit__(None, None, None)
        self.directory.cleanup()

    def wait(self, job_id):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            job = self.client.get("/api/scans/" + job_id, headers=AUTH).json()
            if job["state"] in ("complete", "partial", "failed", "cancelled", "interrupted"):
                return job
            time.sleep(0.05)
        self.fail("Job did not finish")

    def test_private_api_rejects_missing_wrong_and_unicode_tokens(self):
        for headers in ({}, {"Authorization": "Bearer wrong"}, {b"Authorization": "Bearer invalid-é".encode("utf-8")}):
            self.assertEqual(self.client.get("/api/scans", headers=headers).status_code, 401)
        self.assertEqual(self.client.get("/healthz").status_code, 200)
        self.assertEqual(self.client.get("/api/status", headers=AUTH).status_code, 200)
        self.assertNotIn(TOKEN, self.client.get("/api/status", headers=AUTH).text)

    def test_demo_runs_without_network_and_exports_assessed_results(self):
        with patch("azure_php_scout.jobs.subprocess.Popen", side_effect=AssertionError("network worker")):
            response = self.client.post("/api/scans", headers=AUTH, json=dict(mode="demo", name="Example demo"))
            self.assertEqual(response.status_code, 202)
            job = self.wait(response.json()["id"])
        self.assertEqual(job["state"], "complete")
        self.assertEqual(job["summary"]["potentiallyAffected"], 1)
        self.assertEqual(job["summary"]["endOfLife"], 1)
        self.assertEqual(job["summary"]["verifyVersion"], 2)
        self.assertEqual(job["summary"]["endpoints"], 6)
        path = "/api/scans/" + job["id"]
        filtered = self.client.get(path + "/results?assessment=potentially_affected", headers=AUTH).json()
        self.assertEqual(filtered["total"], 1)
        self.assertIn("CVE-2026-109618", filtered["rows"][0]["cves"])
        for format in ("csv", "html", "json"):
            export = self.client.get(path + "/export/" + format, headers=AUTH)
            self.assertEqual(export.status_code, 200)
            self.assertIn("attachment", export.headers["content-disposition"])
        self.assertEqual(self.client.get(path + "/export/html").status_code, 401)
        self.assertNotIn("inventory_csv", self.client.get("/api/scans", headers=AUTH).text)

    def test_real_worker_finds_nonstandard_php_port_and_generates_report(self):
        with local_server({"/": (200, {"X-Powered-By": "PHP/8.2.34"}, "<title>Local PHP fixture</title>")}) as server:
            created = self.client.post("/api/scans", headers=AUTH, json=dict(mode="targets", name="Loopback fixture",
                targets=["127.0.0.1"], vm_ports=str(server.server_port), no_probes=True))
            job = self.wait(created.json()["id"])
        self.assertEqual(job["state"], "complete", job)
        self.assertEqual(job["summary"]["potentiallyAffected"], 1)
        results = self.client.get("/api/scans/" + job["id"] + "/results", headers=AUTH).json()
        self.assertEqual(results["rows"][0]["phpVersion"], "8.2.34")
        self.assertIn("Local PHP fixture", self.client.get("/api/scans/" + job["id"] + "/export/html", headers=AUTH).text)

    def test_invalid_inputs_and_traversal_are_rejected(self):
        for data in (dict(mode="targets", targets=[]), dict(mode="targets", targets=["http://bad.test"]),
                     dict(mode="azure", subscriptions=["not-a-uuid"]), dict(vm_ports="0-99999"),
                     dict(workers=10000), dict(mode="inventory", inventory_csv="x,y\n1,2\n")):
            with self.subTest(data=data):
                self.assertEqual(self.client.post("/api/scans", headers=AUTH, json=data).status_code, 422)
        self.assertEqual(self.client.get("/api/scans/not-a-uuid", headers=AUTH).status_code, 404)
        self.assertEqual(self.client.get("/assets/../../jobs.sqlite", headers=AUTH).status_code, 404)
        self.assertEqual(self.client.get("/api/status", headers=dict(AUTH, Host="attacker.test")).status_code, 400)

    def test_service_lock_prevents_two_workers_owning_one_data_directory(self):
        with self.assertRaises(RuntimeError):
            JobManager(self.directory.name)

    def test_guest_api_protects_scripts_and_lists_private_vms(self):
        self.assertEqual(self.client.get('/api/guest/scripts/Linux').status_code, 401)
        script = self.client.get('/api/guest/scripts/Windows', headers=AUTH).json()
        self.assertEqual(script['commandId'], 'RunPowerShellScript')
        self.assertEqual(len(script['sha256']), 64)
        self.assertIn('FileVersionInfo', script['script'])
        with patch('azure_php_scout.service.list_vms', return_value=dict(vms=[dict(resourceId=LINUX, os='Linux')], errors=[])) as lookup:
            response = self.client.get('/api/azure/vms?subscription=' + SUBSCRIPTION, headers=AUTH)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()['vms'][0]['resourceId'], LINUX)
            lookup.assert_called_once_with([SUBSCRIPTION])
        self.assertEqual(self.client.get('/api/azure/vms?subscription=invalid', headers=AUTH).status_code, 422)
        self.assertEqual(self.client.post('/api/scans', headers=AUTH, json=dict(mode='guest')).status_code, 422)

    def test_guest_background_worker_and_exports_with_mocked_azure(self):
        fixture = Path(self.directory.name) / 'guest-fixture.py'
        # Real job subprocess and guest worker; Azure adapters return synthetic data.
        fixture.write_text('''import sys
from azure_php_scout.guest import run_guest
sys.path.insert(0, sys.argv[1])
from test_guest import LINUX, WINDOWS, azure_reader, output
def invoke(identifier, os, timeout, stop):
    return output(os=os, path='C:/PHP/php.exe' if os == 'Windows' else '/usr/bin/php')
raise SystemExit(run_guest([LINUX, WINDOWS], 'results.csv', runner=azure_reader, invoker=invoke))
''', encoding='utf-8')
        with patch('azure_php_scout.service.shutil.which', return_value='fixture-az'), patch.object(
                JobManager, 'command', return_value=[sys.executable, str(fixture), str(Path(__file__).parent)]):
            created = self.client.post('/api/scans', headers=AUTH, json=dict(mode='guest', name='Synthetic guest fixture', vm_ids=[LINUX, WINDOWS]))
            self.assertEqual(created.status_code, 202)
            job = self.wait(created.json()['id'])
        self.assertEqual(job['state'], 'complete', job)
        self.assertEqual(job['summary']['guestChecked'], 2)
        self.assertEqual(job['summary']['responded'], 0)
        self.assertEqual(job['summary']['potentiallyAffected'], 2)
        path = '/api/scans/' + job['id']
        rows = self.client.get(path + '/results', headers=AUTH).json()['rows']
        self.assertEqual({row['os'] for row in rows}, {'Linux', 'Windows'})
        self.assertTrue(all(row['evidenceSource'] == 'guest' for row in rows))
        html = self.client.get(path + '/export/html', headers=AUTH).text
        self.assertIn('Guest inspection', html)
        self.assertIn('VMs inspected', html)
        self.assertNotIn('port </small>', html)

    def test_subscription_guest_background_worker_reports_private_and_skipped_vms(self):
        fixture = Path(self.directory.name) / 'subscription-fixture.py'
        fixture.write_text('''import sys
from azure_php_scout.guest import run_guest
sys.path.insert(0, sys.argv[1])
from test_guest import SUBSCRIPTION, fleet_reader, output
def invoke(identifier, os, timeout, stop):
    return output(os=os)
raise SystemExit(run_guest([], 'results.csv', subscription=SUBSCRIPTION, runner=fleet_reader, invoker=invoke))
''', encoding='utf-8')
        with patch('azure_php_scout.service.shutil.which', return_value='fixture-az'), patch.object(
                JobManager, 'command', return_value=[sys.executable, str(fixture), str(Path(__file__).parent)]):
            response = self.client.post('/api/scans', headers=AUTH, json=dict(mode='guest', guest_subscription=SUBSCRIPTION))
            self.assertEqual(response.status_code, 202)
            job = self.wait(response.json()['id'])
        self.assertEqual(job['state'], 'partial', job)
        self.assertEqual(job['summary']['guestChecked'], 2)
        self.assertEqual(job['summary']['guestVms'], 3)
        self.assertEqual(job['coverage']['guest']['skipped'], 1)
        self.assertEqual(job['coverage']['guest']['subscriptionId'], SUBSCRIPTION)
        path = '/api/scans/' + job['id']
        html = self.client.get(path + '/export/html', headers=AUTH).text
        self.assertIn('Subscription scope:', html)
        self.assertIn('Synthetic subscription', html)
        self.assertIn('stopped-private', html)
        rows = self.client.get(path + '/results', headers=AUTH).json()['rows']
        self.assertEqual(len(rows), 3)
        self.assertEqual({row['guestStatus'] for row in rows}, {'checked', 'skipped'})

    def test_all_subscriptions_guest_worker_automates_discovery_and_combines_exports(self):
        fixture = Path(self.directory.name) / 'account-fixture.py'
        fixture.write_text('''import sys
from azure_php_scout.guest import run_guest
sys.path.insert(0, sys.argv[1])
from test_guest_accounts import account_reader
from test_guest import output
def invoke(identifier, os, timeout, stop):
    return output(os=os)
raise SystemExit(run_guest([], 'results.csv', all_subscriptions=True, runner=account_reader, invoker=invoke))
''', encoding='utf-8')
        with patch('azure_php_scout.service.shutil.which', return_value='fixture-az'), patch.object(
                JobManager, 'command', return_value=[sys.executable, str(fixture), str(Path(__file__).parent)]):
            response = self.client.post('/api/scans', headers=AUTH, json=dict(mode='guest', guest_all_subscriptions=True))
            self.assertEqual(response.status_code, 202)
            job = self.wait(response.json()['id'])
        self.assertEqual(job['state'], 'partial', job)
        self.assertTrue(job['config']['guest_all_subscriptions'])
        self.assertEqual(job['coverage']['subscriptions'], 5)
        self.assertEqual(job['summary']['guestChecked'], 2,
                         self.client.get('/api/scans/' + job['id'] + '/logs', headers=AUTH).json())
        self.assertEqual(job['summary']['guestVms'], 3)
        path = '/api/scans/' + job['id']
        html = self.client.get(path + '/export/html', headers=AUTH).text
        self.assertIn('Coverage by subscription (5 subscriptions)', html)
        self.assertIn('Synthetic denied subscription', html)
        coverage = self.client.get(path + '/export/json', headers=AUTH).json()
        self.assertEqual(len(coverage['guest']['subscriptionResults']), 5)

    def test_cancellation_preserves_a_terminal_job(self):
        created = self.client.post("/api/scans", headers=AUTH, json=dict(mode="demo", name="Cancelled demo")).json()
        job = self.wait(created["id"])
        cancelled = self.client.post("/api/scans/" + job["id"] + "/cancel", headers=AUTH, json={}).json()
        self.assertEqual(cancelled["state"], "complete")

    def test_queued_and_running_workers_can_be_cancelled(self):
        fixture = [sys.executable, "-u", "-c", "import time; print('fixture ready', flush=True); time.sleep(30)"]
        with patch.object(JobManager, "command", return_value=fixture):
            created = self.client.post("/api/scans", headers=AUTH,
                json=dict(mode="targets", targets=["127.0.0.1"], vm_ports="80")).json()
            path = "/api/scans/" + created["id"]
            deadline = time.monotonic() + 10
            while "fixture ready" not in self.client.get(path + "/logs", headers=AUTH).json()["text"]:
                if time.monotonic() > deadline:
                    self.fail("Fixture worker did not start")
                time.sleep(0.05)
            queued = self.client.post("/api/scans", headers=AUTH, json=dict(mode="demo")).json()
            self.assertEqual(queued["state"], "queued")
            cancelled = self.client.post("/api/scans/" + queued["id"] + "/cancel", headers=AUTH, json={}).json()
            self.assertEqual(cancelled["state"], "cancelled")
            self.client.post(path + "/cancel", headers=AUTH, json={})
            self.assertEqual(self.wait(created["id"])["state"], "cancelled")


class PersistenceTests(unittest.TestCase):
    def test_restart_marks_unfinished_jobs_interrupted(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = JobManager(directory)
            with manager.database() as db:
                db.execute("INSERT INTO jobs(id,state,created,updated,config) VALUES(?,?,?,?,?)",
                           ("00000000-0000-0000-0000-000000000001", "running", "2026-01-01", "2026-01-01", "{}"))
            manager.close()
            manager = JobManager(directory)
            try:
                self.assertEqual(manager.list()[0]["state"], "interrupted")
            finally:
                manager.close()

    def test_generated_token_is_stable_private_and_not_tracked(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            first = service_token(directory)
            self.assertGreaterEqual(len(first), 32)
            self.assertEqual(service_token(directory), first)
            if os.name == "posix":
                self.assertEqual((Path(directory) / "service-token").stat().st_mode & 0o777, 0o600)

    def test_placeholder_environment_tokens_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            for token in ("short", "replace-with-a-random-token-at-least-32-characters"):
                with self.subTest(token=token), patch.dict(os.environ, {"SCOUT_API_TOKEN": token}):
                    with self.assertRaises(RuntimeError):
                        service_token(directory)


if __name__ == "__main__":
    unittest.main()
