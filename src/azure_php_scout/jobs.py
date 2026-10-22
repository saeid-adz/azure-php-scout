"""Single-worker scan queue with SQLite history and isolated subprocess artifacts."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import csv
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import threading
from uuid import UUID, uuid4

from .advisories import enrich
from .report import endpoint_key, write_html_report

TERMINAL = {"complete", "partial", "failed", "cancelled", "interrupted"}


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def summarize(rows):
    rows = list(rows)
    unique = {endpoint_key(row): row for row in rows}.values()
    result = dict(endpoints=0, responded=0, php=0, wordpress=0, potentiallyAffected=0, endOfLife=0, verifyVersion=0)
    for row in unique:
        result["endpoints"] += 1
        result["responded"] += row.get("reachable") == "yes"
        result["php"] += row.get("php") in ("yes", "probable")
        result["wordpress"] += row.get("wordpress") in ("yes", "probable")
        result["potentiallyAffected"] += row.get("assessment") == "potentially_affected"
        result["endOfLife"] += row.get("assessment") == "end_of_life"
        result["verifyVersion"] += row.get("assessment") in ("verify_version", "configuration_only")
    result["guestVms"] = len({row.get("resourceId") for row in rows if row.get("evidenceSource") == "guest"})
    result["guestChecked"] = len({row.get("resourceId") for row in rows if row.get("guestStatus") in ("checked", "incomplete")})
    return result


class JobManager:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.processes, self.futures = {}, {}
        self.closing = False
        self.instance_lock = (self.root / "service.lock").open("a+b")
        try:
            if os.name == "posix":
                import fcntl
                fcntl.flock(self.instance_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                import msvcrt
                self.instance_lock.write(b"0")
                self.instance_lock.flush()
                self.instance_lock.seek(0)
                msvcrt.locking(self.instance_lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            self.instance_lock.close()
            raise RuntimeError("Another service owns this data directory. Run one service worker per directory.") from exc
        with self.database() as db:
            db.execute("CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, state TEXT NOT NULL, created TEXT NOT NULL, updated TEXT NOT NULL, config TEXT NOT NULL, summary TEXT NOT NULL DEFAULT '{}', exit_code INTEGER, error TEXT NOT NULL DEFAULT '')")
            db.execute("UPDATE jobs SET state='interrupted', updated=?, error='Service restarted before this run completed; inspect partial exports.' WHERE state IN ('queued','running','cancelling')", (now(),))
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="scout-job")

    @contextmanager
    def database(self):
        connection = sqlite3.connect(self.root / "jobs.sqlite", timeout=15)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def decode(row):
        if row is None:
            raise KeyError("Scan not found")
        value = dict(row)
        value["config"] = json.loads(value["config"])
        value["summary"] = json.loads(value["summary"])
        return value

    def list(self):
        with self.database() as db:
            return [self.decode(row) for row in db.execute("SELECT * FROM jobs ORDER BY created DESC LIMIT 200")]

    def get(self, job_id):
        job_id = str(UUID(job_id))
        with self.database() as db:
            return self.decode(db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())

    def update(self, job_id, **values):
        allowed = {"state", "summary", "exit_code", "error"}
        if not set(values).issubset(allowed):
            raise ValueError("Invalid job update")
        if "summary" in values:
            values["summary"] = json.dumps(values["summary"])
        values["updated"] = now()
        with self.database() as db:
            db.execute("UPDATE jobs SET " + ", ".join(key + "=?" for key in values) + " WHERE id=?", (*values.values(), job_id))

    def directory(self, job_id):
        self.get(job_id)
        return self.root / "runs" / str(UUID(job_id))

    def create(self, config):
        with self.lock:
            if self.closing:
                raise RuntimeError("Service is shutting down")
            if sum(job["state"] not in TERMINAL for job in self.list()) >= 8:
                raise RuntimeError("The scan queue is full (8 runs). Wait or cancel a queued run.")
            job_id = str(uuid4())
            timestamp = now()
            folder = self.root / "runs" / job_id
            folder.mkdir(mode=0o700, parents=True)
            with self.database() as db:
                db.execute("INSERT INTO jobs(id,state,created,updated,config) VALUES(?,?,?,?,?)",
                           (job_id, "queued", timestamp, timestamp, json.dumps(config)))
            self.futures[job_id] = self.executor.submit(self.run, job_id)
            self.futures[job_id].add_done_callback(lambda _future: self.release_future(job_id))
            return self.get(job_id)

    def release_future(self, job_id):
        with self.lock:
            self.futures.pop(job_id, None)

    def rows(self, job_id):
        path = self.directory(job_id) / "results.csv"
        if not path.exists():
            return []
        with path.open(newline="", encoding="utf-8-sig") as source:
            return [enrich(row) for row in csv.DictReader(source)
                    if row.get("target") and (row.get("port") or row.get("evidenceSource") == "guest") and row.get("php") is not None]

    def coverage(self, job_id):
        path = self.directory(job_id) / "results.coverage.json"
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            return {}

    def command(self, config, folder):
        if config["mode"] == "guest":
            args = [sys.executable, "-m", "azure_php_scout", "guest", "-o", str(folder / "results.csv"),
                    "--guest-timeout", str(config["guest_timeout"])]
            if config.get("guest_subscription"):
                args.extend(["--subscription", config["guest_subscription"]])
            else:
                for resource_id in config["vm_ids"]:
                    args.extend(["--vm-id", resource_id])
            return args
        args = [sys.executable, "-m", "azure_php_scout", "scan", "-o", str(folder / "results.csv")]
        if config["mode"] == "azure":
            args.append("--azure")
            for subscription in config.get("subscriptions", []):
                args.extend(["--subscription", subscription])
        elif config["mode"] == "inventory":
            inventory = folder / "input.csv"
            inventory.write_text(config["inventory_csv"], encoding="utf-8")
            args.extend(["-i", str(inventory)])
        else:
            for target in config["targets"]:
                try:
                    ipaddress.ip_address(target)
                    flag = "--ip"
                except ValueError:
                    flag = "--hostname"
                args.extend([flag, target])
        args.extend(["--vm-ports", config["vm_ports"], "--timeout", str(config["timeout"]),
                     "--workers", str(config["workers"]), "--port-workers", str(config["port_workers"]),
                     "--port-rate", str(config["port_rate"]), "--port-timeout", str(config["port_timeout"])])
        if config.get("running_only"):
            args.append("--running-only")
        if config.get("no_probes"):
            args.append("--no-probes")
        if config.get("verify_tls"):
            args.append("--verify-tls")
        return args

    def demo(self, folder):
        from importlib.resources import files
        from .scanner import FIELDS
        with files("azure_php_scout").joinpath("data/demo.csv").open() as source:
            rows = [enrich(row) for row in csv.DictReader(source)]
        with (folder / "results.csv").open("w", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        scope = dict(source="Synthetic community demo — no network requests", resources=dict(vm=3, appservice=2, staticwebapp=1),
                     subscriptions=1, vmPortScope="Demo data", vmAddresses=3, appPorts=[80, 443], errors=[], skipped=[],
                     scanStatus="complete", httpChecked=len(rows), scheduled=len(rows), tcp={})
        (folder / "results.coverage.json").write_text(json.dumps(scope, indent=2))
        write_html_report(folder / "results.html", rows, scope=scope)

    def run(self, job_id):
        folder = self.root / "runs" / job_id
        try:
            with self.lock:
                job = self.get(job_id)
                if job["state"] == "cancelled":
                    return
                self.update(job_id, state="running")
            if job["config"]["mode"] == "demo":
                self.demo(folder)
                code = 0
            else:
                env = dict(os.environ)
                env.pop("SCOUT_API_TOKEN", None)
                with (folder / "scan.log").open("wb") as log:
                    with self.lock:
                        if self.get(job_id)["state"] == "cancelling":
                            self.update(job_id, state="cancelled")
                            return
                        process = subprocess.Popen(self.command(job["config"], folder), cwd=folder,
                                                   stdout=log, stderr=subprocess.STDOUT, env=env)
                        self.processes[job_id] = process
                    code = process.wait()
            with self.lock:
                cancelled = self.get(job_id)["state"] in ("cancelling", "cancelled")
                rows = self.rows(job_id)
                coverage = self.coverage(job_id)
                state = "cancelled" if cancelled else "complete" if code == 0 else "partial" if rows else "failed"
                if code and not cancelled and job["config"]["mode"] == "guest" and not coverage.get("guest", {}).get("checked"):
                    state = "failed"
                errors = "; ".join(coverage.get("errors", []))
                if code and not errors and not cancelled:
                    errors = "Scanner exited with status {}. Inspect the scan log for details.".format(code)
                self.update(job_id, state=state, exit_code=code, summary=summarize(rows), error=errors)
        except Exception as exc:
            self.update(job_id, state="failed", error=str(exc)[:2000])
        finally:
            with self.lock:
                self.processes.pop(job_id, None)

    @staticmethod
    def signal_stop(process):
        if process.poll() is not None:
            return
        try:
            process.send_signal(signal.SIGINT) if os.name == "posix" else process.terminate()
        except ProcessLookupError:
            return
        def enforce():
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        threading.Thread(target=enforce, daemon=True).start()

    def cancel(self, job_id):
        with self.lock:
            job = self.get(job_id)
            if job["state"] in TERMINAL:
                return job
            future = self.futures.get(job_id)
            if future and future.cancel():
                self.update(job_id, state="cancelled")
            else:
                self.update(job_id, state="cancelling")
                if job_id in self.processes:
                    self.signal_stop(self.processes[job_id])
            return self.get(job_id)

    def close(self):
        with self.lock:
            self.closing = True
            for job in self.list():
                if job["state"] not in TERMINAL:
                    self.cancel(job["id"])
        self.executor.shutdown(wait=True, cancel_futures=True)
        self.instance_lock.close()
