"""Bound Azure CLI waits, including descendants of shell/cmd launchers."""
import os
import signal
import subprocess
import time


class CommandCancelled(RuntimeError):
    pass


def process_options():
    if os.name == "posix":
        return dict(start_new_session=True)
    if os.name == "nt":
        return dict(creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    return {}


def stop_tree(process):
    """Never use an unbounded communicate while cleaning up a timed-out client."""
    pid = process.pid
    grouped = os.name == "posix" and isinstance(pid, int) and pid > 1
    if grouped:
        try:
            # The launcher may have exited while its child still holds the pipes.
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    elif os.name == "nt" and isinstance(pid, int) and pid > 1 and process.poll() is None:
        try:
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=2, check=False)
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
    elif process.poll() is None:
        process.terminate()
    try:
        process.communicate(timeout=2)
        return
    except subprocess.TimeoutExpired:
        pass
    if grouped:
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        process.kill()
    try:
        process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        # Do not let a detached process holding an inherited pipe freeze a scan.
        pass


def capture(arguments, *, timeout, stop=None):
    env = dict(os.environ)
    env.pop("SCOUT_API_TOKEN", None)
    env["PYTHONIOENCODING"] = "utf-8"
    if stop is not None and stop.is_set():
        raise CommandCancelled("Azure CLI request cancelled before submission")
    process = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, encoding="utf-8", errors="replace", env=env, **process_options())
    deadline = time.monotonic() + timeout
    finished = False
    try:
        while True:
            if stop is not None and stop.is_set():
                raise CommandCancelled("Stopped waiting for Azure CLI")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(arguments, timeout)
            try:
                stdout, stderr = process.communicate(timeout=min(0.25, remaining))
                finished = True
                return subprocess.CompletedProcess(arguments, process.returncode, stdout, stderr)
            except subprocess.TimeoutExpired:
                continue
    finally:
        if not finished:
            stop_tree(process)
