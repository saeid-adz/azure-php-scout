"""Opt-in guest PHP inventory using fixed Azure Action Run Command scripts."""
import argparse
import base64
import binascii
from collections import defaultdict
import csv
import hashlib
from importlib.resources import files
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from uuid import UUID

from .advisories import enrich, parse_version
from .inventory import az_json, graph_resources, resource_records
from .report import csv_cell, write_html_report

GUEST_FIELDS = ["evidenceSource", "guestStatus", "guestSource", "guestPath", "guestPackage",
                "guestPackageVersion", "guestProcessObserved", "guestCoverage", "guestScriptSha256"]
VM_QUERY = """Resources
| where type =~ 'microsoft.compute/virtualmachines'
| project id, name, resourceGroup, subscriptionId,
    os=properties.storageProfile.osDisk.osType,
    powerState=properties.extended.instanceView.powerState.code
| order by id asc"""
COMMANDS = {"Linux": ("RunShellScript", "inspect-linux.sh"),
            "Windows": ("RunPowerShellScript", "inspect-windows.ps1")}


def vm_id(value):
    match = re.fullmatch(r"/subscriptions/([^/]+)/resourceGroups/([\w.()-]+)/providers/Microsoft\.Compute/virtualMachines/([\w.-]+)",
                         str(value).strip().rstrip("/"), re.I)
    if not match:
        raise ValueError("Use a complete Azure virtual machine resource ID")
    subscription = str(UUID(match[1]))
    return "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}".format(
        subscription, match[2], match[3])


def selected_vm_ids(values):
    result = {vm_id(value).casefold(): vm_id(value) for value in values}
    if not 1 <= len(result) <= 50:
        raise ValueError("Select between 1 and 50 VM resource IDs")
    return list(result.values())


def list_vms(subscriptions=None, runner=az_json):
    records, accounts, errors = resource_records(VM_QUERY, subscriptions, runner)
    names = {item["id"].lower(): item.get("name", item["id"]) for item in accounts}
    return dict(vms=[dict(resourceId=row["id"], vm=row["name"], os=row.get("os") or "Unknown",
                         resourceGroup=row.get("resourceGroup", ""), subscriptionId=row.get("subscriptionId", ""),
                         subscription=names.get(row.get("subscriptionId", "").lower(), ""),
                         powerState=row.get("powerState") or "unknown") for row in records], errors=errors)


def subscription_vms(subscription, runner=az_json):
    """Resolve one explicit subscription completely before submitting any commands."""
    subscription = str(UUID(subscription))
    inventory = list_vms([subscription], runner=runner)
    if inventory["errors"]:
        raise RuntimeError("Subscription VM discovery incomplete; no guest commands submitted. " +
                           "; ".join(inventory["errors"]))
    machines = {}
    for machine in inventory["vms"]:
        identifier = vm_id(machine["resourceId"])
        if identifier.split("/")[2] != subscription:
            raise ValueError("VM discovery returned a resource outside the selected subscription; no commands submitted")
        machines[identifier.casefold()] = dict(machine, resourceId=identifier)
    return list(machines.values())


def all_subscription_vms(*, runner=az_json, stop=None, progress=None, updated=None):
    """Refresh account scope, batch by tenant, and isolate failed subscription reads."""
    stop = stop or threading.Event()
    accounts = runner(["account", "list", "--all", "--refresh"])
    if not isinstance(accounts, list) or not accounts:
        raise RuntimeError("No Azure subscriptions visible. Run az login on the service host.")
    subscriptions = {}
    for account in accounts:
        if not isinstance(account, dict) or not account.get("id"):
            raise ValueError("Azure CLI returned an invalid subscription record; no commands submitted")
        identifier = str(UUID(account["id"]))
        subscriptions.setdefault(identifier, dict(id=identifier, name=account.get("name") or identifier,
            tenantId=account.get("tenantId") or "", state=account.get("state") or "Unknown",
            discoveryStatus="pending", requested=0, checked=0, failed=0, skipped=0, completed=0, notSubmitted=0))
    result = dict(vms=[], subscriptions=list(subscriptions.values()), errors=[], discoveryStatus="running")
    groups = defaultdict(list)
    for info in subscriptions.values():
        if info["state"].lower() == "enabled":
            groups[info["tenantId"]].append(info["id"])
        else:
            info.update(discoveryStatus="skipped", error="Subscription state is {}; no guest commands submitted.".format(info["state"]))
            result["errors"].append("{} ({}): {}".format(info["name"], info["id"], info["error"]))

    def snapshot():
        if updated:
            updated(result)

    def discover(ids):
        if stop.is_set():
            return
        if progress:
            progress("Discovering VMs in {} subscription(s), tenant {}.".format(len(ids), subscriptions[ids[0]]["tenantId"]))
        try:
            records = graph_resources(ids, runner, query=VM_QUERY)
            machines = {}
            for record in records:
                identifier = vm_id(record["id"])
                subscription = identifier.split("/")[2]
                if subscription not in ids:
                    raise ValueError("VM discovery returned a resource outside the requested subscriptions")
                machines[identifier.casefold()] = dict(resourceId=identifier, vm=record.get("name") or identifier.split("/")[-1],
                    os=record.get("os") or "Unknown", resourceGroup=record.get("resourceGroup") or identifier.split("/")[4],
                    subscriptionId=subscription, subscription=subscriptions[subscription]["name"],
                    powerState=record.get("powerState") or "unknown")
        except (RuntimeError, ValueError, OSError, KeyError, TypeError) as exc:
            if len(ids) > 1:
                # Retry inventory reads individually; never retry guest execution.
                for identifier in ids:
                    discover([identifier])
                return
            info = subscriptions[ids[0]]
            info.update(discoveryStatus="failed", error=str(exc)[:1000])
            result["errors"].append("{} ({}): VM discovery failed; no commands submitted in this subscription. {}".format(
                info["name"], info["id"], info["error"]))
        else:
            result["vms"].extend(machines.values())
            for identifier in ids:
                subscriptions[identifier].update(discoveryStatus="complete",
                    requested=sum(item["subscriptionId"] == identifier for item in machines.values()))
        snapshot()

    snapshot()
    for ids in groups.values():
        for offset in range(0, len(ids), 100):
            discover(ids[offset:offset + 100])
    if stop.is_set():
        for info in subscriptions.values():
            if info["discoveryStatus"] == "pending":
                info.update(discoveryStatus="not_submitted", error="Scan stopped before subscription discovery.")
        result["errors"].append("Scan stopped before guest command submission; subscription discovery may be incomplete.")
        result["discoveryStatus"] = "interrupted"
    else:
        result["discoveryStatus"] = "partial" if result["errors"] else "complete"
    snapshot()
    return result


def script_info(os_name):
    command, filename = COMMANDS[os_name]
    resource = files("azure_php_scout").joinpath("scripts/" + filename)
    content = resource.read_bytes()
    return dict(commandId=command, filename=filename, sha256=hashlib.sha256(content).hexdigest(),
                script=content.decode("utf-8"))


def _decode(value, limit):
    try:
        raw = base64.b64decode(value, validate=True)
        text = raw.decode("utf-8")
    except (ValueError, binascii.Error, UnicodeError) as exc:
        raise ValueError("Invalid encoded guest inventory field") from exc
    if len(raw) > limit or any(ord(char) < 32 for char in text):
        raise ValueError("Invalid or oversized guest inventory field")
    return text


def parse_output(result, expected_os):
    """Require a complete frame; Azure only returns the last 4,096 output bytes."""
    components = result.get("value") if isinstance(result, dict) else None
    if not isinstance(components, list) or not components:
        raise ValueError("Run Command returned no status/output")
    messages = []
    for component in components:
        if not isinstance(component, dict):
            raise ValueError("Invalid Run Command status component")
        code = str(component.get("code", "")).lower()
        if code.endswith("/failed") or str(component.get("level", "")).lower() == "error":
            raise ValueError("Azure reported a failed guest command; inspect VM agent status and permissions")
        if "stderr" not in code:
            messages.append(str(component.get("message", "")))
    output = "\n".join(messages)
    begin, end = "SCOUT_GUEST_BEGIN_V1", "SCOUT_GUEST_END_V1"
    if output.count(begin) != 1 or output.count(end) != 1:
        raise ValueError("Guest output is missing its complete frame; it may be truncated or the script failed")
    body = output.split(begin, 1)[1].split(end, 1)[0]
    if len(body.encode("utf-8")) > 4096:
        raise ValueError("Guest output exceeds the supported output budget")
    runtime, packages, metadata = [], [], {}
    for line in body.strip().splitlines():
        parts = line.strip().split("|")
        kind = parts[0]
        if kind == "RUNTIME" and len(parts) == 4:
            if not parse_version(parts[1]) or parts[3] not in ("binary", "file_metadata"):
                raise ValueError("Unrecognized PHP version/source in guest output")
            runtime.append(dict(version=parts[1], path=_decode(parts[2], 160), source=parts[3]))
        elif kind == "PACKAGE" and len(parts) == 3:
            packages.append(dict(name=_decode(parts[1], 64), version=_decode(parts[2], 96)))
        elif kind in ("OS", "PROCESS", "PACKAGES", "BINARY_ERRORS", "LIMIT") and len(parts) == 2:
            if kind in metadata:
                raise ValueError("Duplicate guest inventory metadata")
            metadata[kind] = parts[1]
        else:
            raise ValueError("Unrecognized guest inventory output")
    if (set(metadata) != {"OS", "PROCESS", "PACKAGES", "BINARY_ERRORS", "LIMIT"}
            or metadata["OS"] != expected_os or metadata["PROCESS"] not in ("yes", "no", "unknown")
            or metadata["PACKAGES"] not in ("dpkg", "rpm", "unavailable", "not_checked")
            or metadata["LIMIT"] not in ("yes", "no") or not metadata["BINARY_ERRORS"].isdigit()
            or len(runtime) > 8 or len(packages) > 16):
        raise ValueError("Guest inventory is incomplete or does not match the VM operating system")
    return dict(runtimes=runtime, packages=packages, process=metadata["PROCESS"],
                limited=metadata["LIMIT"] == "yes", binaryErrors=int(metadata["BINARY_ERRORS"]),
                packageTool=metadata["PACKAGES"], scriptSha256=result.get("_scoutScriptSha256"))


class GuestCommandError(RuntimeError):
    def __init__(self, message, *, remote_may_continue=False, status="failed"):
        super().__init__(message)
        self.remote_may_continue = remote_may_continue
        self.status = status
        self.script_sha256 = None


def invoke(resource_id, os_name, timeout, stop):
    """No shell, caller-supplied scripts, credential arguments, or automatic retries."""
    if stop.is_set():
        raise GuestCommandError("Cancelled before Run Command was submitted", status="cancelled")
    command, filename = COMMANDS[os_name]
    resource = files("azure_php_scout").joinpath("scripts/" + filename)
    snapshot = resource.read_bytes()
    script_hash = hashlib.sha256(snapshot).hexdigest()
    env = dict(os.environ)
    env.pop("SCOUT_API_TOKEN", None)
    env["PYTHONIOENCODING"] = "utf-8"
    with tempfile.TemporaryDirectory(prefix="scout-guest-script-") as folder:
        script = Path(folder) / filename
        script.write_bytes(snapshot)
        args = ["az", "vm", "run-command", "invoke", "--ids", resource_id,
                "--subscription", resource_id.split("/")[2], "--command-id", command,
                "--scripts", "@" + str(script), "--only-show-errors", "-o", "json"]
        try:
            process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, encoding="utf-8", errors="replace", env=env)
        except OSError as exc:
            raise GuestCommandError("Unable to start Azure CLI for guest inspection") from exc
        deadline = time.monotonic() + timeout
        try:
            while True:
                try:
                    stdout, stderr = process.communicate(timeout=0.25)
                    break
                except subprocess.TimeoutExpired:
                    if stop.is_set() or time.monotonic() >= deadline:
                        status = "cancelled" if stop.is_set() else "timeout"
                        raise GuestCommandError(
                            "Stopped waiting for Azure Run Command. The submitted VM script may still be running; check Azure before retrying.",
                            remote_may_continue=True, status=status)
            if process.returncode:
                message = (stderr.strip().splitlines() or ["Azure CLI Run Command request failed"])[0][:500]
                # CLI failure can occur while polling an already accepted action.
                raise GuestCommandError(message, remote_may_continue=True)
            try:
                result = json.loads(stdout)
                if not isinstance(result, dict):
                    raise ValueError("Invalid Run Command result")
                result["_scoutScriptSha256"] = script_hash
                return result
            except ValueError as exc:
                raise GuestCommandError("Azure CLI returned invalid Run Command JSON; Azure execution state is unknown", remote_may_continue=True) from exc
        except GuestCommandError as exc:
            exc.script_sha256 = script_hash
            raise
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()


def base_row(resource_id, vm=None):
    vm = vm or {}
    os_name = ((vm.get("storageProfile") or {}).get("osDisk") or {}).get("osType") or vm.get("os") or ""
    return dict(resourceType="vm", resourceId=resource_id, vmId=resource_id,
                subscriptionId=resource_id.split("/")[2], subscription=vm.get("subscription") or resource_id.split("/")[2],
                resourceGroup=vm.get("resourceGroup") or resource_id.split("/")[4],
                vm=vm.get("name") or resource_id.split("/")[-1], os=os_name,
                target=resource_id, hostname=vm.get("name") or resource_id.split("/")[-1], port="",
                evidenceSource="guest", guestStatus="checked", php="unknown", wordpress="unknown",
                phpVersion="", reachable="no", service="azure-run-command", guestProcessObserved="unknown")


def result_rows(resource_id, vm, output):
    base = base_row(resource_id, vm)
    partial = output["limited"] or output["binaryErrors"] > 0 or output["process"] == "unknown"
    limitations = "Bounded host inventory; custom locations, containers, PHP extensions in Apache, and WordPress files are not exhaustively inspected. Installed disk/package versions do not prove the version executing web requests."
    if output["limited"]:
        limitations += " Output/candidate limit reached."
    if output["binaryErrors"]:
        limitations += " {} binary version checks could not complete.".format(output["binaryErrors"])
    if output["packageTool"] == "unavailable":
        limitations += " No supported package manager was available."
    base.update(guestStatus="incomplete" if partial else "checked", guestProcessObserved=output["process"],
                guestCoverage=limitations, note=limitations, guestScriptSha256=output.get("scriptSha256") or script_info(base["os"])["sha256"])
    rows = []
    seen = set()
    for item in output["runtimes"]:
        key = (item["path"].casefold(), item["version"])
        if key in seen:
            continue
        seen.add(key)
        rows.append(enrich(dict(base, php="yes", phpVersion=item["version"], guestSource=item["source"],
                                guestPath=item["path"], evidence="Guest {}: {} reports PHP {}".format(item["source"], item["path"], item["version"]))))
    for item in output["packages"]:
        # Epochs are packaging metadata; retain the complete vendor version separately.
        version = re.sub(r"^\d+:", "", item["version"])
        if not parse_version(version):
            continue
        rows.append(enrich(dict(base, php="yes", phpVersion=version, guestSource="package",
                                guestPackage=item["name"], guestPackageVersion=item["version"],
                                evidence="Installed {} package {}: {}".format(output["packageTool"], item["name"], item["version"]))))
    if not rows:
        rows.append(enrich(dict(base, php="probable" if output["process"] == "yes" else "unknown",
                                evidence="PHP process observed without a usable version." if output["process"] == "yes" else
                                "No PHP version found in the inspected locations. This is not proof that PHP is absent.")))
    return rows


def inspect_vm(resource_id, *, timeout, stop, runner=az_json, invoker=invoke):
    args = ["--ids", resource_id, "--subscription", resource_id.split("/")[2]]
    vm = runner(["vm", "show", *args])
    row = base_row(resource_id, vm)
    if row["os"] not in COMMANDS:
        return [enrich(dict(row, guestStatus="skipped", note="Unsupported or unknown VM OS; no command submitted."))], False
    view = runner(["vm", "get-instance-view", *args])
    view = view.get("instanceView") or view
    power = next((item.get("code", "") for item in (view.get("statuses") or []) if item.get("code", "").lower().startswith("powerstate/")), "unknown")
    ready = any(item.get("code", "").lower() == "provisioningstate/succeeded" for item in ((view.get("vmAgent") or {}).get("statuses") or []))
    if power.lower() != "powerstate/running" or not ready:
        return [enrich(dict(row, powerState=power, guestStatus="skipped", note="VM must be running with a ready Azure VM Agent. No guest command submitted."))], False
    if stop.is_set():
        return [enrich(dict(row, guestStatus="cancelled", note="Cancelled before guest command submission."))], False
    try:
        response = invoker(resource_id, row["os"], timeout, stop)
        return result_rows(resource_id, vm, parse_output(response, row["os"])), False
    except GuestCommandError as exc:
        return [enrich(dict(row, guestStatus=exc.status, note=str(exc), guestScriptSha256=exc.script_sha256 or ""))], exc.remote_may_continue
    except ValueError as exc:
        return [enrich(dict(row, guestStatus="failed", note=str(exc)))], False


def save_results(destination, rows, scope):
    from .scanner import FIELDS
    destination = Path(destination)
    fields = list(dict.fromkeys(FIELDS + GUEST_FIELDS))
    temporary = destination.with_name("." + destination.name + ".tmp")
    try:
        with temporary.open("w", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=fields)
            writer.writeheader()
            writer.writerows({key: csv_cell(value) for key, value in row.items()} for row in rows)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    coverage = destination.with_suffix(".coverage.json")
    temporary = coverage.with_name("." + coverage.name + ".tmp")
    try:
        temporary.write_text(json.dumps(scope, indent=2), encoding="utf-8")
        temporary.replace(coverage)
    finally:
        temporary.unlink(missing_ok=True)
    write_html_report(destination.with_suffix(".html"), rows, status=scope["scanStatus"], scope=scope)


def run_guest(vm_ids, destination, *, subscription=None, all_subscriptions=False, timeout=180, stop=None, runner=az_json, invoker=invoke, progress=None):
    if all_subscriptions and (subscription is not None or vm_ids):
        raise ValueError("Choose all subscriptions, one subscription, or specific VM IDs")
    if subscription is not None:
        subscription = str(UUID(subscription))
        if vm_ids:
            raise ValueError("Choose one subscription or specific VM IDs, not both")
        vm_ids = []
    elif not all_subscriptions:
        vm_ids = selected_vm_ids(vm_ids)
    else:
        vm_ids = []
    stop = stop or threading.Event()
    rows = []
    scope = dict(scanType="guest", source="Azure VM Run Command", resources=dict(vm=len(vm_ids)),
                 subscriptions=1 if subscription else len({item.split('/')[2] for item in vm_ids}), errors=[], skipped=[],
                 scanStatus="running", remoteMayContinue=False,
                 guest=dict(scope="all_subscriptions" if all_subscriptions else "subscription" if subscription else "vms", subscriptionId=subscription,
                            discoveryStatus="pending" if subscription or all_subscriptions else "not_required",
                            requested=len(vm_ids), checked=0, failed=0, skipped=0, completed=0, notSubmitted=0))
    save_results(destination, rows, scope)
    machines = {}
    subscription_results = {}
    if all_subscriptions:
        if progress:
            progress("Refreshing all subscriptions available to the signed-in Azure CLI account.")
        def snapshot(inventory):
            scope["subscriptions"] = len(inventory["subscriptions"])
            scope["guest"].update(subscriptionResults=inventory["subscriptions"], discoveryStatus=inventory["discoveryStatus"],
                                  requested=len(inventory["vms"]))
            scope["resources"]["vm"] = len(inventory["vms"])
            scope["errors"] = list(inventory["errors"])
            save_results(destination, rows, scope)
        try:
            inventory = all_subscription_vms(runner=runner, stop=stop, progress=progress, updated=snapshot)
            machines = {item["resourceId"].casefold(): item for item in inventory["vms"]}
            vm_ids = [item["resourceId"] for item in inventory["vms"]]
            subscription_results = {item["id"]: item for item in inventory["subscriptions"]}
        except (RuntimeError, ValueError, OSError, KeyError, TypeError) as exc:
            scope["guest"]["discoveryStatus"] = "failed"
            scope["errors"].append(str(exc)[:2000])
            scope["scanStatus"] = "interrupted" if stop.is_set() else "failed"
            save_results(destination, rows, scope)
            return 130 if stop.is_set() else 1
    elif subscription:
        if progress:
            progress("Discovering all VMs in subscription {} (public and private).".format(subscription))
        try:
            if not stop.is_set():
                inventory = subscription_vms(subscription, runner=runner)
                machines = {item["resourceId"].casefold(): item for item in inventory}
                vm_ids = [item["resourceId"] for item in inventory]
                scope["guest"].update(discoveryStatus="complete", requested=len(vm_ids))
                scope["resources"]["vm"] = len(vm_ids)
                if inventory:
                    scope["guest"]["subscriptionName"] = inventory[0].get("subscription") or subscription
                if progress:
                    progress("Discovered {} VMs; stopped or unready VMs will be recorded as skipped.".format(len(vm_ids)))
        except (RuntimeError, ValueError, OSError) as exc:
            scope["guest"]["discoveryStatus"] = "failed"
            scope["errors"].append(str(exc)[:2000])
            scope["scanStatus"] = "interrupted" if stop.is_set() else "failed"
            save_results(destination, rows, scope)
            return 130 if stop.is_set() else 1
        save_results(destination, rows, scope)
    for resource_id in vm_ids:
        if stop.is_set():
            rows.append(enrich(dict(base_row(resource_id, machines.get(resource_id.casefold())),
                                    guestStatus="not_submitted", note="Inspection stopped before this VM was submitted.")))
            scope["guest"]["notSubmitted"] += 1
            if resource_id.split("/")[2] in subscription_results:
                subscription_results[resource_id.split("/")[2]]["notSubmitted"] += 1
            continue
        scope["guest"]["currentVm"] = resource_id
        if progress:
            progress("Guest inspection: {} / {}: {}".format(scope["guest"]["completed"] + 1, len(vm_ids), resource_id))
        save_results(destination, rows, scope)
        try:
            findings, remote = inspect_vm(resource_id, timeout=timeout, stop=stop, runner=runner, invoker=invoker)
        except (RuntimeError, ValueError) as exc:
            findings, remote = [enrich(dict(base_row(resource_id, machines.get(resource_id.casefold())), guestStatus="failed", note=str(exc)[:1000]))], False
        for finding in findings:
            machine = machines.get(resource_id.casefold(), {})
            if machine.get("subscription"):
                finding["subscription"] = machine["subscription"]
        rows.extend(findings)
        state = findings[0]["guestStatus"]
        scope["guest"]["completed"] += 1
        scope["guest"]["checked"] += state in ("checked", "incomplete")
        scope["guest"]["skipped"] += state == "skipped"
        scope["guest"]["failed"] += state not in ("checked", "incomplete", "skipped")
        info = subscription_results.get(resource_id.split("/")[2])
        if info is not None:
            info["completed"] += 1
            info["checked"] += state in ("checked", "incomplete")
            info["skipped"] += state == "skipped"
            info["failed"] += state not in ("checked", "incomplete", "skipped")
        scope["remoteMayContinue"] |= remote
        if state != "checked":
            scope["errors"].append("{}: {}".format(resource_id, findings[0].get("note") or findings[0].get("guestCoverage") or state))
        if state == "skipped":
            scope["skipped"].append(dict(vm=findings[0]["vm"], resourceId=resource_id, reason=findings[0]["note"]))
        save_results(destination, rows, scope)
    scope["guest"].pop("currentVm", None)
    if stop.is_set():
        scope["errors"].append("Inspection stopped; {} remaining VM commands were not submitted.".format(scope["guest"]["notSubmitted"]))
    scope["scanStatus"] = "interrupted" if stop.is_set() else "failed" if scope["errors"] else "complete"
    save_results(destination, rows, scope)
    return 130 if stop.is_set() else 1 if scope["errors"] else 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="azure-php-scout guest", description="Inspect PHP on Windows/Linux VMs, including private VMs. Executes fixed scripts as root/SYSTEM through Azure Run Command.")
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--vm-id", action="append", help="complete VM resource ID; repeat for up to 50 selected VMs")
    selection.add_argument("--subscription", help="inspect every VM in this one subscription UUID, with or without a public IP")
    selection.add_argument("--all-subscriptions", action="store_true", help="automatically discover all subscriptions available to Azure CLI and inspect their Windows/Linux VMs")
    parser.add_argument("--guest-timeout", type=int, default=180, help="seconds to wait per VM (60–1800); remote scripts cannot be cancelled")
    parser.add_argument("--dry-run", action="store_true", help="read selected VM metadata and print the plan without executing guest commands")
    parser.add_argument("-o", "--output", default="guest-results.csv")
    args = parser.parse_args(argv)
    try:
        subscription = str(UUID(args.subscription)) if args.subscription else None
        ids = selected_vm_ids(args.vm_id) if args.vm_id else []
        if not 60 <= args.guest_timeout <= 1800:
            raise ValueError("Guest timeout must be between 60 and 1800 seconds")
        destination = Path(args.output)
        if destination.suffix.lower() != ".csv":
            raise ValueError("Guest output must use a .csv filename")
        if args.dry_run:
            plan = []
            if args.all_subscriptions:
                inventory = all_subscription_vms(runner=az_json)
                for vm in inventory["vms"]:
                    plan.append(dict(resourceId=vm["resourceId"], os=vm["os"], commandId=COMMANDS.get(vm["os"], ("unsupported",))[0]))
                print(json.dumps(dict(subscriptions=inventory["subscriptions"], errors=inventory["errors"], vms=plan), indent=2))
                return 1 if inventory["errors"] else 0
            if subscription:
                ids = [item["resourceId"] for item in subscription_vms(subscription, runner=az_json)]
            for resource_id in ids:
                vm = az_json(["vm", "show", "--ids", resource_id, "--subscription", resource_id.split('/')[2]])
                row = base_row(resource_id, vm)
                plan.append(dict(resourceId=resource_id, os=row["os"], commandId=COMMANDS.get(row["os"], ("unsupported",))[0]))
            print(json.dumps(plan, indent=2))
            return 0
        stop = threading.Event()
        previous = {}
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.signal(sig, lambda *_args: stop.set())
        try:
            return run_guest(ids, destination, subscription=subscription, all_subscriptions=args.all_subscriptions, timeout=args.guest_timeout, stop=stop,
                             progress=lambda message: print(message, file=sys.stderr, flush=True))
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
    except (RuntimeError, ValueError, OSError) as exc:
        parser.error(str(exc))
