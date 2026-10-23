"""Read-only Azure inventory through Azure CLI / Resource Graph. No SDK dependencies."""
from collections import Counter, defaultdict
from dataclasses import dataclass, field
import json
import subprocess
from .processes import capture

QUERY = """
Resources
| where type =~ 'microsoft.compute/virtualmachines'
    or type =~ 'microsoft.network/networkinterfaces'
    or type =~ 'microsoft.network/publicipaddresses'
    or type =~ 'microsoft.web/sites'
    or type =~ 'microsoft.web/sites/slots'
    or type =~ 'microsoft.web/staticsites'
| project id, name, type, kind, resourceGroup, subscriptionId,
    nics=properties.networkProfile.networkInterfaces,
    ipConfigurations=properties.ipConfigurations,
    publicIp=properties.ipAddress, publicFqdn=properties.dnsSettings.fqdn,
    os=properties.storageProfile.osDisk.osType,
    powerState=properties.extended.instanceView.powerState.code,
    defaultHostName=coalesce(properties.defaultHostName, properties.defaultHostname), hostNames=properties.hostNames,
    hostNameSslStates=properties.hostNameSslStates, customDomains=properties.customDomains,
    state=properties.state, provisioningState=properties.provisioningState,
    linuxFxVersion=properties.siteConfig.linuxFxVersion, phpVersion=properties.siteConfig.phpVersion,
    publicNetworkAccess=properties.publicNetworkAccess
| order by id asc
"""


@dataclass
class Inventory:
    rows: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    subscriptions: int = 0
    resources: dict = field(default_factory=dict)


def az_json(arguments, *, stop=None):
    try:
        result = capture(["az", *arguments, "--only-show-errors", "-o", "json"], timeout=180, stop=stop)
    except FileNotFoundError as exc:
        raise RuntimeError("Azure CLI is required for --azure. Install az and run az login.") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Azure inventory request timed out") from exc
    if result.returncode:
        raise RuntimeError((result.stderr.strip() or "Azure CLI request failed").splitlines()[0][:1000])
    try:
        return json.loads(result.stdout)
    except ValueError as exc:
        raise RuntimeError("Azure CLI returned invalid JSON") from exc


def graph_resources(subscriptions, runner=az_json, *, query=QUERY):
    """Use a deterministic order, explicit subscription scope and every continuation page."""
    records, token, seen = [], None, set()
    while True:
        args = ["graph", "query", "-q", query, "--first", "1000", "--subscriptions",
                *subscriptions, "--subscription", subscriptions[0]]
        if token:
            args.extend(["--skip-token", token])
        page = runner(args)
        records.extend(page.get("data", []))
        token = page.get("skip_token") or page.get("$skipToken")
        if not token:
            total = page.get("total_records", page.get("totalRecords", len(records)))
            if total > len(records):
                raise RuntimeError("Azure Resource Graph truncated inventory without a continuation token")
            return records
        if token in seen:
            raise RuntimeError("Azure Resource Graph repeated a continuation token")
        seen.add(token)


def normalize_resources(records, subscriptions):
    inventory = Inventory(subscriptions=len(subscriptions))
    names = {item["id"].lower(): item.get("name", item["id"]) for item in subscriptions}
    by_id = {item["id"].lower(): item for item in records}
    counts = Counter()
    for resource in by_id.values():
        kind = resource["type"].lower()
        resource_type = ("vm" if kind == "microsoft.compute/virtualmachines" else
                         "staticwebapp" if kind == "microsoft.web/staticsites" else
                         "appservice" if kind in ("microsoft.web/sites", "microsoft.web/sites/slots") else None)
        if not resource_type:
            continue
        counts[resource_type] += 1
        metadata = dict(subscription=names.get(resource.get("subscriptionId", "").lower(), ""),
                        subscriptionId=resource.get("subscriptionId", ""), resourceGroup=resource.get("resourceGroup", ""),
                        resourceType=resource_type, resourceId=resource["id"], kind=resource.get("kind") or "",
                        publicNetworkAccess=resource.get("publicNetworkAccess") or "")
        if resource_type == "vm":
            metadata.update(vm=resource["name"], vmId=resource["id"], os=resource.get("os") or "",
                            powerState=resource.get("powerState") or "")
            addresses = set()
            for nic_ref in resource.get("nics") or []:
                nic = by_id.get((nic_ref.get("id") or "").lower(), {})
                for config in nic.get("ipConfigurations") or []:
                    pip_ref = (config.get("properties") or {}).get("publicIPAddress") or {}
                    public = by_id.get((pip_ref.get("id") or "").lower(), {})
                    if public.get("publicIp"):
                        addresses.add((public["publicIp"], public.get("publicFqdn") or ""))
            for address, fqdn in sorted(addresses):
                inventory.rows.append(dict(metadata, publicIp=address, hostname=""))
                if fqdn:
                    inventory.rows.append(dict(metadata, publicIp=address, hostname=fqdn))
            if not addresses:
                inventory.skipped.append(dict(metadata, reason="No directly attached public IP; private/NAT-only VM is outside this external scan"))
            continue
        metadata.update(app=resource["name"], state=resource.get("state") or resource.get("provisioningState") or "",
                        runtime=resource.get("linuxFxVersion") or "", phpVersion=resource.get("phpVersion") or "")
        hosts = set(resource.get("hostNames") or [])
        if resource.get("defaultHostName"):
            hosts.add(resource["defaultHostName"])
        for binding in resource.get("hostNameSslStates") or []:
            if binding.get("name") and (binding.get("hostType") or "").lower() != "repository":
                hosts.add(binding["name"])
        for domain in resource.get("customDomains") or []:
            hosts.add(domain if isinstance(domain, str) else domain.get("name") or domain.get("domainName") or "")
        hosts = {host.lower().rstrip(".") for host in hosts if host and "*" not in host and ".scm." not in host.lower()}
        for host in sorted(hosts):
            inventory.rows.append(dict(metadata, hostname=host, publicIp=""))
        if not hosts:
            inventory.skipped.append(dict(metadata, reason="Azure did not expose a default or custom hostname"))
    inventory.resources = dict(counts)
    return inventory


def resource_records(query=QUERY, subscription_ids=None, runner=az_json, progress=None):
    subscriptions = runner(["account", "list", "--all"])
    subscriptions = [item for item in subscriptions if item.get("state") == "Enabled"]
    if subscription_ids:
        selected = set(subscription_ids)
        subscriptions = [item for item in subscriptions if item["id"] in selected]
        missing = selected.difference(item["id"] for item in subscriptions)
        if missing:
            raise ValueError("Subscriptions unavailable to the Azure CLI session: " + ", ".join(sorted(missing)))
    if not subscriptions:
        raise RuntimeError("No enabled Azure subscriptions visible. Run az login.")
    groups = defaultdict(list)
    for subscription in subscriptions:
        groups[subscription.get("tenantId", "")].append(subscription["id"])
    records, errors = [], []
    for tenant, ids in groups.items():
        for offset in range(0, len(ids), 100):
            chunk = ids[offset:offset + 100]
            if progress:
                progress("Azure inventory: {} subscriptions in tenant {}".format(len(chunk), tenant))
            try:
                records.extend(graph_resources(chunk, runner, query=query))
            except RuntimeError as exc:
                errors.append("Tenant {}, subscriptions {}: {}".format(tenant, ", ".join(chunk), exc))
    return records, subscriptions, errors


def discover_azure(subscription_ids=None, runner=az_json, progress=None):
    records, subscriptions, errors = resource_records(QUERY, subscription_ids, runner, progress)
    inventory = normalize_resources(records, subscriptions)
    inventory.errors = errors
    if not records:
        raise RuntimeError("Azure inventory returned no resources. " + "; ".join(errors))
    return inventory
