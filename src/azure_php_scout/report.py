"""Render scan results as a standalone, offline HTML report (standard library only)."""
from collections import Counter
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from string import Template
import tempfile
from urllib.parse import urlsplit
from .advisories import assess, enrich, catalog

CONTROL_ESCAPES = {code: "\\x{:02x}".format(code) for code in range(32) if code not in (9, 10, 13)}
RESOURCE_LABELS = {"vm": "Virtual machine", "appservice": "App Service", "staticwebapp": "Static Web App", "target": "Manual target"}


def clean_text(value):
    """Keep binary protocol errors readable and compatible with CSV/HTML parsers."""
    return str(value if value is not None else "").translate(CONTROL_ESCAPES)


def csv_cell(value):
    if isinstance(value, str):
        value = clean_text(value)
        if value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
            return "'" + value
    return value


def text(value):
    return escape(clean_text(value), quote=True)


def endpoint_key(row):
    return tuple(str(row.get(key, "")) for key in ("target", "hostname", "port"))


def safe_link(url, label=None):
    """CSV imports and scanned content must never become executable HTML or URLs."""
    url = str(url or "")
    try:
        parts = urlsplit(url)
        valid = (parts.scheme in ("http", "https") and parts.hostname
                 and parts.username is None and parts.password is None
                 and not any(ord(char) < 32 for char in url))
    except ValueError:
        valid = False
    label = text(label or url or "—")
    return ('<a href="{}" target="_blank" rel="noopener noreferrer">{}</a>'.format(text(url), label)
            if valid else label)


def badge(state, version=""):
    state = state if state in ("yes", "probable") else "unknown"
    label = {"yes": "Detected", "probable": "Probable", "unknown": "Unknown"}[state]
    return '<span class="badge {}">{}</span>{}'.format(
        state, label, '<span class="version">{}</span>'.format(text(version)) if version else "")


def result_row(row):
    assessment = assess(row)
    customer = row.get("subscription") or "Unassigned"
    asset = row.get("vm") or row.get("app") or row.get("hostname") or row.get("target") or "—"
    resource_type = row.get("resourceType") or ("vm" if row.get("vm") else "appservice" if row.get("app") else "target")
    php = row.get("php") if row.get("php") in ("yes", "probable") else "unknown"
    wp = row.get("wordpress") if row.get("wordpress") in ("yes", "probable") else "unknown"
    reachable = "yes" if row.get("reachable") == "yes" else "no"
    rank = 0 if "yes" in (php, wp) else 1 if "probable" in (php, wp) else 2 if reachable == "yes" else 3
    details = []
    for label, key in (("Page title", "title"), ("Server", "server"), ("Resource group", "resourceGroup"),
                       ("OS", "os"), ("Inventory state", "powerState"), ("App state", "state"),
                       ("Configured runtime", "configuredRuntime"), ("Configured PHP", "configuredPhpVersion"),
                       ("Inventory note", "inventoryNote"), ("Requests", "requests"), ("Resource ID", "resourceId"),
                       ("Public network access", "publicNetworkAccess"), ("TCP open", "tcpOpen"), ("Protocol", "service"), ("VM resource ID", "vmId")):
        if row.get(key) not in (None, ""):
            details.append('<dt>{}</dt><dd>{}</dd>'.format(label, text(row[key])))
    details.append('<dt>Initial URL</dt><dd>{}</dd>'.format(safe_link(row.get("url"))))
    if row.get("finalUrl"):
        details.append('<dt>Final URL</dt><dd>{}</dd>'.format(safe_link(row["finalUrl"])))
    evidence = row.get("evidence") or "No PHP or WordPress signature found."
    note = '<h4>Notes</h4><p>{}</p>'.format(text(row["note"])) if row.get("note") else ""
    http = '<span class="http-code">{}</span><small>Responded</small>'.format(text(row.get("httpStatus") or "—"))
    if reachable == "no":
        http = '<span class="offline">{}</span>'.format("Open TCP / no HTTP" if row.get("tcpOpen") == "yes" else "No response")
    endpoint = row.get("finalUrl") or row.get("url")
    label = row.get("hostname") or row.get("target") or "—"
    return '''<tr class="result" data-customer="{customer}" data-php="{php}" data-wp="{wp}"
 data-reachable="{reachable}" data-rank="{rank}" data-target="{target}" data-port="{port}" data-resource="{resource_type}">
 <td><strong>{customer}</strong><small>{asset}</small><small>{resource_label}</small></td>
 <td class="endpoint">{link}<small>{target} · port {port}</small></td>
 <td>{http}</td><td>{php_badge}</td><td>{wp_badge}</td><td>{risk}</td>
 <td><details><summary>View details</summary><div class="detail-content"><dl>{details}</dl>
 <h4>Detection evidence</h4><p>{evidence}</p><h4>Version assessment</h4><p>{basis}</p>
 <h4>Recommended action</h4><p>{remediation}</p>{advisories}{note}</div></details></td></tr>'''.format(
        customer=text(customer), asset=text(asset), php=php, wp=wp, reachable=reachable,
        rank=rank, target=text(row.get("target")), port=text(row.get("port")),
        link=safe_link(endpoint, label), http=http, php_badge=badge(php, row.get("phpVersion")),
        wp_badge=badge(wp, row.get("wordpressVersion")), details="".join(details),
        evidence=text(evidence), note=note, resource_type=text(resource_type),
        resource_label=text(RESOURCE_LABELS.get(resource_type, resource_type)),
        risk='<span class="risk {}">{}</span>'.format(text(assessment["riskLevel"]), text(assessment["assessment"].replace("_", " "))),
        basis=text(assessment["assessmentBasis"]), remediation=text(assessment["remediation"]),
        advisories="".join('<p>{}</p>'.format(safe_link(item["url"], item["id"])) for item in assessment["matches"]))


def coverage_html(scope):
    if not scope:
        return ""
    items = []
    counts = scope.get("resources", {})
    items.append('<p><strong>Inventory:</strong> {} · {} subscriptions · {} VMs · {} App Services/slots · {} Static Web Apps</p>'.format(
        text(scope.get("source", "Saved inventory")), text(scope.get("subscriptions", "—")),
        text(counts.get("vm", "—")), text(counts.get("appservice", "—")), text(counts.get("staticwebapp", "—"))))
    items.append('<p><strong>Scan scope:</strong> {} · {} VM IPs · managed web ports {}{}</p>'.format(
        text(scope.get("vmPortScope", "—")), text(scope.get("vmAddresses", "—")),
        text(", ".join(map(str, scope.get("appPorts", [])))), " · running resources only" if scope.get("runningOnly") else ""))
    tcp = scope.get("tcp") or {}
    if tcp:
        items.append('<p><strong>TCP discovery:</strong> {:,} / {:,} completed · {:,} open · {:,} refused · {:,} filtered/timed out · {:,} errors</p>'.format(
            tcp.get("checked", 0), tcp.get("total", 0), tcp.get("open", 0), tcp.get("closed", 0), tcp.get("timedOut", 0), tcp.get("errors", 0)))
    else:
        items.append('<p>TCP discovery has not completed any checks in this report snapshot.</p>')
    errors = scope.get("errors") or []
    if errors:
        items.append('<div class="coverage-warning"><strong>Incomplete coverage — {} issue(s)</strong><ul>{}</ul></div>'.format(
            len(errors), "".join('<li>{}</li>'.format(text(error)) for error in errors)))
    skipped = scope.get("skipped") or []
    if skipped:
        items.append('<details class="coverage-details"><summary>{} resources without a scannable public endpoint</summary><ul>{}</ul></details>'.format(
            len(skipped), "".join('<li><strong>{} / {}</strong> — {}</li>'.format(text(item.get("subscription", "")),
                text(item.get("vm") or item.get("app") or item.get("resourceId", "")), text(item.get("reason", ""))) for item in skipped)))
    items.append('<p class="count">Only TCP connections that open are tested for HTTP/HTTPS during VM discovery. A timeout does not prove a port is closed. Private/NAT-only VMs need a reachable address or an internal scan location.</p>')
    return '<section class="coverage" aria-label="Inventory and port coverage"><h2>Inventory &amp; scan coverage</h2>{}</section>'.format("".join(items))


def write_html_report(path, rows, *, status="complete", expected=None, scope=None):
    """Atomically replace the report, preserving the previous snapshot on write failure."""
    rows = [enrich(row) for row in rows]
    unique = {endpoint_key(row): row for row in rows}
    total = len(unique)
    expected = total if expected is None else expected
    responded = sum(row.get("reachable") == "yes" for row in unique.values())
    php = Counter(row.get("php") for row in unique.values())
    wp = Counter(row.get("wordpress") for row in unique.values())
    customers = sorted({row.get("subscription") or "Unassigned" for row in rows}, key=str.casefold)
    labels = {"complete": "Scan complete", "imported": "Imported CSV results",
              "running": "Scan in progress", "interrupted": "Scan interrupted", "failed": "Scan incomplete"}
    if status not in labels:
        raise ValueError("invalid report status")
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    values = dict(
        status=status, status_label=labels[status], timestamp=text(timestamp),
        total=total, expected=expected, responded=responded, unavailable=total - responded,
        php_count=php["yes"] + php["probable"], php_yes=php["yes"], php_probable=php["probable"],
        wp_count=wp["yes"] + wp["probable"], wp_yes=wp["yes"], wp_probable=wp["probable"],
        row_count=len(rows),
        progress=round(100 * total / expected) if expected else 0,
        customer_options="".join('<option value="{0}">{0}</option>'.format(text(customer)) for customer in customers),
        rows="\n".join(result_row(row) for row in sorted(rows, key=lambda row: (
            0 if row.get("wordpress") == "yes" or row.get("php") == "yes" else
            1 if row.get("wordpress") == "probable" or row.get("php") == "probable" else
            2 if row.get("reachable") == "yes" else 3,
            str(row.get("subscription", "")).casefold(), endpoint_key(row)))),
        empty_hidden=" hidden" if rows else "",
        coverage=coverage_html(scope),
        potential_count=sum(row.get("assessment") == "potentially_affected" for row in unique.values()),
        advisory_date=text(catalog()["reviewed_at"]),
    )
    template = Template(Path(__file__).with_name("report-template.html").read_text(encoding="utf-8"))
    html = template.substitute(values)
    path = Path(path)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix="." + path.name, suffix=".tmp", delete=False) as output:
            temporary_path = Path(output.name)
            output.write(html)
        temporary_path.replace(path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
