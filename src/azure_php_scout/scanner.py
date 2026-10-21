#!/usr/bin/env python3
"""Fingerprint PHP/WordPress using public HTTP responses. Python 3.9+, no dependencies.

Run --help for options; see README.md for detection semantics and CSV examples.
"""
import argparse
import concurrent.futures as cf
import csv
from dataclasses import dataclass, field
from html.parser import HTMLParser
import http.client
import ipaddress
import json
from pathlib import Path
import queue
import re
import ssl
import sys
import threading
import time
from urllib.parse import quote, urljoin, urlsplit, urlunsplit
import zlib

from .report import clean_text, csv_cell, write_html_report
from .inventory import discover_azure
from .discovery import WEB_PORTS, TLS_PORTS, discover_open_ports
from .advisories import ASSESSMENT_FIELDS, enrich

MAX_BODY = 300_000
UA = "Azure-PHP-Scout/0.1.0"
REDIRECTS = {301, 302, 303, 307, 308}
META_FIELDS = ["subscription", "resourceGroup", "vm", "os", "powerState", "vmId",
               "app", "state", "kind", "configuredRuntime", "configuredPhpVersion",
               "inventoryNote", "resourceType", "resourceId", "subscriptionId", "publicNetworkAccess"]
FIELDS = META_FIELDS + ["target", "hostname", "port", "url", "finalUrl", "reachable",
                        "httpStatus", "server", "title", "php", "phpVersion",
                        "wordpress", "wordpressVersion", "evidence", "requests", "note", "tcpOpen", "service", "phpVersions"] + ASSESSMENT_FIELDS


def hostname(value):
    """Validate an IP or DNS name, without accepting URLs or header injection."""
    value = value.strip().rstrip(".")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    value = value.encode("idna").decode("ascii").lower()
    if len(value) > 253 or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in value.split(".")
    ):
        raise ValueError("invalid IP/hostname: {!r}".format(value))
    return value


def authority(host, port, tls):
    host = "[{}]".format(host) if ":" in host else host
    return host if port == (443 if tls else 80) else "{}:{}".format(host, port)


def make_url(host, port, tls, path="/"):
    return "{}://{}{}".format("https" if tls else "http", authority(host, port, tls), path)


@dataclass
class Target:
    address: str
    host: str
    metadata: list = field(default_factory=list)


def target_type(target):
    kinds = {row.get("resourceType") for row in target.metadata}
    if "vm" in kinds or any(row.get("vm") for row in target.metadata):
        return "vm"
    if "staticwebapp" in kinds:
        return "staticwebapp"
    if "appservice" in kinds or any(row.get("app") for row in target.metadata):
        return "appservice"
    try:
        ipaddress.ip_address(target.address)
        return "vm"
    except ValueError:
        return "target"


@dataclass
class Response:
    url: str
    status: int
    headers: dict
    body: str

    def header(self, name):
        return " ".join(self.headers.get(name.lower(), []))


@dataclass
class Fetch:
    responses: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    @property
    def last(self):
        return self.responses[-1] if self.responses else None


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to the inventory address, but use the site's hostname for TLS SNI."""
    def __init__(self, address, port, server_name, **kwargs):
        super().__init__(address, port, **kwargs)
        self.server_name = server_name

    def connect(self):
        http.client.HTTPConnection.connect(self)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.server_name)


class Client:
    def __init__(self, target, options, stop):
        self.target = target
        self.options = options
        self.stop = stop
        self.requests = 0
        self.context = ssl.create_default_context()
        if not options.verify_tls:
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def get(self, url):
        parts = urlsplit(url)
        tls = parts.scheme == "https"
        port = parts.port or (443 if tls else 80)
        host = hostname(parts.hostname or "")
        conn = (PinnedHTTPSConnection(self.target.address, port, server_name=host,
                                     timeout=self.options.timeout, context=self.context)
                if tls else http.client.HTTPConnection(self.target.address, port,
                                                       timeout=self.options.timeout))
        self.requests += 1
        try:
            path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
            path = quote(path, safe="/%?=&:+,;@!$'()*[]~-._")
            conn.request("GET", path, headers={"User-Agent": UA, "Host": authority(host, port, tls),
                                              "Accept": "*/*", "Accept-Encoding": "identity",
                                              "Connection": "close"})
            response = conn.getresponse()
            headers = {}
            for key, value in response.getheaders():
                headers.setdefault(key.lower(), []).append(value)
            chunks, size = [], 0
            deadline = time.monotonic() + self.options.timeout
            # Redirect bodies aren't used; don't wait for an unbounded redirect body.
            while response.status not in REDIRECTS and size < MAX_BODY:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if conn.sock:
                    conn.sock.settimeout(remaining)
                try:
                    chunk = response.read1(min(64_000, MAX_BODY - size))
                except (OSError, http.client.HTTPException):
                    break  # Retain headers and any body already received.
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            raw = b"".join(chunks)
            encoding = response.getheader("Content-Encoding", "").lower()
            if encoding in ("gzip", "deflate"):
                try:
                    raw = zlib.decompressobj(31 if encoding == "gzip" else 15).decompress(raw, MAX_BODY)
                except zlib.error:
                    raw = b""
            try:
                body = raw.decode(response.headers.get_content_charset() or "utf-8", "replace")
            except LookupError:
                body = raw.decode("utf-8", "replace")
            return Response(url, response.status, headers, body)
        finally:
            conn.close()

    def fetch(self, url):
        result = Fetch()
        visited = set()
        for _ in range(self.options.max_redirects + 1):
            if self.stop.is_set():
                result.notes.append("scan interrupted")
                break
            if url in visited:
                result.notes.append("redirect loop")
                break
            visited.add(url)
            try:
                parts = urlsplit(url)
                if parts.scheme not in ("http", "https") or parts.username is not None or parts.password is not None:
                    raise ValueError("unsupported redirect URL")
                host = hostname(parts.hostname or "")
                port = parts.port or (443 if parts.scheme == "https" else 80)
                allowed = self.options.ports
                if allowed is None:
                    allowed = self.options.vm_ports if target_type(self.target) == "vm" else self.options.app_ports
                if port not in allowed:
                    raise ValueError("redirect port {} is outside --ports".format(port))
                # DNS names use Host/SNI on the original address, without resolving them.
                try:
                    literal = ipaddress.ip_address(host)
                except ValueError:
                    literal = None
                if literal is not None and host != self.target.address:
                    raise ValueError("redirect to a different IP was not followed")
                response = self.get(url)
            except (OSError, http.client.HTTPException, ValueError) as exc:
                result.notes.append("{}: {}".format(type(exc).__name__, str(exc)[:180]))
                break
            result.responses.append(response)
            if response.status not in REDIRECTS or not response.header("location"):
                break
            try:
                url = urljoin(url, response.header("location"))
            except ValueError as exc:
                result.notes.append("invalid redirect: {}".format(exc))
                break
        else:
            result.notes.append("redirect limit reached")
        return result


class Page(HTMLParser):
    def __init__(self, body):
        super().__init__(convert_charrefs=True)
        self.generators, self.links, self.api_links = [], [], []
        self.inputs, self.forms, self.title_parts = set(), [], []
        self.in_title = False
        try:
            self.feed(body)
        except (AssertionError, ValueError, NotImplementedError):
            pass  # Malformed public HTML must not abort the inventory scan.

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "meta" and (attrs.get("name") or "").lower() == "generator":
            self.generators.append(attrs.get("content") or "")
        if tag == "link" and attrs.get("rel") == "https://api.w.org/":
            self.api_links.append(attrs.get("href") or "")
        for key in ("src", "href", "action"):
            if attrs.get(key):
                self.links.append(attrs[key])
        if tag == "input":
            self.inputs.add(attrs.get("name"))
        if tag == "form":
            self.forms.append(attrs.get("action") or "")
        if tag == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data)

    @property
    def title(self):
        return " ".join("".join(self.title_parts).split())[:200]


def local_link(base, link):
    """Return a same-host HTTP URL, ignoring external asset URLs."""
    try:
        url = urljoin(base, link)
        parts = urlsplit(url)
        if parts.scheme in ("http", "https") and parts.hostname == urlsplit(base).hostname:
            return url
    except ValueError:
        pass
    return None


class Findings:
    def __init__(self):
        self.php = self.wordpress = "unknown"
        self.php_version = self.wp_version = ""
        self.php_versions = set()
        self.evidence = []

    def mark(self, kind, state, reason, response):
        ranks = {"unknown": 0, "probable": 1, "yes": 2}
        if ranks[state] > ranks[getattr(self, kind)]:
            setattr(self, kind, state)
        evidence = "{} [{}] {}: {}".format(kind, state, response.url, reason)
        if evidence not in self.evidence:
            self.evidence.append(evidence)

    def inspect(self, response, probe=False):
        previous_evidence = len(self.evidence)
        page = Page(response.body)
        powered = response.header("x-powered-by") + " " + response.header("server")
        match = re.search(r"\bPHP(?:/([\d]+(?:\.[\d]+){0,3}[\w.+-]*))?\b", powered, re.I)
        if match:
            self.mark("php", "yes", "PHP reported in HTTP headers", response)
            self.php_version = self.php_version or match.group(1) or ""
            self.php_versions.update(item.group(1) for item in re.finditer(
                r"\bPHP/([\d]+(?:\.[\d]+){0,3}[\w.+-]*)", powered, re.I))
        cookies = response.headers.get("set-cookie", [])
        if any(re.match(r"\s*PHPSESSID=", value, re.I) for value in cookies):
            self.mark("php", "probable", "PHPSESSID cookie", response)
        if any(re.match(r"\s*wordpress_(?:logged_in_|sec_|test_cookie=|[a-f0-9]{32}=)", value, re.I)
               for value in cookies):
            self.mark("wordpress", "yes", "WordPress cookie name", response)
        if response.header("x-redirect-by").strip().lower() == "wordpress":
            self.mark("wordpress", "yes", "X-Redirect-By: WordPress", response)
        api_header = re.search(r'<([^>]+)>\s*;\s*rel=[\"\']?https://api\.w\.org/[\"\']?',
                               response.header("link"), re.I)
        api_links = list(page.api_links)
        if api_header:
            api_links.append(api_header.group(1))
        if any(local_link(response.url, link) for link in api_links):
            self.mark("wordpress", "yes", "WordPress REST API discovery link", response)
        if 200 <= response.status < 300:
            for generator in page.generators:
                match = re.fullmatch(r"WordPress(?:\s+([\d]+(?:\.[\d]+){0,3}[\w.+-]*))?", generator.strip(), re.I)
                if match:
                    self.mark("wordpress", "yes", "WordPress generator meta tag", response)
                    self.wp_version = self.wp_version or match.group(1) or ""
            paths = []
            for link in page.links:
                url = local_link(response.url, link)
                if url:
                    paths.append(urlsplit(url).path.lower())
            if any(re.search(r"/(?:wp-content|wp-includes)/", path) for path in paths):
                self.mark("wordpress", "probable", "local wp-content/wp-includes reference", response)
            if not probe and (any(path.endswith(".php") for path in paths)
                              or urlsplit(response.url).path.lower().endswith(".php")):
                self.mark("php", "probable", "PHP extension in page URL or local link", response)
            if {"log", "pwd", "wp-submit"}.issubset(page.inputs) and any(
                (local_link(response.url, action) or "").split("?")[0].endswith("/wp-login.php")
                for action in page.forms
            ):
                self.mark("wordpress", "yes", "WordPress login form fields and action", response)
            try:
                data = json.loads(response.body)
            except (ValueError, RecursionError):
                data = None
            if (isinstance(data, dict) and isinstance(data.get("namespaces"), list)
                    and "wp/v2" in data["namespaces"] and isinstance(data.get("routes"), dict)):
                self.mark("wordpress", "yes", "WordPress REST index (wp/v2 and routes)", response)
        if any(item.startswith("wordpress [") for item in self.evidence[previous_evidence:]):
            self.mark("php", "probable", "inferred from WordPress; PHP runtime not confirmed", response)
        return page


def probe_urls(response, page):
    parts = urlsplit(response.url)
    base_path = parts.path.rsplit("/", 1)[0] + "/"
    # A site under /blog can have a home page at /: use local WP asset paths as a hint.
    for link in page.links:
        url = local_link(response.url, link)
        match = re.search(r"^(.*?/)(?:wp-content|wp-includes)/", urlsplit(url).path) if url else None
        if match:
            base_path = match.group(1)
            break
    base = urlunsplit((parts.scheme, parts.netloc, base_path, "", ""))
    return [urljoin(base, "wp-json/"), base + "?rest_route=/", urljoin(base, "wp-login.php")]


def scan(target, port, options, stop, tcp_open=False):
    client = Client(target, options, stop)
    url = make_url(target.host, port, port in options.tls_ports)
    result = client.fetch(url)
    if not result.responses and not stop.is_set():
        fallback_url = make_url(target.host, port, port not in options.tls_ports)
        fallback = client.fetch(fallback_url)
        if fallback.responses:
            result, url = fallback, fallback_url
        else:
            result.notes.extend(fallback.notes)
    findings = Findings()
    page = None
    for response in result.responses:
        page = findings.inspect(response)
    root = result.last
    if root and not options.no_probes and findings.wordpress != "yes":
        for probe_url in probe_urls(root, page):
            if stop.is_set():
                break
            probe = client.fetch(probe_url)
            for response in probe.responses:
                findings.inspect(response, probe=True)
            if probe.notes:
                result.notes.append("probe {}: {}".format(probe_url, "; ".join(probe.notes)))
            if findings.wordpress == "yes":
                break
    row = {"target": target.address, "hostname": target.host, "port": port, "url": url,
           "finalUrl": root.url if root else "", "reachable": "yes" if root else "no",
           "httpStatus": root.status if root else "", "server": root.header("server") if root else "",
           "title": page.title if page else "", "php": findings.php, "phpVersion": findings.php_version,
           "wordpress": findings.wordpress, "wordpressVersion": findings.wp_version,
           "evidence": "; ".join(findings.evidence), "requests": client.requests,
           "note": "; ".join(dict.fromkeys(result.notes)),
           "tcpOpen": "yes" if tcp_open or root else "unknown",
           "service": urlsplit(root.url).scheme if root else "unidentified TCP" if tcp_open else "unknown",
           "phpVersions": ",".join(sorted(findings.php_versions))}
    if root and urlsplit(root.url).hostname != target.host:
        row["note"] += ("; " if row["note"] else "") + "redirect hostname tested on original target address"
    return row


def load_targets(options, extra_rows=None):
    targets = {}

    def add(address, host, metadata):
        address, host = hostname(address), hostname(options.host or host or address)
        key = (address, host)
        if key not in targets:
            targets[key] = Target(address, host)
        if metadata not in targets[key].metadata:
            targets[key].metadata.append(metadata)

    for address in options.ip:
        add(str(ipaddress.ip_address(address)), options.host, {})
    for host in options.hostname:
        add(host, host, {})
    paths = options.input or []
    def consume(records, path):
        for line, row in enumerate(records, 2):
            if options.running_only:
                state = row.get("powerState") or row.get("state") or ""
                static = row.get("resourceType") == "staticwebapp"
                if state.lower() not in ("running", "powerstate/running") and not (
                    static and state.lower() in ("", "ready", "succeeded")
                ):
                    continue
            metadata = {name: row.get(name) or "" for name in META_FIELDS}
            metadata.update(configuredRuntime=row.get("runtime") or "",
                            configuredPhpVersion=row.get("phpVersion") or "",
                            inventoryNote=row.get("note") or "")
            if not metadata["resourceType"]:
                metadata["resourceType"] = ("vm" if row.get("vm") or row.get("publicIp") else
                                            "staticwebapp" if "azurestaticapps.net" in (row.get("hostname") or "")
                                            or "azurestaticwebsites.net" in (row.get("hostname") or "") else
                                            "appservice" if row.get("app") else "target")
            host = (row.get("hostname") or "").strip()
            addresses = re.split(r"[\s,;]+", (row.get("publicIp") or row.get("ip") or "").strip())
            try:
                if any(addresses):
                    for address in filter(None, addresses):
                        add(str(ipaddress.ip_address(address)), host, metadata)
                elif host:
                    add(host, host, metadata)
            except ValueError as exc:
                raise ValueError("{}:{}: {}".format(path, line, exc)) from exc
    for path in paths:
        with open(path, newline="", encoding="utf-8-sig") as source:
            reader = csv.DictReader(source)
            if not set(reader.fieldnames or []).intersection({"publicIp", "ip", "hostname"}):
                raise ValueError("{}: CSV needs publicIp, ip, or hostname column".format(path))
            consume(reader, path)
    if extra_rows is not None:
        consume(extra_rows, "Azure inventory")
    return list(targets.values()), paths


def parse_ports(value):
    try:
        if value.lower() == "all":
            return list(range(1, 65536))
        if value.lower() == "web":
            return list(WEB_PORTS)
        ports = []
        for item in value.split(","):
            if "-" in item:
                start, end = map(int, item.strip().split("-"))
                if not 1 <= start <= end <= 65535:
                    raise ValueError
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(item.strip()))
        ports = list(dict.fromkeys(ports))
        if not ports or any(port < 1 or port > 65535 for port in ports):
            raise ValueError
        return ports
    except ValueError:
        raise argparse.ArgumentTypeError("use web, all, or ports/ranges between 1 and 65535 (e.g. 80,443,8000-9000)")


def positive_int(value):
    try:
        number = int(value)
        if number > 0:
            return number
    except ValueError:
        pass
    raise argparse.ArgumentTypeError("must be a positive integer")


def timeout_value(value):
    try:
        number = float(value)
        if 0 < number <= 300:
            return number
    except ValueError:
        pass
    raise argparse.ArgumentTypeError("must be a number greater than 0 and at most 300")


def validate_output_paths(sources, outputs):
    sources = {Path(path).resolve() for path in sources}
    outputs = [Path(path).resolve() for path in outputs]
    if len(set(outputs)) != len(outputs):
        raise ValueError("CSV and HTML outputs must use different files")
    if sources.intersection(outputs):
        raise ValueError("outputs must differ from the input CSV")


def convert_report(options):
    if options.no_html:
        raise ValueError("--report-from requires HTML output")
    if options.input or options.ip or options.hostname or options.azure:
        raise ValueError("--report-from cannot be combined with scan targets")
    path = options.html_output or str(Path(options.report_from).with_suffix(".html"))
    validate_output_paths([options.report_from], [path])
    with open(options.report_from, newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(clean_text(line) for line in source)
        required = {"target", "port", "reachable", "php", "wordpress"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError("--report-from needs a scanner results CSV, not an inventory CSV")
        rows = list(reader)
    if options.dry_run:
        print("{} result rows validated; no report written".format(len(rows)), file=sys.stderr)
    else:
        coverage = Path(options.report_from).with_suffix(".coverage.json")
        scope = json.loads(coverage.read_text(encoding="utf-8")) if coverage.exists() else None
        write_html_report(path, rows, status="imported", scope=scope)
        print("HTML report: {} ({} result rows)".format(path, len(rows)), file=sys.stderr)
    return 0


def save_json(path, value):
    path = Path(path)
    temporary = path.with_name("." + path.name + ".tmp")
    try:
        temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def cache_inventory(inventory):
    fields = sorted({key for row in inventory.rows for key in row} or set(META_FIELDS + ["publicIp", "hostname"]))
    destination = Path("azure-web-inventory.csv")
    temporary = destination.with_suffix(".csv.tmp")
    try:
        with temporary.open("w", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=fields)
            writer.writeheader()
            writer.writerows({key: csv_cell(value) for key, value in row.items()} for row in inventory.rows)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    save_json("azure-inventory-coverage.json", dict(subscriptions=inventory.subscriptions,
              resources=inventory.resources, skipped=inventory.skipped, errors=inventory.errors))


def execute_scan(targets, options, scope, html_path):
    stop = threading.Event()
    events = queue.Queue()
    slots = threading.BoundedSemaphore(options.workers * 2)
    pool = cf.ThreadPoolExecutor(max_workers=options.workers)
    scheduled = [0]
    rows = []
    by_address = {}
    direct = []
    for target in targets:
        if options.ports is None and target_type(target) == "vm":
            by_address.setdefault(target.address, []).append(target)
        else:
            direct.append(target)
    scope.update(vmPortScope=options.vm_ports_label if options.ports is None else "Explicit ports (no TCP sweep)",
                 vmPortsPerAddress=len(options.vm_ports) if options.ports is None else len(options.ports),
                 appPorts=list(options.ports or options.app_ports),
                 selectedTargets=len(targets), vmAddresses=len(by_address),
                 runningOnly=options.running_only, tcp={}, source=scope.get("source", "CSV / explicit targets"))
    scope["vmTargets"] = [{"address": address, "assets": sorted({metadata.get("vm") or address
                          for target in group for metadata in (target.metadata or [{}])})}
                          for address, group in by_address.items()]

    def enqueue(target, port, tcp_open):
        while not stop.is_set():
            if slots.acquire(timeout=0.2):
                scheduled[0] += 1
                events.put(("endpoint", (target, port, tcp_open)))
                return

    def produce():
        try:
            for target in direct:
                for port in (options.ports or options.app_ports):
                    if stop.is_set():
                        break
                    enqueue(target, port, False)
            if by_address and not stop.is_set():
                for address, port in discover_open_ports(by_address, options.vm_ports,
                    workers=options.port_workers, timeout=options.port_timeout, rate=options.port_rate,
                    stop=stop, progress=lambda stats: events.put(("progress", stats))):
                    for target in by_address[address]:
                        enqueue(target, port, True)
        except Exception as exc:
            events.put(("error", str(exc)))
        finally:
            events.put(("finished", None))

    completed = responded = php = wordpress = 0
    active, finished = 0, False
    report_status, exit_code = "running", 0
    last_report, last_progress = 0, 0
    producer = threading.Thread(target=produce, name="port-discovery", daemon=True)

    def publish():
        scope.update(scanStatus=report_status, scheduled=scheduled[0], httpChecked=completed)
        save_json(Path(options.output).with_suffix(".coverage.json"), scope)
        if html_path:
            write_html_report(html_path, rows, status=report_status, expected=scheduled[0], scope=scope)

    try:
        publish()
        with open(options.output, "w", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=FIELDS)
            writer.writeheader()
            output.flush()
            producer.start()
            while not finished or active:
                try:
                    event, payload = events.get(timeout=0.5)
                except queue.Empty:
                    event, payload = "idle", None
                if event == "endpoint":
                    target, port, tcp_open = payload
                    future = pool.submit(scan, target, port, options, stop, tcp_open)
                    future.add_done_callback(lambda result, target=target: events.put(("result", (result, target))))
                    active += 1
                elif event == "result":
                    future, target = payload
                    slots.release()
                    active -= 1
                    row = future.result()
                    for metadata in target.metadata:
                        result = {key: clean_text(value) if isinstance(value, str) else value
                                  for key, value in dict(metadata, **row).items()}
                        result["resourceType"] = result.get("resourceType") or target_type(target)
                        result = enrich(result)
                        writer.writerow({key: csv_cell(value) for key, value in result.items()})
                        rows.append(result)
                    output.flush()
                    completed += 1
                    responded += row["reachable"] == "yes"
                    php += row["php"] != "unknown"
                    wordpress += row["wordpress"] != "unknown"
                    print("[HTTP {}] {}:{} HTTP={} PHP={} WordPress={}".format(
                          completed, row["target"], row["port"], row["httpStatus"] or "-",
                          row["php"], row["wordpress"]), file=sys.stderr)
                elif event == "progress":
                    scope["tcp"] = payload
                    if time.monotonic() - last_progress >= 10 or payload["checked"] == payload["total"]:
                        print("[TCP] {}/{} checked; {} open; {} timed out".format(
                              payload["checked"], payload["total"], payload["open"], payload["timedOut"]), file=sys.stderr)
                        last_progress = time.monotonic()
                elif event == "error":
                    scope.setdefault("errors", []).append("Port discovery: " + payload)
                elif event == "finished":
                    finished = True
                if time.monotonic() - last_report >= 5:
                    publish()
                    last_report = time.monotonic()
            report_status = "failed" if scope.get("errors") else "complete"
            exit_code = 1 if scope.get("errors") else 0
    except KeyboardInterrupt:
        report_status, exit_code = "interrupted", 130
        print("Interrupted; completed results preserved.", file=sys.stderr)
    except (OSError, ValueError) as exc:
        report_status, exit_code = "failed", 1
        scope.setdefault("errors", []).append(str(exc))
        print("Scan failed: {}".format(exc), file=sys.stderr)
    finally:
        stop.set()
        if producer.ident is not None:
            producer.join()
        pool.shutdown(wait=True, cancel_futures=True)
        if report_status == "running":
            report_status = "failed"
        try:
            publish()
        except OSError as exc:
            print("Cannot save report: {}".format(exc), file=sys.stderr)
            exit_code = exit_code or 1
    print("{}: {} HTTP checks, {} responses, {} PHP signals, {} WordPress signals. HTML: {}".format(
          report_status, completed, responded, php, wordpress, html_path or "disabled"), file=sys.stderr)
    return exit_code


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-i", "--input", action="append", help="inventory CSV; repeat to combine files (default: latest Azure inventory)")
    parser.add_argument("--azure", action="store_true", help="refresh VM, App Service and Static Web App inventory using Azure CLI")
    parser.add_argument("--subscription", action="append", help="Azure subscription ID to include; repeat (default: all enabled visible subscriptions)")
    parser.add_argument("--inventory-only", action="store_true", help="save fresh Azure inventory without endpoint scans (requires --azure)")
    parser.add_argument("-o", "--output", default="web-scan.csv", help="results CSV (default: web-scan.csv)")
    html_group = parser.add_mutually_exclusive_group()
    html_group.add_argument("--html", "--html-output", dest="html_output",
                            help="HTML report path (default: CSV basename with .html)")
    html_group.add_argument("--no-html", action="store_true", help="write only the CSV results")
    parser.add_argument("--report-from", metavar="RESULTS.csv", help="convert saved scan results to HTML without scanning")
    parser.add_argument("--ip", action="append", default=[], help="single IPv4/IPv6 target; repeat for more")
    parser.add_argument("--hostname", action="append", default=[], help="DNS target; repeat for more")
    parser.add_argument("--host", help="Host header and TLS SNI override, e.g. the website on --ip")
    parser.add_argument("--ports", type=parse_ports, help="explicit ports/ranges for all targets; bypass VM TCP discovery")
    parser.add_argument("--vm-ports", type=parse_ports, default=parse_ports("web"), help="VM TCP discovery: all, web, or ports/ranges (default: common web ports)")
    parser.add_argument("--app-ports", type=parse_ports, default=[80, 443], help="App Service/Static Web App HTTP ports (default: 80,443)")
    parser.add_argument("--port-workers", type=positive_int, default=512, help="maximum concurrent TCP discovery sockets (default: 512)")
    parser.add_argument("--port-timeout", type=timeout_value, default=1, help="TCP connect timeout seconds (default: 1)")
    parser.add_argument("--port-rate", type=positive_int, default=1000, help="maximum new TCP connections per second (default: 1000)")
    parser.add_argument("--tls-ports", type=parse_ports, default=TLS_PORTS, help="ports tried with TLS first; other ports try HTTP then TLS")
    parser.add_argument("--timeout", type=timeout_value, default=8, help="socket/body timeout in seconds (default: 8)")
    parser.add_argument("--workers", type=positive_int, default=10, help="concurrent endpoint scans (default: 10)")
    parser.add_argument("--max-redirects", type=int, choices=range(0, 11), default=5, metavar="0..10")
    parser.add_argument("--running-only", action="store_true", help="include only CSV rows marked running")
    parser.add_argument("--no-probes", action="store_true", help="only request / and follow its redirects")
    parser.add_argument("--verify-tls", action="store_true", help="require a trusted TLS certificate matching the hostname")
    parser.add_argument("--dry-run", action="store_true", help="validate input and show counts without requests or output")
    options = parser.parse_args(argv)
    try:
        if options.report_from:
            return convert_report(options)
        if options.inventory_only and not options.azure:
            raise ValueError("--inventory-only requires --azure")
        if options.subscription and not options.azure:
            raise ValueError("--subscription requires --azure")
        scope = dict(errors=[], skipped=[])
        inventory = None
        if options.azure:
            inventory = discover_azure(options.subscription, progress=lambda message: print(message, file=sys.stderr))
            scope.update(source="Live Azure Resource Graph", subscriptions=inventory.subscriptions,
                         resources=inventory.resources, skipped=inventory.skipped, errors=inventory.errors)
            for error in inventory.errors:
                print("Partial Azure coverage: " + error, file=sys.stderr)
        targets, paths = load_targets(options, inventory.rows if inventory else None)
        if not targets and not inventory:
            raise ValueError("Choose --azure, -i INVENTORY.csv, --ip, or --hostname; the selected input contains no targets")
        html_path = None if options.no_html else options.html_output or str(Path(options.output).with_suffix(".html"))
        validate_output_paths(paths + (["azure-web-inventory.csv", "azure-inventory-coverage.json"] if options.azure else []),
                              [options.output, str(Path(options.output).with_suffix(".coverage.json"))] + ([html_path] if html_path else []))
    except (OSError, ValueError, RuntimeError, csv.Error) as exc:
        parser.error(str(exc))
    options.vm_ports = set(options.vm_ports)
    options.vm_ports_label = ("Full TCP range 1–65535" if len(options.vm_ports) == 65535 else
                             "Common web port profile" if options.vm_ports == set(WEB_PORTS) else
                             "Selected TCP ports: " + ",".join(map(str, sorted(options.vm_ports))))
    vm_addresses = {target.address for target in targets if target_type(target) == "vm"}
    print("{} unique targets; {} VM addresses; VM scope: {}; App ports: {}".format(
          len(targets), len(vm_addresses), options.vm_ports_label if options.ports is None else "explicit ports",
          options.ports or options.app_ports), file=sys.stderr)
    if options.ports is None:
        attempts = len(vm_addresses) * len(options.vm_ports)
        print("TCP discovery: {:,} connection attempts; {} sockets; rate at most {}/second".format(
              attempts, options.port_workers, options.port_rate), file=sys.stderr)
    if options.dry_run:
        return 0
    if inventory:
        cache_inventory(inventory)
    if options.inventory_only:
        print("Inventory saved to azure-web-inventory.csv", file=sys.stderr)
        return 1 if inventory.errors else 0
    return execute_scan(targets, options, scope, html_path)


if __name__ == "__main__":
    sys.exit(main())
