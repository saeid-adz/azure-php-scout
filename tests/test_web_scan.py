"""Regression tests use synthetic pages and local HTTP(S) servers only."""
import contextlib
import csv
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from azure_php_scout import scanner
from azure_php_scout import report as web_report


def options(**overrides):
    values = dict(timeout=1, verify_tls=False, max_redirects=5, ports=[80, 443],
                  tls_ports=[443, 8443], no_probes=False, host=None, ip=[],
                  hostname=[], input=[], running_only=False)
    values.update(overrides)
    return SimpleNamespace(**values)


def response(body="", status=200, headers=None, path="/"):
    return scanner.Response("http://example.test" + path, status, headers or {}, body)


class DetectionTests(unittest.TestCase):
    def inspect(self, **kwargs):
        findings = scanner.Findings()
        findings.inspect(response(**kwargs))
        return findings

    def test_php_header_and_version(self):
        findings = self.inspect(headers={"x-powered-by": ["PHP/8.2.19"]})
        self.assertEqual((findings.php, findings.php_version), ("yes", "8.2.19"))
        self.assertEqual(findings.wordpress, "unknown")

    def test_session_cookie_is_probable_and_value_is_not_exported(self):
        findings = self.inspect(headers={"set-cookie": ["other=1", "PHPSESSID=secret; HttpOnly"]})
        self.assertEqual(findings.php, "probable")
        self.assertNotIn("secret", " ".join(findings.evidence))

    def test_generator_is_wordpress_but_only_infers_php(self):
        findings = self.inspect(body='<meta content="WordPress 6.7.2" name="generator">')
        self.assertEqual((findings.wordpress, findings.wp_version, findings.php),
                         ("yes", "6.7.2", "probable"))
        self.assertEqual(findings.php_version, "")

    def test_remote_assets_and_prose_do_not_identify_local_runtime(self):
        findings = self.inspect(body='<p>WordPress PHP wp-content/wp-includes</p>'
                                '<script src="https://other.test/wp-includes/a.js"></script>')
        self.assertEqual((findings.wordpress, findings.php), ("unknown", "unknown"))

    def test_local_asset_version_is_not_core_version(self):
        findings = self.inspect(body='<link href="/wp-content/plugins/demo/style.css?ver=9.9">')
        self.assertEqual(findings.wordpress, "probable")
        self.assertEqual(findings.wp_version, "")

    def test_error_body_is_not_positive(self):
        findings = self.inspect(status=404, body='<meta name="generator" content="WordPress 1.2">')
        self.assertEqual(findings.wordpress, "unknown")

    def test_rest_index_requires_structure(self):
        findings = self.inspect(body=json.dumps({"namespaces": ["wp/v2"], "routes": {"/": {}}}))
        self.assertEqual(findings.wordpress, "yes")
        self.assertEqual(self.inspect(body='{"namespaces":["wp/v2"]}').wordpress, "unknown")

    def test_rest_discovery_and_redirect_header(self):
        for headers in ({"link": ['<http://example.test/?rest_route=/>; rel="https://api.w.org/"']},
                        {"x-redirect-by": ["WordPress"]}):
            with self.subTest(headers=headers):
                self.assertEqual(self.inspect(headers=headers, status=301).wordpress, "yes")

    def test_malformed_html_does_not_abort_scan(self):
        self.assertEqual(self.inspect(body='<![invalid]><title>broken').php, "unknown")

    def test_probe_status_and_php_extension_are_not_evidence(self):
        findings = scanner.Findings()
        findings.inspect(response(body="Generic fallback page", path="/wp-login.php"), probe=True)
        self.assertEqual((findings.wordpress, findings.php), ("unknown", "unknown"))

    def test_no_inferred_php_evidence_on_unrelated_probe(self):
        findings = scanner.Findings()
        findings.inspect(response(body='<script src="/wp-includes/a.js"></script>'))
        count = len(findings.evidence)
        findings.inspect(response(body="Not found", status=404, path="/wp-json/"), probe=True)
        self.assertEqual(len(findings.evidence), count)


class InputTests(unittest.TestCase):
    def test_multi_ip_duplicates_hostnames_and_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / "input.csv"
            with inventory.open("w", newline="", encoding="utf-8-sig") as file:
                writer = csv.DictWriter(file, fieldnames=["publicIp", "hostname", "vm", "powerState"])
                writer.writeheader()
                writer.writerows([
                    dict(publicIp="192.0.2.1 192.0.2.2", hostname="www.example.test", vm="one", powerState="PowerState/running"),
                    dict(publicIp="192.0.2.1", hostname="www.example.test", vm="two", powerState="PowerState/running"),
                    dict(publicIp="192.0.2.3", vm="off", powerState="PowerState/deallocated"),
                    dict(publicIp="", vm="empty", powerState="PowerState/running")])
            targets, _ = scanner.load_targets(options(input=[str(inventory)], running_only=True))
            self.assertEqual(len(targets), 2)
            self.assertEqual(targets[0].host, "www.example.test")
            self.assertEqual([row["vm"] for row in targets[0].metadata], ["one", "two"])

    def test_platform_php_config_does_not_become_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / "apps.csv"
            inventory.write_text("hostname,phpVersion,runtime\napp.example.test,5.6,PHP|5.6\n")
            targets, _ = scanner.load_targets(options(input=[str(inventory)]))
            self.assertEqual(targets[0].metadata[0]["configuredPhpVersion"], "5.6")
            self.assertNotIn("phpVersion", targets[0].metadata[0])

    def test_single_ip_does_not_load_default_inventory(self):
        targets, paths = scanner.load_targets(options(ip=["2001:db8::1"]))
        self.assertEqual(paths, [])
        self.assertEqual(len(targets), 1)
        self.assertEqual(scanner.make_url(targets[0].host, 8443, True), "https://[2001:db8::1]:8443/")

    def test_invalid_port_timeout_and_host_are_rejected(self):
        for value in ("0", "65536", "80,", "abc"):
            with self.subTest(port=value), self.assertRaises(scanner.argparse.ArgumentTypeError):
                scanner.parse_ports(value)
        for value in ("nan", "inf", "0", "-1"):
            with self.subTest(timeout=value), self.assertRaises(scanner.argparse.ArgumentTypeError):
                scanner.timeout_value(value)
        with self.assertRaises(ValueError):
            scanner.hostname("example.test\r\nX-Header: injected")

    def test_dry_run_does_not_make_requests_or_create_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "results.csv"
            with patch.object(scanner.Client, "get", side_effect=AssertionError("network")):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(scanner.main(["--ip", "192.0.2.1", "--dry-run", "-o", str(output)]), 0)
            self.assertFalse(output.exists())
            self.assertFalse(output.with_suffix(".html").exists())

    def test_cannot_overwrite_input(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / "input.csv"
            content = "publicIp\n192.0.2.1\n"
            inventory.write_text(content)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                scanner.main(["-i", str(inventory), "-o", str(inventory)])
            self.assertEqual(error.exception.code, 2)
            self.assertEqual(inventory.read_text(encoding="utf-8"), content)


class ReportTests(unittest.TestCase):
    def test_untrusted_csv_values_cannot_become_spreadsheet_formulas(self):
        for value in ('=HYPERLINK("https://example.test")', '+1+1', '-1+1', '@SUM(1)', ' \t=1+1'):
            with self.subTest(value=value):
                self.assertTrue(web_report.csv_cell(value).startswith("'"))
        self.assertEqual(web_report.csv_cell('ordinary text'), 'ordinary text')
        self.assertEqual(web_report.csv_cell('AMQP\x00'), r'AMQP\x00')

    def row(self, **overrides):
        row = dict(subscription="Customer A", vm="web01", target="192.0.2.10", hostname="site.example.test",
                   port="443", reachable="yes", httpStatus="200", php="probable", phpVersion="",
                   wordpress="yes", wordpressVersion="6.7.2", url="https://site.example.test/",
                   finalUrl="https://site.example.test/", evidence="WordPress generator", requests="1")
        row.update(overrides)
        return row

    def test_unique_endpoint_summary_and_all_metadata_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.html"
            web_report.write_html_report(report, [self.row(), self.row(subscription="Customer B")], expected=5)
            html = report.read_text(encoding="utf-8")
            self.assertEqual(re.findall(r'<strong>(\d+)</strong>', html)[:4], ["1", "1", "1", "1"])
            self.assertEqual(html.count('<tr class="result"'), 2)
            self.assertIn("Customer A", html)
            self.assertIn("Customer B", html)
            self.assertIn("1 / 5 endpoints", html)

    def test_hostile_scan_values_are_escaped_and_unsafe_links_are_inert(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.html"
            hostile = '</script><script>alert("xss")</script><img src=x onerror=alert(1)>'
            web_report.write_html_report(report, [self.row(title=hostile, evidence=hostile,
                subscription='Bad"><img src=x onerror=alert(1)>', finalUrl="javascript:alert(1)")])
            html = report.read_text(encoding="utf-8")
            self.assertEqual(html.count("<script>"), 1)  # Only the fixed report script.
            self.assertNotIn("<img", html)
            self.assertNotIn('href="javascript:', html)
            self.assertIn("&lt;/script&gt;", html)
            self.assertIn("&lt;img", html)

    def test_empty_and_interrupted_reports_show_completion_state(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.html"
            web_report.write_html_report(report, [], status="interrupted", expected=10)
            html = report.read_text(encoding="utf-8")
            self.assertIn("Scan interrupted", html)
            self.assertIn("0 / 10 endpoints", html)
            self.assertIn('id="empty">', html)

    def test_convert_results_to_html_without_network_or_changing_csv(self):
        with tempfile.TemporaryDirectory() as directory:
            source, report = Path(directory) / "saved.csv", Path(directory) / "custom.html"
            with source.open("w", newline="") as file:
                writer = csv.DictWriter(file, fieldnames=self.row().keys())
                writer.writeheader()
                writer.writerow(self.row())
            original = source.read_bytes()
            with patch.object(scanner.Client, "get", side_effect=AssertionError("network")):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(scanner.main(["--report-from", str(source), "--html", str(report)]), 0)
            self.assertEqual(source.read_bytes(), original)
            self.assertIn("Imported CSV results", report.read_text(encoding="utf-8"))

    def test_import_rejects_inventory_file(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "inventory.csv"
            source.write_text("publicIp,phpVersion\n192.0.2.1,5.6\n")
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                scanner.main(["--report-from", str(source)])
            self.assertEqual(error.exception.code, 2)
            self.assertFalse(source.with_suffix(".html").exists())

    def test_binary_protocol_errors_remain_readable_in_csv_and_html(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "results.csv"
            with patch.object(scanner.Client, "get", side_effect=scanner.http.client.BadStatusLine("AMQP\x00\x01")):
                with contextlib.redirect_stderr(io.StringIO()):
                    code = scanner.main(["--ip", "192.0.2.1", "--ports", "80", "-o", str(source)])
            self.assertEqual(code, 0)
            self.assertNotIn(b"\x00", source.read_bytes())
            with source.open(newline="") as file:
                rows = list(csv.DictReader(file))
            self.assertIn(r"AMQP\x00\x01", rows[0]["note"])
            self.assertIn(r"AMQP\x00\x01", source.with_suffix(".html").read_text(encoding="utf-8"))
            # Older scanner CSVs can also contain these raw protocol bytes.
            source.write_text(source.read_text(encoding="utf-8").replace(r"AMQP\x00\x01", "AMQP\x00\x01"))
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(scanner.main(["--report-from", str(source)]), 0)
            self.assertNotIn("\x00", source.with_suffix(".html").read_text(encoding="utf-8"))

    def test_html_path_cannot_overwrite_inventory_or_csv_output(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "inventory.csv", Path(directory) / "results.csv"
            source.write_text("publicIp\n192.0.2.1\n")
            for destination in (source, output):
                with self.subTest(path=destination), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        scanner.main(["-i", str(source), "-o", str(output), "--html", str(destination)])
                    self.assertEqual(error.exception.code, 2)
            self.assertEqual(source.read_text(encoding="utf-8"), "publicIp\n192.0.2.1\n")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append((self.path, self.headers.get("Host")))
        status, headers, body = self.server.routes.get(self.path, self.server.fallback)
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *_args):
        pass


@contextlib.contextmanager
def local_server(routes, fallback=(404, {}, "Not found"), context=None):
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.routes, server.fallback, server.requests = routes, fallback, []
    if context:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


class NetworkTests(unittest.TestCase):
    def scan(self, server, **overrides):
        settings = options(ports=[server.server_port], **overrides)
        return scanner.scan(scanner.Target("127.0.0.1", "127.0.0.1"), server.server_port,
                            settings, threading.Event())

    def test_rest_fallback_and_subdirectory(self):
        routes = {
            "/": (302, {"Location": "/blog/"}, ""),
            "/blog/": (200, {}, "<title>Example blog</title>"),
            "/blog/?rest_route=/": (200, {"Content-Type": "application/json"},
                                    '{"namespaces":["wp/v2"],"routes":{}}')}
        with local_server(routes) as server:
            row = self.scan(server)
            self.assertEqual((row["wordpress"], row["php"], row["title"]),
                             ("yes", "probable", "Example blog"))
            self.assertTrue(row["finalUrl"].endswith("/blog/"))
            self.assertEqual([path for path, _ in server.requests],
                             ["/", "/blog/", "/blog/wp-json/", "/blog/?rest_route=/"])

    def test_soft_404_all_200_is_not_wordpress_or_php(self):
        with local_server({}, fallback=(200, {}, "<title>Application</title>")) as server:
            row = self.scan(server)
            self.assertEqual((row["php"], row["wordpress"]), ("unknown", "unknown"))
            self.assertEqual(row["requests"], 4)

    def test_login_form_probe(self):
        form = '<form action="/wp-login.php"><input name="log"><input name="pwd"><input name="wp-submit"></form>'
        with local_server({"/": (200, {}, "Home"), "/wp-login.php": (200, {}, form)}) as server:
            self.assertEqual(self.scan(server)["wordpress"], "yes")

    def test_redirect_hostname_uses_original_ip_and_new_host_header(self):
        with local_server({}) as server:
            server.routes = {"/": (302, {"Location": "http://unresolvable.invalid:{}/site/".format(server.server_port)}, ""),
                             "/site/": (200, {"X-Powered-By": "PHP/8.3.1"}, "<title>Virtual host</title>")}
            row = self.scan(server, no_probes=True)
            self.assertEqual(row["php"], "yes")
            self.assertEqual(server.requests[1][1], "unresolvable.invalid:{}".format(server.server_port))
            self.assertIn("original target address", row["note"])

    def test_redirect_loop_is_reported(self):
        with local_server({"/": (302, {"Location": "/"}, "")}) as server:
            row = self.scan(server, no_probes=True)
            self.assertEqual(row["reachable"], "yes")
            self.assertIn("redirect loop", row["note"])
            self.assertEqual(len(server.requests), 1)

    def test_different_ip_or_unselected_port_redirect_is_not_requested(self):
        for location in ("http://192.0.2.99:PORT/", "http://127.0.0.1:1/", "http://[bad/"):
            with self.subTest(location=location), local_server({}) as server:
                server.routes = {"/": (302, {"Location": location.replace("PORT", str(server.server_port))}, "")}
                row = self.scan(server, no_probes=True)
                self.assertEqual(len(server.requests), 1)
                self.assertTrue(row["note"])

    def test_compressed_response_and_body_limit(self):
        body = gzip.compress(b'<meta name="generator" content="WordPress 6.7">' + b"x" * (scanner.MAX_BODY * 3))
        with local_server({"/": (200, {"Content-Encoding": "gzip"}, body)}) as server:
            settings = options(ports=[server.server_port])
            client = scanner.Client(scanner.Target("127.0.0.1", "127.0.0.1"), settings, threading.Event())
            result = client.fetch("http://127.0.0.1:{}/".format(server.server_port))
            self.assertEqual(len(result.last.body), scanner.MAX_BODY)
            self.assertEqual(self.scan(server)["wordpress"], "yes")

    def test_cli_writes_complete_csv_with_inventory_metadata(self):
        with local_server({"/": (200, {"X-Powered-By": "PHP/8.2.9"}, "<title>A, B &amp; C</title>")}) as server:
            with tempfile.TemporaryDirectory() as directory:
                inventory, output = Path(directory) / "input.csv", Path(directory) / "results.csv"
                inventory.write_text('publicIp,vm,subscription\n127.0.0.1,VM1,"Customer, AB"\n')
                with contextlib.redirect_stderr(io.StringIO()):
                    code = scanner.main(["-i", str(inventory), "-o", str(output), "--ports",
                                         str(server.server_port), "--no-probes"])
                with output.open(newline="") as file:
                    rows = list(csv.DictReader(file))
                self.assertEqual(code, 0)
                self.assertEqual(len(rows), 1)
                self.assertEqual((rows[0]["vm"], rows[0]["subscription"], rows[0]["title"]),
                                 ("VM1", "Customer, AB", "A, B & C"))
                self.assertEqual(rows[0]["phpVersion"], "8.2.9")
                html = output.with_suffix(".html").read_text(encoding="utf-8")
                self.assertIn("Scan complete", html)
                self.assertIn("Customer, AB", html)
                self.assertIn("8.2.9", html)
                self.assertIn("A, B &amp; C", html)

    def test_unreachable_endpoint_still_has_output(self):
        with patch.object(scanner.Client, "get", side_effect=ConnectionRefusedError("closed")):
            row = scanner.scan(scanner.Target("192.0.2.1", "192.0.2.1"), 80, options(), threading.Event())
        self.assertEqual((row["reachable"], row["php"], row["wordpress"]), ("no", "unknown", "unknown"))
        self.assertIn("ConnectionRefusedError", row["note"])

    @unittest.skipUnless(shutil.which("openssl"), "openssl needed to generate a local TLS certificate")
    def test_https_host_and_sni_and_certificate_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            key, cert = Path(directory) / "key.pem", Path(directory) / "cert.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-keyout", str(key), "-out", str(cert), "-subj", "/CN=virtual.example.test"],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(cert), str(key))
            seen_sni = []
            context.set_servername_callback(lambda _sock, name, _context: seen_sni.append(name))
            with local_server({"/": (200, {"X-Powered-By": "PHP/8.3.2"}, "Home")}, context=context) as server:
                settings = options(ports=[server.server_port], tls_ports=[server.server_port], no_probes=True)
                target = scanner.Target("127.0.0.1", "virtual.example.test")
                row = scanner.scan(target, server.server_port, settings, threading.Event())
                self.assertEqual(row["phpVersion"], "8.3.2")
                self.assertEqual(seen_sni[0], "virtual.example.test")
                self.assertEqual(server.requests[0][1], "virtual.example.test:{}".format(server.server_port))
                settings.verify_tls = True
                client = scanner.Client(target, settings, threading.Event())
                result = client.fetch(row["url"])
                self.assertIsNone(result.last)
                self.assertIn("SSLCertVerificationError", result.notes[0])


if __name__ == "__main__":
    unittest.main()
