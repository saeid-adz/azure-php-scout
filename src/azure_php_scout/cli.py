"""Command entry point for the service, scanner, and offline assessment."""
import argparse
import csv
import json
import os
from pathlib import Path
import sys

from . import __version__
from .advisories import enrich


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "scan":
        from .scanner import main as scan
        return scan(argv[1:])
    parser = argparse.ArgumentParser(prog="azure-php-scout", description="Discover Azure PHP exposure and review potential advisory impact.")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="run the authenticated local dashboard and API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--data-dir", default=os.environ.get("SCOUT_DATA_DIR", ".scout"))
    token = commands.add_parser("token", help="print the local service token for dashboard sign-in")
    token.add_argument("--data-dir", default=os.environ.get("SCOUT_DATA_DIR", ".scout"))
    assess = commands.add_parser("assess", help="assess saved scanner CSV results without network access")
    assess.add_argument("input")
    assess.add_argument("-o", "--output", default="assessed.csv")
    commands.add_parser("scan", help="discover and scan targets (run scan --help for options)")
    args = parser.parse_args(argv)
    if args.command in ("serve", "token"):
        from .service import create_app, service_token
        if args.command == "token":
            print(service_token(args.data_dir))
            return 0
        if args.host not in ("127.0.0.1", "localhost", "::1") and not os.environ.get("SCOUT_API_TOKEN"):
            parser.error("Set SCOUT_API_TOKEN (32+ characters) before binding outside loopback.")
        if not 1 <= args.port <= 65535:
            parser.error("Port must be between 1 and 65535")
        import uvicorn
        print("Dashboard: http://{}:{} — use 'azure-php-scout token --data-dir {}' to sign in.".format(args.host, args.port, args.data_dir), file=sys.stderr)
        uvicorn.run(create_app(args.data_dir), host=args.host, port=args.port, workers=1, proxy_headers=False)
        return 0
    if args.command == "assess":
        from .report import csv_cell, write_html_report
        source, destination = Path(args.input), Path(args.output)
        html = destination.with_suffix(".html")
        if source.resolve() in (destination.resolve(), html.resolve()):
            parser.error("Output files must differ from the input CSV")
        try:
            with source.open(newline="", encoding="utf-8-sig") as input_file:
                reader = csv.DictReader(input_file)
                if not {"target", "port", "php", "wordpress"}.issubset(reader.fieldnames or []):
                    parser.error("Use a scanner results CSV, not an inventory CSV")
                rows = [enrich(row) for row in reader]
                fields = list(dict.fromkeys((reader.fieldnames or []) + list(enrich({}).keys())))
            with destination.open("w", newline="", encoding="utf-8") as output:
                writer = csv.DictWriter(output, fieldnames=fields)
                writer.writeheader()
                writer.writerows({key: csv_cell(value) for key, value in row.items()} for row in rows)
            coverage = source.with_suffix(".coverage.json")
            scope = json.loads(coverage.read_text(encoding="utf-8")) if coverage.exists() else dict(source="Imported scan results; original coverage unavailable")
            write_html_report(html, rows, status="imported", scope=scope)
        except (OSError, ValueError, csv.Error) as exc:
            parser.error(str(exc))
        print("Assessed {} rows. HTML: {}".format(len(rows), html))
        return 0
    return 0
