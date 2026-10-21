# Contributing

Start with an issue describing the discovery or assessment behavior you want to
improve. Reproduce issues using `examples/` or a local HTTP fixture. Remove all
real tenant, subscription, resource, hostname, and address data from public reports.

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
python -m pytest -q
python -m build
```

Tests query synthetic Azure records and local TCP/HTTP/HTTPS fixtures. They must
never automatically scan a contributor's subscriptions or public addresses.
Some environments require permission for local socket listeners. The TLS fixture
uses OpenSSL and is skipped when it is not installed.

Keep discovery, configuration evidence, runtime evidence, and advisory assessment
separate. Add regression tests for affected/fixed boundaries, prereleases, unknown
versions, and vendor backport uncertainty when changing version rules. Update
`data/advisories.json` with primary vendor URLs and the actual review date. Never
combine fixed versions for separate branches into one global comparison.

The packaged report and browser dashboard must escape external text. Avoid
`innerHTML` for scan data, arbitrary file paths in API requests, or secrets in
subprocess arguments. Preserve the bounded TCP/HTTP pipeline and explicit coverage
gaps. Add meaningful tests for security boundaries and operational behavior.

The source uses the MIT license. By contributing, you agree that contributions
are provided under that license. Security bugs belong in private reporting,
as described in [SECURITY.md](SECURITY.md).
