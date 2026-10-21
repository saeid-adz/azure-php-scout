# Security policy

Report vulnerabilities in Azure PHP Scout through
[GitHub private vulnerability reporting](https://github.com/saeid-adz/azure-php-scout/security/advisories/new).
Keep customer IPs, hostnames, subscription IDs, credentials, and scan exports out
of public issues and pull requests. Use the synthetic examples for reproductions.

This is a self-hosted, single-operator discovery service. Every API route containing
scan data or controls requires a bearer token. The default listener is loopback.
Non-loopback binding requires an explicit `SCOUT_API_TOKEN`. Use TLS, a restricted
network path, and access controls at your ingress when hosting remotely. One
service process owns a data directory; do not use multiple Uvicorn workers against
one directory. The service uses an exclusive process lock.

The scanner sends TCP connections and HTTP GETs. It never submits exploit payloads,
executes fixes, or invokes VM Run Command. Use it on resources you administer or
have permission to assess. Azure discovery is read-only, but scans create network
traffic and logs. Full-range scans can run for hours and are explicitly selected.

Version-based findings do not establish exploitability, vendor patch status, or
complete vulnerability coverage. The reviewed catalog covers two PHP core CVEs;
unknown versions and unreviewed branches remain verification tasks. Verify the
runtime serving requests and distribution/LTS backports. The tool does not replace
vendor guidance, authenticated package inventory, or a broader security assessment.

Runtime data, the SQLite database, logs, reports, inventories, Azure CLI state,
and service tokens are local operator data. They are excluded from source control
and from the Docker build context. The Dockerfile copies only source/package files.
The service token is stored in a private file when not supplied by environment;
the browser stores it in session storage for the lifetime of its tab.

Please use the latest release. No long-term support commitment is currently made.
