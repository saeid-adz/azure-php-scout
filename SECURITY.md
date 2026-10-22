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

External scanning sends TCP connections and HTTP GETs. It never submits exploit
payloads or executes fixes. Optional **guest inspection** invokes fixed Azure Run
Command scripts as root/SYSTEM on all VMs across the signed-in account's accessible
subscriptions, one selected subscription, or specific VM IDs. Account-wide execution
requires the explicit **All accessible subscriptions** scope / `--all-subscriptions`
flag / `guest_all_subscriptions=true`; it is never implied by an empty selection.
Subscription scopes include private VMs and have no 50-VM limit. Incomplete discovery
prevents submissions in affected subscriptions; other discovered subscriptions
continue in account-wide mode. The API does not
accept custom guest scripts or arbitrary commands. The host identity must have
the relevant Run Command action permission. Reader alone is insufficient.
The service token can request these privileged checks using that host identity.
Use it on resources you administer or
have permission to assess. Azure discovery is read-only, but scans create network
traffic and logs. Full-range scans can run for hours and are explicitly selected.
Guest checks also create Azure Run Command extension/agent artifacts and logs.
The bundled scripts do not install packages, change application configuration,
or restart services. Installed package/file versions remain separate from HTTP
runtime evidence. See [guest inspection](docs/GUEST-INSPECTION.md).

Azure Action Run Command cannot cancel a submitted guest script. Local
cancellation prevents further submissions and stops waiting, while an accepted
remote command may continue. Reports retain this uncertainty and do not retry
automatically. Missing or truncated output is not reported as PHP absence.

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
