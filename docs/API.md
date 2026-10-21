# API

All `/api/` endpoints require `Authorization: Bearer <service-token>`. The health
probe and static sign-in interface contain no private scan data. Interactive API
documentation is disabled; authenticated OpenAPI is at `/api/openapi.json`.
Mutating requests use JSON and require Content-Length, with a 2 MB body limit.
The service does not enable cross-origin browser access.

| Method | Path | Result |
| --- | --- | --- |
| GET | `/healthz` | Liveness/version, no authentication. |
| GET | `/api/status` | Version, Azure CLI availability, reviewed advisory scope. |
| GET | `/api/advisories` | Bundled catalog and primary source links. |
| GET | `/api/azure/subscriptions` | Enabled subscriptions visible to the host CLI. |
| GET | `/api/azure/vms?subscription=UUID` | VM inventory including private Windows/Linux VMs; repeat subscription to scope browsing. Returns `{vms, errors}`. |
| GET | `/api/guest/scripts/{os}` | Fixed `Linux`/`Windows` script, command ID, filename, and SHA-256 for operator review. |
| GET | `/api/scans` | Latest 200 runs, with configuration and state. |
| POST | `/api/scans` | Queue a run, returning HTTP 202 and its UUID. |
| GET | `/api/scans/{id}` | Current summary and coverage snapshot. |
| GET | `/api/scans/{id}/results` | Filtered/paginated findings. |
| POST | `/api/scans/{id}/cancel` | Cancel a queued run or interrupt its worker. |
| GET | `/api/scans/{id}/logs` | Last 32 KB of the scan log. |
| GET | `/api/scans/{id}/export/{format}` | Download `html`, `csv`, or coverage `json`. |

Example scan request:

```json
{
  "mode": "azure",
  "name": "Web exposure review",
  "subscriptions": [],
  "vm_ports": "web",
  "workers": 10,
  "timeout": 5,
  "port_workers": 256,
  "port_rate": 500,
  "port_timeout": 1,
  "running_only": false,
  "no_probes": false,
  "verify_tls": false
}
```

Modes: `azure` for live metadata discovery, `targets` with an array of IPs/hostnames,
`inventory` with UTF-8 text in `inventory_csv`, `demo` for synthetic results, or
`guest` for explicitly selected VM guest inspections.
Subscription IDs must be UUIDs. At most 256 direct targets, 1.5 MB inventory text,
64 HTTP workers, 1,024 TCP sockets, and 5,000 new TCP connections/second are allowed.
The queue admits up to eight pending/running runs. One run executes at a time.

Guest mode requires `vm_ids`, an explicit array of 1–50 full VM resource IDs,
and accepts `guest_timeout` (60–1800 seconds, default 180). No caller-supplied
script or command is accepted. VM IDs are rejected in other modes. Subscription
filters do not expand or replace the explicit guest execution scope. The guest
worker checks that the VM is running with a ready agent before submission and
selects the fixed OS-specific script. Guest commands run sequentially.

```json
{
  "mode": "guest",
  "name": "Selected VM PHP inventory",
  "vm_ids": ["/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/example-rg/providers/Microsoft.Compute/virtualMachines/example-vm"],
  "guest_timeout": 180
}
```

Guest rows include `evidenceSource=guest`, `guestStatus`, `guestSource`,
`guestPath`, `guestPackage`, `guestPackageVersion`, `guestProcessObserved`,
`guestCoverage`, and `guestScriptSha256`. Guest records have no HTTP URL/port.
Summary fields `guestVms` and `guestChecked` count unique VMs separately from
software records and HTTP response counts. Coverage has `scanType=guest`,
`guest` progress counters, and `remoteMayContinue` for uncertain remote execution.

Results accept `offset` (default 0), `limit` (1–500, default 100), `q`,
`resource_type`, and `assessment`. They are sorted by risk priority, then target.
Response shape: `{total, offset, limit, rows}`. Row fields include evidence and
source/configuration metadata, `assessment`, `riskLevel`, `cves`, `remediation`,
`phpSupport`, and `advisoryReviewedAt`. Exported CSV text is protected against
spreadsheet formula interpretation.

States: `queued`, `running`, `cancelling`, `cancelled`, `complete`, `partial`,
`failed`, and `interrupted`. A partial run has findings and a nonzero scanner exit;
its coverage/log explains the gap. On service restart, unfinished history becomes
interrupted and is not automatically restarted. Cancellation is best effort;
completed artifacts are retained. An unresponsive process is killed after 15 seconds.
For guest mode, this stops the local client, not a script already accepted by
Azure Action Run Command. Check Azure before retrying a timed-out/cancelled VM.

The token can start scans and read results, so protect it as an operator credential.
There is no arbitrary command, local path, or public unauthenticated scanner API.
The token also permits bundled guest checks using the host's Run Command permissions.
