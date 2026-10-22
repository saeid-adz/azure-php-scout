# Self-hosting

The supported first-release topology is one service instance with one persistent
local data directory. Run `azure-php-scout serve` directly or use `compose.yaml`.
The container includes pinned Azure CLI and Resource Graph, runs as UID 10001, and
persists state under `/data`. TCP discovery uses normal connect sockets and needs
no raw-socket privileges.

## Local Docker

Generate a random token in `.env`, then start Compose as described in the README.
The published port is bound to 127.0.0.1. Azure CLI credentials can be initialized
inside the container:

```sh
docker compose exec scout az login --use-device-code
```

Authenticate in the browser using the service token from `.env`. This operator
token is separate from Azure authentication. Keep `.env` and the data volume private.

## Azure with managed identity

Host the container or Python service where it can reach the identity endpoint and
the public targets. Assign a system/user managed identity and grant it resource
read access on the subscriptions to assess. Inside that environment:

```sh
az login --identity
```

For a user-assigned identity:

```sh
az login --identity --client-id MANAGED-IDENTITY-CLIENT-ID
```

With Compose on an appropriately configured Azure VM, run those commands through
`docker compose exec scout`. No identity secret belongs in the image, source,
request payload, or repository. Reader visibility can vary across delegated
subscriptions/tenants; review the report's inventory errors.

The project does not provision Azure resources or assign roles automatically.
Allow outbound Azure metadata/API access, DNS, and target HTTP/TCP connections.
For internal targets, use an appropriate VNet-connected execution location and
provide reachable target addresses. Direct-IP discovery does not enumerate inbound
load-balancer/NAT mappings.

## Remote operator access

Set `SCOUT_API_TOKEN` to at least 32 random characters and `SCOUT_ALLOWED_HOSTS` to
the actual ingress hostname. Put the service behind HTTPS and a restricted ingress
or VPN. The bearer token grants scan and data access. It is not a multi-user role
system. The server does not trust forwarded headers by default.

Do not run multiple Uvicorn workers against one data directory; the process lock
rejects a second owner. Restrict the data directory/volume to the operator, and
back it up according to your retention policy. It contains customer inventories,
logs, results, and Azure CLI session state. The repository and image contain only
code and synthetic examples.

Graceful shutdown allows up to 15 seconds for active workers to stop before they
are killed. A container supervisor should terminate all child processes on a hard
stop. Interrupted jobs remain in history and are not automatically rerun. There
is no automatic retry of a full estate scan after a service restart.

Optional guest inspection needs the identity's Run Command action permission on
the VMs in the selected subscription or individually selected VMs, in addition to
inventory read access. Grant Reader on the whole selected subscription for full
VM discovery. Scripts run as
root/SYSTEM through a ready VM Agent, including on private VMs. Restrict those
permissions to the intended VM scope and protect the service token accordingly.
Stopping the service cannot cancel guest scripts already accepted by Azure.
See [guest inspection](GUEST-INSPECTION.md) for permissions, output limits, and
the distinction between installed and HTTP runtime evidence.
