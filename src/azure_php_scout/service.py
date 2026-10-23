"""Authenticated, single-operator FastAPI service for self-hosted scan workflows."""
from contextlib import asynccontextmanager
import csv
import io
import os
from pathlib import Path
import secrets
import shutil
from typing import Literal
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .advisories import catalog
from .inventory import az_json
from .jobs import JobManager, summarize
from .guest import list_vms, script_info, selected_vm_ids, retry_input
from .scanner import hostname, parse_ports


def service_token(root):
    supplied = os.environ.get("SCOUT_API_TOKEN")
    if supplied:
        if len(supplied) < 32 or supplied.lower().startswith(("replace-", "change-me", "changeme")):
            raise RuntimeError("SCOUT_API_TOKEN must be a fresh random token containing at least 32 characters")
        return supplied
    root = Path(root)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = root / "service-token"
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        token = path.read_text(encoding="utf-8").strip()
    else:
        token = secrets.token_urlsafe(32)
        with os.fdopen(descriptor, "w") as output:
            output.write(token + "\n")
    if len(token) < 32:
        raise RuntimeError("The saved service token is invalid. Replace it with a fresh token.")
    return token


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["azure", "targets", "inventory", "demo", "guest"] = "azure"
    name: str = Field(default="Azure discovery", min_length=1, max_length=100)
    subscriptions: list[str] = Field(default_factory=list, max_length=1000)
    targets: list[str] = Field(default_factory=list, max_length=256)
    inventory_csv: str = Field(default="", max_length=1_500_000)
    vm_ports: str = Field(default="web", max_length=1000)
    timeout: float = Field(default=5, ge=1, le=30)
    workers: int = Field(default=10, ge=1, le=64)
    port_workers: int = Field(default=256, ge=1, le=1024)
    port_rate: int = Field(default=500, ge=1, le=5000)
    port_timeout: float = Field(default=1, ge=0.2, le=10)
    running_only: bool = False
    no_probes: bool = False
    verify_tls: bool = False
    vm_ids: list[str] = Field(default_factory=list, max_length=50)
    guest_subscription: str | None = None
    guest_all_subscriptions: bool = False
    guest_retry_scan: str | None = None
    guest_timeout: int = Field(default=180, ge=60, le=1800)

    @field_validator("guest_subscription", "guest_retry_scan")
    @classmethod
    def guest_subscription_id(cls, value):
        return str(UUID(value)) if value is not None else None

    @field_validator("vm_ids")
    @classmethod
    def virtual_machine_ids(cls, values):
        return selected_vm_ids(values) if values else []

    @field_validator("subscriptions")
    @classmethod
    def subscription_ids(cls, values):
        return list(dict.fromkeys(str(UUID(value)) for value in values))

    @field_validator("targets")
    @classmethod
    def target_names(cls, values):
        return list(dict.fromkeys(hostname(value) for value in values))

    @field_validator("vm_ports")
    @classmethod
    def port_scope(cls, value):
        try:
            parse_ports(value)
        except Exception as exc:
            raise ValueError("Use web, all, or valid TCP ports/ranges") from exc
        return value

    @model_validator(mode="after")
    def source(self):
        if self.mode == "guest" and sum((bool(self.vm_ids), bool(self.guest_subscription), self.guest_all_subscriptions, bool(self.guest_retry_scan))) != 1:
            raise ValueError("Choose all subscriptions, one subscription, specific VM IDs, or a previous guest scan to retry")
        if self.mode == "guest" and (self.guest_subscription or self.guest_all_subscriptions or self.guest_retry_scan) and self.subscriptions:
            raise ValueError("Guest subscription scopes cannot be combined with subscription browsing filters")
        if self.mode != "guest" and (self.vm_ids or self.guest_subscription or self.guest_all_subscriptions or self.guest_retry_scan):
            raise ValueError("Guest subscription and VM resource IDs are only used in guest inspection mode")
        if self.mode == "targets" and not self.targets:
            raise ValueError("Provide at least one target")
        if self.mode == "inventory":
            reader = csv.DictReader(io.StringIO(self.inventory_csv))
            if not set(reader.fieldnames or []).intersection({"ip", "publicIp", "hostname"}):
                raise ValueError("CSV needs a publicIp, ip, or hostname column")
            if not any(reader):
                raise ValueError("CSV has no targets")
        return self


def create_app(data_dir=None, token=None):
    root = Path(data_dir or os.environ.get("SCOUT_DATA_DIR", ".scout")).resolve()
    api_token = token or service_token(root)
    if len(api_token) < 32:
        raise RuntimeError("Service tokens must contain at least 32 characters")

    @asynccontextmanager
    async def lifespan(app):
        app.state.jobs = JobManager(root)
        try:
            yield
        finally:
            app.state.jobs.close()

    app = FastAPI(title="Azure PHP Scout", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    allowed = ["localhost", "127.0.0.1", "[::1]"] + os.environ.get("SCOUT_ALLOWED_HOSTS", "").split(",")
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[host.strip() for host in allowed])

    @app.middleware("http")
    async def controls(request: Request, call_next):
        if request.method in ("POST", "PUT", "PATCH"):
            length = request.headers.get("content-length")
            if length is None:
                return JSONResponse({"detail": "Content-Length required"}, status_code=411)
            try:
                valid_length = 0 <= int(length) <= 2_000_000
            except ValueError:
                valid_length = False
            if not valid_length:
                return JSONResponse({"detail": "Request body exceeds 2 MB or has an invalid length"}, status_code=413)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        return response

    def authorize(authorization: str | None = Header(default=None)):
        candidate = authorization[7:] if authorization and authorization.startswith("Bearer ") else ""
        if not secrets.compare_digest(candidate.encode("utf-8"), api_token.encode("utf-8")):
            raise HTTPException(401, "A valid service token is required", headers={"WWW-Authenticate": "Bearer"})

    auth = [Depends(authorize)]

    def public_job(value):
        value = dict(value)
        value["config"] = {key: field for key, field in value["config"].items() if key != "inventory_csv"}
        return value
    assets = Path(__file__).with_name("web")
    app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(assets / "index.html")

    @app.get("/healthz")
    def health():
        return {"status": "ok", "version": __version__}

    @app.get("/api/status", dependencies=auth)
    def status():
        return dict(version=__version__, azureCliAvailable=shutil.which("az") is not None,
                    advisoryReviewedAt=catalog()["reviewed_at"], advisoryScope=catalog()["scope"],
                    advisoryIds=[item["id"] for item in catalog()["advisories"]])

    @app.get("/api/advisories", dependencies=auth)
    def advisories():
        return catalog()

    @app.get("/api/azure/subscriptions", dependencies=auth)
    def subscriptions():
        try:
            records = az_json(["account", "list", "--all"])
            return [{key: row.get(key) for key in ("id", "name", "tenantId", "state")}
                    for row in records if row.get("state") == "Enabled"]
        except RuntimeError as exc:
            raise HTTPException(503, str(exc)) from exc

    @app.get("/api/scans", dependencies=auth)
    def scans():
        return [public_job(value) for value in app.state.jobs.list()]

    @app.get("/api/azure/vms", dependencies=auth)
    def virtual_machines(subscription: list[UUID] = Query(default=[])):
        try:
            return list_vms([str(value) for value in subscription])
        except (RuntimeError, ValueError) as exc:
            raise HTTPException(503, str(exc)) from exc

    @app.get("/api/guest/scripts/{os_name}", dependencies=auth)
    def guest_script(os_name: Literal["Linux", "Windows"]):
        return script_info(os_name)

    @app.post("/api/scans", status_code=202, dependencies=auth)
    def create_scan(config: ScanRequest):
        if config.mode in ("azure", "guest") and not shutil.which("az"):
            raise HTTPException(503, "Install Azure CLI and run az login, or use an inventory CSV.")
        if config.guest_retry_scan:
            parent = job(config.guest_retry_scan)
            if parent["config"]["mode"] != "guest" or parent["state"] in ("queued", "running", "cancelling"):
                raise HTTPException(409, "Select a finished VM guest scan to retry")
            try:
                retry_input(app.state.jobs.directory(config.guest_retry_scan) / "results.csv")
            except (ValueError, OSError) as exc:
                raise HTTPException(409, str(exc)) from exc
        try:
            return public_job(app.state.jobs.create(config.model_dump()))
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc

    def job(job_id):
        try:
            return app.state.jobs.get(job_id)
        except (KeyError, ValueError):
            raise HTTPException(404, "Scan not found") from None

    @app.get("/api/scans/{job_id}", dependencies=auth)
    def scan_detail(job_id: str):
        value = job(job_id)
        rows = app.state.jobs.rows(job_id)
        value.update(summary=summarize(rows), coverage=app.state.jobs.coverage(job_id))
        return public_job(value)

    @app.get("/api/scans/{job_id}/results", dependencies=auth)
    def results(job_id: str, offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500),
                q: str = Query("", max_length=200), resource_type: str = "", assessment: str = ""):
        job(job_id)
        rows = app.state.jobs.rows(job_id)
        selected = [row for row in rows if (not q or q.casefold() in " ".join(str(value) for value in row.values()).casefold())
                    and (not resource_type or row.get("resourceType") == resource_type)
                    and (not assessment or row.get("assessment") == assessment)]
        priority = {"critical": 0, "high": 1, "medium": 2, "info": 3}
        selected.sort(key=lambda row: (priority.get(row.get("riskLevel"), 4), row.get("target", ""), str(row.get("port", ""))))
        return dict(total=len(selected), offset=offset, limit=limit, rows=selected[offset:offset + limit])

    @app.post("/api/scans/{job_id}/cancel", dependencies=auth)
    def cancel(job_id: str):
        job(job_id)
        return public_job(app.state.jobs.cancel(job_id))

    @app.get("/api/openapi.json", dependencies=auth)
    def schema():
        return app.openapi()

    @app.get("/api/scans/{job_id}/logs", dependencies=auth)
    def logs(job_id: str):
        job(job_id)
        path = app.state.jobs.directory(job_id) / "scan.log"
        if not path.exists():
            return {"text": ""}
        with path.open("rb") as source:
            source.seek(max(0, path.stat().st_size - 32_000))
            return {"text": source.read().decode("utf-8", "replace")}

    @app.get("/api/scans/{job_id}/export/{format}", dependencies=auth)
    def export(job_id: str, format: Literal["html", "csv", "json"]):
        job(job_id)
        name = {"html": "results.html", "csv": "results.csv", "json": "results.coverage.json"}[format]
        path = app.state.jobs.directory(job_id) / name
        if not path.exists():
            raise HTTPException(409, "This export is not available yet")
        return FileResponse(path, filename="azure-php-scout-{}.{}".format(job_id[:8], format),
                            media_type={"html": "text/html", "csv": "text/csv", "json": "application/json"}[format])

    return app
