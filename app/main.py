from __future__ import annotations

import asyncio
import hmac
import ipaddress
import logging
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from app.core.config import ALLOWED_EXTENSIONS, LIVE_MAX_CONCURRENT, MAX_UPLOAD_BYTES, REMOTE_API_TOKEN, ROOT
from app.models import HostKeyEnrollmentRequest, SSHAssessmentRequest, SSHTargetRequest, VersionCVERequest
from app.reports.export import export
from app.services import store
from app.services.engine import assess
from app.services.live import (
    LiveAuditError, PreparedTarget, collect_device_info, enroll_host_key, inspect_host_key,
    prepare_target, run_live_audit, run_unified_scan,
)
from app.services.parser import RouterExport, parse_export
from aynuomodules.cve import CVEAssessmentError, assess as assess_cves

log = logging.getLogger("aynuo")


@asynccontextmanager
async def lifespan(_: FastAPI):
    store.initialize()
    yield


app = FastAPI(
    title="AYNUO v4.0 — MikroTik Security Assessment Platform",
    version="4.0.0", docs_url=None, redoc_url=None, lifespan=lifespan,
)
app.mount("/assets", StaticFiles(directory=ROOT / "frontend"), name="assets")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    client_host = request.client.host if request.client else ""
    try:
        local = ipaddress.ip_address(client_host).is_loopback
    except ValueError:
        local = False
    if not local:
        supplied = request.headers.get("X-AYNUO-Token", "")
        if not REMOTE_API_TOKEN or not hmac.compare_digest(supplied, REMOTE_API_TOKEN):
            return JSONResponse({"detail": "Remote dashboard access requires a valid AYNUO API token."}, 403)
    response = await call_next(request)
    response.headers.update({
        "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; script-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        "Cache-Control": "no-store" if request.url.path.startswith("/api/") else "no-cache",
    })
    return response


@app.get("/")
def dashboard():
    return FileResponse(ROOT / "frontend" / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ready", "product": "AYNUO", "version": "4.0.0", "transport": "SSH"}


async def _target(request: SSHTargetRequest) -> PreparedTarget:
    try:
        return await asyncio.to_thread(prepare_target, request.host, request.port)
    except LiveAuditError as exc:
        raise HTTPException(422, exc.public_message) from exc


@app.post("/api/ssh/host-key/inspect")
async def host_key_inspect(request: SSHTargetRequest):
    target = await _target(request)
    try:
        return await asyncio.to_thread(inspect_host_key, target, request.timeout)
    except LiveAuditError as exc:
        raise HTTPException(422, exc.public_message) from exc


@app.post("/api/ssh/host-key/enroll")
async def host_key_enroll(request: HostKeyEnrollmentRequest):
    target = await _target(request)
    try:
        return await asyncio.to_thread(
            enroll_host_key, target, request.fingerprint, timeout=request.timeout,
        )
    except LiveAuditError as exc:
        raise HTTPException(409 if exc.code == "host_key_changed" else 422, exc.public_message) from exc


def _run_offline_audit(aid: str, filename: str, parsed: RouterExport) -> None:
    try:
        store.set_running(aid)
        store.update_stage(aid, "running_security_checks")
        result = assess(parsed)
        store.update_stage(aid, "generating_results")
        result.update({"id": aid, "filename": filename})
        store.complete(aid, result)
    except Exception as exc:
        log.exception("Offline audit %s failed", aid)
        store.fail(aid, f"Assessment failed: {type(exc).__name__}: {exc}")


@app.post("/api/assessments", status_code=202)
@app.post("/api/audits/offline", status_code=202)
async def create_offline_audit(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    filename = Path(file.filename or "").name
    if Path(filename).suffix.lower() not in ALLOWED_EXTENSIONS:
        raise HTTPException(415, "Upload a RouterOS .rsc or .txt text export.")
    try:
        payload = await file.read(MAX_UPLOAD_BYTES + 1)
    finally:
        await file.close()
    if len(payload) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "The upload exceeds the 5 MB limit.")
    try:
        parsed = parse_export(payload.decode("utf-8-sig"))
    except UnicodeDecodeError as exc:
        raise HTTPException(422, "The upload must be a UTF-8 RouterOS text export.") from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    aid = str(uuid.uuid4())
    store.create_pending(aid, filename, assessment_type="AUDIT")
    background_tasks.add_task(_run_offline_audit, aid, filename, parsed)
    return {"id": aid, "status": "queued", "assessment_type": "AUDIT", "source": "OFFLINE"}


def _run_ssh_audit(aid: str, request: SSHAssessmentRequest, target: PreparedTarget) -> None:
    password = request.password.get_secret_value()
    try:
        store.set_running(aid)
        result = run_live_audit(
            target, request.username, password, timeout=request.timeout,
            progress=lambda stage: store.update_stage(aid, stage),
        )
        result.update({"id": aid, "filename": f"SSH audit {target.hostname}"})
        store.complete(aid, result)
    except LiveAuditError as exc:
        log.warning("SSH audit %s failed with code %s", aid, exc.code)
        store.fail(aid, exc.public_message)
    except Exception as exc:
        log.error("SSH audit %s failed unexpectedly (%s)", aid, type(exc).__name__)
        store.fail(aid, "The SSH audit failed unexpectedly. Review server diagnostics and retry.")
    finally:
        password = ""
        request.password = type(request.password)("")


@app.post("/api/audits/ssh", status_code=202)
async def create_ssh_audit(request: SSHAssessmentRequest, background_tasks: BackgroundTasks):
    target = await _target(request)
    aid = str(uuid.uuid4())
    try:
        store.create_live_pending(
            aid, f"SSH audit {target.hostname}", f"{target.resolved_ip}:{target.port}",
            LIVE_MAX_CONCURRENT, "AUDIT",
        )
    except store.JobConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    background_tasks.add_task(_run_ssh_audit, aid, request, target)
    return {"id": aid, "status": "queued", "assessment_type": "AUDIT", "source": "SSH"}


def _run_unified_security_scan(aid: str, request: SSHAssessmentRequest, target: PreparedTarget) -> None:
    password = request.password.get_secret_value()
    try:
        store.set_running(aid)
        result = run_unified_scan(
            target, request.username, password, timeout=request.timeout,
            progress=lambda stage: store.update_stage(aid, stage),
            component_progress=lambda component, state: store.update_component(aid, component, state),
        )
        result.update({"id": aid, "filename": f"Unified SSH scan {target.hostname}"})
        store.complete(aid, result)
    except LiveAuditError as exc:
        log.warning("Unified SSH scan %s failed with code %s", aid, exc.code)
        store.fail(aid, exc.public_message)
    except Exception as exc:
        log.error("Unified SSH scan %s failed unexpectedly (%s)", aid, type(exc).__name__)
        store.fail(aid, "The unified security scan failed unexpectedly. Review diagnostics and retry.")
    finally:
        password = ""
        request.password = type(request.password)("")


@app.post("/api/scans/ssh", status_code=202)
async def create_unified_security_scan(request: SSHAssessmentRequest, background_tasks: BackgroundTasks):
    target = await _target(request)
    aid = str(uuid.uuid4())
    try:
        store.create_live_pending(
            aid, f"Unified SSH scan {target.hostname}", f"{target.resolved_ip}:{target.port}",
            LIVE_MAX_CONCURRENT, "SCAN",
        )
    except store.JobConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    background_tasks.add_task(_run_unified_security_scan, aid, request, target)
    return {"id": aid, "status": "queued", "assessment_type": "SCAN", "source": "SSH"}


def _run_offline_cve(aid: str, version: str) -> None:
    try:
        store.set_running(aid)
        result = assess_cves(version, progress=lambda stage: store.update_stage(aid, stage))
        result.update({"id": aid, "filename": f"RouterOS {version} CVE assessment"})
        store.complete(aid, result)
    except CVEAssessmentError as exc:
        log.warning("CVE assessment %s failed: data unavailable", aid)
        store.fail(aid, str(exc))
    except Exception as exc:
        log.error("CVE assessment %s failed unexpectedly (%s)", aid, type(exc).__name__)
        store.fail(aid, "The CVE assessment failed unexpectedly; vulnerability status is unknown.")


@app.post("/api/cve/version", status_code=202)
def create_version_cve(request: VersionCVERequest, background_tasks: BackgroundTasks):
    aid = str(uuid.uuid4())
    store.create_pending(
        aid, f"RouterOS {request.version} CVE assessment", source="OFFLINE",
        assessment_type="CVE", routeros_version=request.version,
    )
    background_tasks.add_task(_run_offline_cve, aid, request.version)
    return {"id": aid, "status": "queued", "assessment_type": "CVE", "source": "OFFLINE"}


def _run_ssh_cve(aid: str, request: SSHAssessmentRequest, target: PreparedTarget) -> None:
    password = request.password.get_secret_value()
    try:
        store.set_running(aid)
        store.update_stage(aid, "retrieving_router_information")
        device = collect_device_info(target, request.username, password, timeout=request.timeout)
        version = device.get("routeros_version")
        if not version:
            raise LiveAuditError("version_unavailable", "RouterOS did not return a version over SSH.")
        result = assess_cves(
            str(version), source="SSH", device=device,
            progress=lambda stage: store.update_stage(aid, stage),
        )
        result.update({"id": aid, "filename": f"SSH CVE assessment {target.hostname}"})
        store.complete(aid, result)
    except (LiveAuditError, CVEAssessmentError) as exc:
        message = exc.public_message if isinstance(exc, LiveAuditError) else str(exc)
        log.warning("SSH CVE assessment %s failed safely", aid)
        store.fail(aid, message)
    except Exception as exc:
        log.error("SSH CVE assessment %s failed unexpectedly (%s)", aid, type(exc).__name__)
        store.fail(aid, "The live CVE assessment failed unexpectedly; vulnerability status is unknown.")
    finally:
        password = ""
        request.password = type(request.password)("")


@app.post("/api/cve/ssh", status_code=202)
async def create_ssh_cve(request: SSHAssessmentRequest, background_tasks: BackgroundTasks):
    target = await _target(request)
    aid = str(uuid.uuid4())
    try:
        store.create_live_pending(
            aid, f"SSH CVE assessment {target.hostname}", f"{target.resolved_ip}:{target.port}",
            LIVE_MAX_CONCURRENT, "CVE",
        )
    except store.JobConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    background_tasks.add_task(_run_ssh_cve, aid, request, target)
    return {"id": aid, "status": "queued", "assessment_type": "CVE", "source": "SSH"}


@app.get("/api/assessments/{assessment_id}/status")
def assessment_status(assessment_id: str):
    state = store.status(assessment_id)
    if not state:
        raise HTTPException(404, "Assessment not found.")
    return state


@app.get("/api/assessments/{assessment_id}")
@app.get("/api/assessments/{assessment_id}/results")
def assessment(assessment_id: str):
    state = store.status(assessment_id)
    if not state:
        raise HTTPException(404, "Assessment not found.")
    if state["status"] != "completed":
        raise HTTPException(409, state.get("error") or f"Assessment is {state['status']}.")
    return store.get(assessment_id)


@app.get("/api/assessments/{assessment_id}/export/{kind}")
def report(assessment_id: str, kind: str):
    result = store.get(assessment_id)
    if not result:
        state = store.status(assessment_id)
        if state:
            raise HTTPException(409, state.get("error") or f"Assessment is {state['status']}.")
        raise HTTPException(404, "Assessment not found.")
    if kind not in {"html", "json", "csv", "pdf"}:
        raise HTTPException(400, "Supported exports: HTML, JSON, CSV, PDF.")
    body, content_type, extension = export(result, kind)
    return Response(body, media_type=content_type, headers={
        "Content-Disposition": f'attachment; filename="aynuo-{assessment_id}.{extension}"',
    })

