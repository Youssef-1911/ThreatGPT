from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import logging
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from .. import models, schemas
from ..analysis_orchestrator import AnalysisOrchestrator
from ..deps import get_current_user, get_db
from ..email_service import EmailService
from ..versioning_service import create_project_version

router = APIRouter(prefix="/projects/{project_id}/integrations", tags=["integrations"])
UPLOAD_ROOT = Path(__file__).resolve().parents[1] / "uploads"
logger = logging.getLogger(__name__)

SUPPORTED_WEBHOOK_TYPES = {"GIT_WEBHOOK", "SAST_WEBHOOK", "DAST_WEBHOOK"}
PHASE_BY_INTEGRATION = {
    "GIT_WEBHOOK": "In Development",
    "SAST_WEBHOOK": "In Development",
    "DAST_WEBHOOK": "Pre-release",
}


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC).replace(tzinfo=None)


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _hash_payload(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _serialize_payload(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, default=str)


def _assert_webhook_secret(provided_secret: str | None, stored_secret_hash: str | None) -> None:
    if not provided_secret or not stored_secret_hash:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid integration secret")
    provided_hash = _hash_secret(provided_secret)
    if not hmac.compare_digest(provided_hash, stored_secret_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid integration secret")


def _extract_branch_from_git_ref(ref: Any) -> str | None:
    if not isinstance(ref, str) or not ref.strip():
        return None
    prefix = "refs/heads/"
    if ref.startswith(prefix):
        return ref[len(prefix) :]
    return ref


def _extract_changed_files_from_github_push(payload: dict[str, Any]) -> list[str]:
    changed_files: set[str] = set()
    commits = payload.get("commits")
    if isinstance(commits, list):
        for commit in commits:
            if not isinstance(commit, dict):
                continue
            for key in ("added", "modified", "removed"):
                values = commit.get(key)
                if isinstance(values, list):
                    changed_files.update(str(value) for value in values if value)

    head_commit = payload.get("head_commit")
    if isinstance(head_commit, dict):
        for key in ("added", "modified", "removed"):
            values = head_commit.get(key)
            if isinstance(values, list):
                changed_files.update(str(value) for value in values if value)

    return sorted(changed_files)


def _get_project_for_owner(db: Session, project_id: str, owner_id: str) -> models.Project:
    project = (
        db.query(models.Project)
        .filter(models.Project.id == project_id, models.Project.owner_id == owner_id)
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def _get_project_or_404(db: Session, project_id: str) -> models.Project:
    project = db.query(models.Project).filter(models.Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def _get_integration_config(
    db: Session,
    *,
    project_id: str,
    integration_type: str,
) -> models.IntegrationConfig:
    integration = (
        db.query(models.IntegrationConfig)
        .filter(
            models.IntegrationConfig.project_id == project_id,
            models.IntegrationConfig.integration_type == integration_type,
        )
        .order_by(models.IntegrationConfig.updated_at.desc())
        .first()
    )
    if not integration:
        raise HTTPException(status_code=404, detail="Integration configuration not found")
    if integration.status != "CONNECTED":
        raise HTTPException(status_code=400, detail="Integration is not connected")
    if integration.trigger_mode != "WEBHOOK":
        raise HTTPException(status_code=400, detail="Integration trigger mode does not allow webhook")
    return integration


def _existing_duplicate_event(
    db: Session,
    *,
    integration_id: str,
    external_event_id: str | None,
    payload_hash: str,
) -> models.IntegrationEvent | None:
    query = db.query(models.IntegrationEvent).filter(models.IntegrationEvent.integration_id == integration_id)
    if external_event_id:
        duplicate = query.filter(models.IntegrationEvent.external_event_id == external_event_id).first()
        if duplicate:
            return duplicate
    return query.filter(models.IntegrationEvent.payload_hash == payload_hash).first()


def _link_all_project_documents_to_version(db: Session, *, project_id: str, version_id: str) -> None:
    documents = db.query(models.ProjectDocument).filter(models.ProjectDocument.project_id == project_id).all()
    for document in documents:
        linked_versions = list(document.linked_version_ids or [])
        if version_id not in linked_versions:
            linked_versions.append(version_id)
            document.linked_version_ids = linked_versions
            document.updated_at = _utcnow()


def _persist_evidence_document(
    db: Session,
    *,
    project_id: str,
    version_id: str,
    phase: str,
    tag: str,
    doc_name: str,
    payload: dict[str, Any],
) -> models.ProjectDocument:
    now = _utcnow()
    project_dir = UPLOAD_ROOT / project_id / "integrations"
    project_dir.mkdir(parents=True, exist_ok=True)

    safe_name = f"{uuid.uuid4()}_{doc_name}.json"
    abs_path = project_dir / safe_name
    content = _serialize_payload(payload)
    abs_path.write_text(content, encoding="utf-8")

    document = models.ProjectDocument(
        id=str(uuid.uuid4()),
        project_id=project_id,
        name=f"{doc_name}.json",
        type="application/json",
        size=abs_path.stat().st_size,
        tag=tag,
        phase=phase,
        uploaded_at=now,
        storage_key=str(abs_path.relative_to(UPLOAD_ROOT)),
        linked_version_ids=[version_id],
        linked_threat_ids=[],
        created_at=now,
        updated_at=now,
    )
    db.add(document)
    return document


def _create_new_version_for_event(
    db: Session,
    *,
    project: models.Project,
    integration_type: str,
    commit_hash: str | None,
    branch: str | None,
    external_event_id: str | None,
    context_details: dict[str, Any],
) -> models.ProjectVersion:
    now = _utcnow()
    version = create_project_version(
        db,
        project=project,
        created_by=integration_type,
        context_snapshot={
            "integration_event": {
                "integration_type": integration_type,
                "external_event_id": external_event_id,
                "commit_hash": commit_hash,
                "branch": branch,
                "details": context_details,
            }
        },
        notes=f"Auto version from {integration_type}",
        threat_ids=[threat.id for threat in (project.threats or [])],
        mitigation_ids=[mitigation.id for mitigation in (project.mitigations or [])],
    )
    project.updated_at = now
    return version


def _find_linked_analysis_run_id(db: Session, *, project_id: str, version_id: str) -> str | None:
    run = (
        db.query(models.AnalysisRun)
        .filter(
            models.AnalysisRun.project_id == project_id,
            models.AnalysisRun.version_id == version_id,
            models.AnalysisRun.trigger_type.in_(["integration", "integration_manual"]),
        )
        .order_by(models.AnalysisRun.created_at.desc())
        .first()
    )
    return run.id if run else None


def _emit_integration_email(
    *,
    integration: models.IntegrationConfig,
    owner_email: str | None,
    subject: str,
    body: str,
) -> None:
    config = integration.config_json if isinstance(integration.config_json, dict) else {}
    recipients: list[str] = []
    if isinstance(owner_email, str) and owner_email.strip():
        recipients.append(owner_email.strip())

    notification_emails = config.get("notification_emails", [])
    if isinstance(notification_emails, list):
        for recipient in notification_emails:
            if isinstance(recipient, str) and recipient.strip() and recipient.strip() not in recipients:
                recipients.append(recipient.strip())

    if not recipients:
        return

    email_service = EmailService()
    for recipient in recipients:
        email_service.send_notification(
            to_email=recipient,
            subject=subject,
            body=body,
        )


def _extract_sast_findings(payload: dict[str, Any], report_content: Any) -> tuple[list[Any], str | None]:
    """Accept wrapped SAST findings, Semgrep webhook events, and raw Semgrep JSON output."""
    findings = payload.get("findings")
    if findings is None and isinstance(payload.get("results"), list):
        findings = payload.get("results")
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    if findings is None and isinstance(data.get("findings"), list):
        findings = data.get("findings")
    if findings is None and isinstance(data.get("results"), list):
        findings = data.get("results")
    if findings is None:
        semgrep_finding_candidates = _extract_semgrep_finding_candidates(payload, report_content)
        if semgrep_finding_candidates:
            findings = semgrep_finding_candidates
    if findings is None and isinstance(report_content, dict):
        report_findings = report_content.get("findings")
        semgrep_results = report_content.get("results")
        semgrep_finding_candidates = _extract_semgrep_finding_candidates(report_content, None)
        if isinstance(report_findings, list):
            findings = report_findings
        elif isinstance(semgrep_results, list):
            findings = semgrep_results
        elif semgrep_finding_candidates:
            findings = semgrep_finding_candidates

    if findings is None:
        return [], None
    if not isinstance(findings, list):
        return [], "findings must be a list"
    normalized = [
        _normalize_semgrep_webhook_finding(finding) if isinstance(finding, dict) else finding
        for finding in findings
    ]
    return normalized, None


def _extract_nested_object(payload: dict[str, Any], key: str) -> dict[str, Any] | None:
    direct = payload.get(key)
    if isinstance(direct, dict):
        return direct

    for container_key in ("data", "payload", "event"):
        container = payload.get(container_key)
        if isinstance(container, dict):
            nested = container.get(key)
            if isinstance(nested, dict):
                return nested
    return None


def _looks_like_semgrep_finding(candidate: Any) -> bool:
    if not isinstance(candidate, dict):
        return False
    return any(key in candidate for key in ("check_id", "path", "line", "message", "metadata"))


def _extract_semgrep_finding_candidates(payload: dict[str, Any], report_content: Any) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    if not isinstance(payload, dict):
        return candidates

    semgrep_finding = _extract_nested_object(payload, "semgrep_finding")
    if isinstance(semgrep_finding, dict):
        candidates.append({"semgrep_finding": semgrep_finding})

    for key in ("finding",):
        finding = _extract_nested_object(payload, key)
        if _looks_like_semgrep_finding(finding):
            candidates.append(finding)  # type: ignore[arg-type]

    event_type = str(payload.get("event_type") or payload.get("event") or payload.get("type") or "").lower()
    event_data = payload.get("data")
    if "semgrep_finding" in event_type and _looks_like_semgrep_finding(event_data):
        candidates.append(event_data)  # type: ignore[arg-type]

    if _looks_like_semgrep_finding(payload):
        candidates.append(payload)

    if isinstance(report_content, dict):
        report_semgrep_finding = _extract_nested_object(report_content, "semgrep_finding")
        if isinstance(report_semgrep_finding, dict):
            candidates.append({"semgrep_finding": report_semgrep_finding})

    return candidates


def _detect_sast_payload_type(payload: dict[str, Any], report_content: Any) -> str:
    if _extract_nested_object(payload, "semgrep_scan") is not None:
        return "semgrep_scan"
    event_type = str(payload.get("event_type") or payload.get("event") or payload.get("type") or "").lower()
    if "semgrep_scan" in event_type:
        return "semgrep_scan"
    if "semgrep_finding" in event_type:
        return "semgrep_finding"
    if _extract_semgrep_finding_candidates(payload, report_content):
        return "semgrep_finding"
    if isinstance(payload.get("results"), list):
        return "semgrep_results"
    if isinstance(payload.get("findings"), list):
        return "findings"
    return "unknown"


def _normalize_semgrep_severity(value: Any) -> str:
    mapped = {
        0: "Low",
        1: "Medium",
        2: "High",
        "0": "Low",
        "1": "Medium",
        "2": "High",
        "INFO": "Low",
        "WARNING": "Medium",
        "ERROR": "High",
        "CRITICAL": "Critical",
    }.get(value, value)
    if mapped is None:
        return "unknown"
    return str(mapped)


def _is_semgrep_test_notification(payload: dict[str, Any], findings: list[Any]) -> bool:
    candidates: list[Any] = []
    candidates.extend(findings)
    payload_findings = payload.get("findings")
    if isinstance(payload_findings, list):
        candidates.extend(payload_findings)
    if isinstance(payload.get("text"), str) or isinstance(payload.get("username"), str):
        candidates.append(payload)

    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        text = str(candidate.get("text") or candidate.get("message") or "").strip().lower()
        username = str(candidate.get("username") or "").strip().lower()
        if text == "test notification" and username == "semgrep":
            return True
    return False


def _normalize_semgrep_webhook_finding(finding: dict[str, Any]) -> dict[str, Any]:
    semgrep_finding = finding.get("semgrep_finding")
    if not isinstance(semgrep_finding, dict):
        if _looks_like_semgrep_finding(finding):
            semgrep_finding = finding
        else:
            nested_finding = finding.get("finding")
            if _looks_like_semgrep_finding(nested_finding):
                semgrep_finding = nested_finding  # type: ignore[assignment]
    if not isinstance(semgrep_finding, dict):
        return finding

    metadata = semgrep_finding.get("metadata") if isinstance(semgrep_finding.get("metadata"), dict) else {}
    cwe_value = metadata.get("cwe")
    if isinstance(cwe_value, list) and cwe_value:
        cwe = str(cwe_value[0]).split(":", 1)[0]
    elif cwe_value:
        cwe = str(cwe_value).split(":", 1)[0]
    else:
        cwe = ""

    severity_raw = semgrep_finding.get("severity")
    severity = _normalize_semgrep_severity(severity_raw)
    if not severity:
        severity = metadata.get("impact") or metadata.get("likelihood") or "unknown"

    line_value = semgrep_finding.get("line")
    if line_value in (None, ""):
        start_block = semgrep_finding.get("start")
        if isinstance(start_block, dict):
            line_value = start_block.get("line")

    return {
        "tool": "semgrep",
        "rule_id": semgrep_finding.get("check_id") or semgrep_finding.get("id") or "unknown",
        "check_id": semgrep_finding.get("check_id") or semgrep_finding.get("id") or "unknown",
        "id": semgrep_finding.get("id"),
        "cwe": cwe,
        "severity": severity,
        "file": semgrep_finding.get("path") or "",
        "path": semgrep_finding.get("path") or "",
        "line": line_value or "",
        "message": semgrep_finding.get("message") or "",
        "description": semgrep_finding.get("message") or "",
        "start": {"line": line_value or 0},
        "extra": {
            "message": semgrep_finding.get("message") or "",
            "severity": severity,
            "metadata": metadata,
        },
        "commit_hash": semgrep_finding.get("commit") or semgrep_finding.get("commit_hash"),
        "branch": semgrep_finding.get("ref"),
        "metadata": metadata,
        "raw_semgrep_finding": semgrep_finding,
    }


def _create_or_update_integration_config(
    db: Session,
    *,
    project_id: str,
    payload: schemas.IntegrationConfigCreate | schemas.IntegrationConfigUpdate,
    integration: models.IntegrationConfig | None = None,
) -> models.IntegrationConfig:
    now = _utcnow()
    if integration is None:
        integration = models.IntegrationConfig(
            id=str(uuid.uuid4()),
            project_id=project_id,
            integration_type=payload.integration_type,  # type: ignore[attr-defined]
            provider=payload.provider or "custom",  # type: ignore[attr-defined]
            phase_scope=payload.phase_scope,
            trigger_mode=payload.trigger_mode or "WEBHOOK",
            status=payload.status or "CONNECTED",
            config_json=payload.config_json or {},
            secret_hash=_hash_secret(payload.secret) if getattr(payload, "secret", None) else None,
            secret_ref=payload.secret_ref,
            last_success_at=None,
            last_error=None,
            created_at=now,
            updated_at=now,
        )
        db.add(integration)
        return integration

    data = payload.model_dump(exclude_unset=True)
    if "provider" in data:
        integration.provider = str(data["provider"])
    if "phase_scope" in data:
        integration.phase_scope = str(data["phase_scope"]) if data["phase_scope"] is not None else None
    if "trigger_mode" in data:
        integration.trigger_mode = str(data["trigger_mode"])
    if "status" in data:
        integration.status = str(data["status"])
    if "config_json" in data:
        new_config = data["config_json"] if isinstance(data["config_json"], dict) else {}
        existing_config = integration.config_json if isinstance(integration.config_json, dict) else {}
        if "access_token" not in new_config and existing_config.get("access_token"):
            new_config = dict(new_config)
            new_config["access_token"] = existing_config.get("access_token")
        integration.config_json = new_config
    if "secret_ref" in data:
        integration.secret_ref = str(data["secret_ref"]) if data["secret_ref"] is not None else None
    if "secret" in data and data["secret"]:
        integration.secret_hash = _hash_secret(str(data["secret"]))
    integration.updated_at = now
    return integration


def _record_non_analysis_integration_event(
    *,
    db: Session,
    integration: models.IntegrationConfig,
    project_id: str,
    payload: dict[str, Any],
    event_type: str,
    event_id: str | None,
    commit_hash: str | None,
    branch: str | None,
) -> models.IntegrationEvent:
    payload_hash = _hash_payload(payload)
    duplicate = _existing_duplicate_event(
        db,
        integration_id=integration.id,
        external_event_id=event_id,
        payload_hash=payload_hash,
    )
    if duplicate:
        return duplicate

    now = _utcnow()
    event = models.IntegrationEvent(
        id=str(uuid.uuid4()),
        integration_id=integration.id,
        project_id=project_id,
        event_type=event_type,
        external_event_id=event_id,
        payload_hash=payload_hash,
        payload_storage_key=None,
        raw_payload_json=payload,
        commit_hash=commit_hash,
        branch=branch,
        processing_status="accepted",
        error_message=None,
        created_at=now,
        processed_at=now,
        linked_version_id=None,
        linked_run_id=None,
    )
    db.add(event)
    integration.last_success_at = now
    integration.last_error = None
    integration.updated_at = now
    db.commit()
    return event


@router.get("/configs", response_model=list[schemas.IntegrationConfigOut])
def list_integration_configs(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    _get_project_for_owner(db, project_id, current_user.id)
    return (
        db.query(models.IntegrationConfig)
        .filter(models.IntegrationConfig.project_id == project_id)
        .order_by(models.IntegrationConfig.created_at.desc())
        .all()
    )


@router.post("/configs", response_model=schemas.IntegrationConfigOut, status_code=status.HTTP_201_CREATED)
def upsert_integration_config(
    project_id: str,
    payload: schemas.IntegrationConfigCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    _get_project_for_owner(db, project_id, current_user.id)
    existing = (
        db.query(models.IntegrationConfig)
        .filter(
            models.IntegrationConfig.project_id == project_id,
            models.IntegrationConfig.integration_type == payload.integration_type,
        )
        .first()
    )
    integration = _create_or_update_integration_config(
        db,
        project_id=project_id,
        payload=payload,
        integration=existing,
    )
    db.commit()
    db.refresh(integration)
    return integration


@router.patch("/configs/{integration_id}", response_model=schemas.IntegrationConfigOut)
def update_integration_config(
    project_id: str,
    integration_id: str,
    payload: schemas.IntegrationConfigUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    _get_project_for_owner(db, project_id, current_user.id)
    integration = (
        db.query(models.IntegrationConfig)
        .filter(
            models.IntegrationConfig.id == integration_id,
            models.IntegrationConfig.project_id == project_id,
        )
        .first()
    )
    if not integration:
        raise HTTPException(status_code=404, detail="Integration configuration not found")
    _create_or_update_integration_config(
        db,
        project_id=project_id,
        payload=payload,
        integration=integration,
    )
    db.commit()
    db.refresh(integration)
    return integration


def _handle_webhook_event(
    *,
    db: Session,
    project_id: str,
    integration_type: str,
    payload: dict[str, Any],
    x_integration_secret: str | None,
    phase: str,
    tag: str,
    event_type: str,
    event_id: str | None,
    commit_hash: str | None,
    branch: str | None,
    evidence_payload: dict[str, Any],
    auto_run_analysis: bool,
) -> schemas.IntegrationWebhookResponse:
    project = _get_project_or_404(db, project_id)
    owner = db.query(models.User).filter(models.User.id == project.owner_id).first() if project.owner_id else None
    integration = _get_integration_config(db, project_id=project_id, integration_type=integration_type)
    _assert_webhook_secret(x_integration_secret, integration.secret_hash)

    payload_hash = _hash_payload(payload)
    duplicate = _existing_duplicate_event(
        db,
        integration_id=integration.id,
        external_event_id=event_id,
        payload_hash=payload_hash,
    )
    if duplicate:
        return schemas.IntegrationWebhookResponse(
            status="ignored_duplicate",
            message="Duplicate webhook event ignored",
            project_id=project_id,
            version_id=duplicate.linked_version_id,
            event_id=duplicate.id,
            analysis_run_id=duplicate.linked_run_id,
            details={"integration_type": integration_type},
        )

    now = _utcnow()
    version = _create_new_version_for_event(
        db,
        project=project,
        integration_type=integration_type,
        commit_hash=commit_hash,
        branch=branch,
        external_event_id=event_id,
        context_details=evidence_payload,
    )
    _link_all_project_documents_to_version(db, project_id=project_id, version_id=version.id)

    evidence_document = _persist_evidence_document(
        db,
        project_id=project_id,
        version_id=version.id,
        phase=phase,
        tag=tag,
        doc_name=f"{integration_type.lower()}_{event_type.lower()}",
        payload=evidence_payload,
    )

    event = models.IntegrationEvent(
        id=str(uuid.uuid4()),
        integration_id=integration.id,
        project_id=project_id,
        event_type=event_type,
        external_event_id=event_id,
        payload_hash=payload_hash,
        payload_storage_key=evidence_document.storage_key,
        raw_payload_json=payload,
        commit_hash=commit_hash,
        branch=branch,
        processing_status="accepted",
        error_message=None,
        created_at=now,
        processed_at=None,
        linked_version_id=version.id,
        linked_run_id=None,
    )
    db.add(event)
    db.commit()

    analysis_result: dict[str, Any] | None = None
    linked_run_id: str | None = None
    if auto_run_analysis:
        orchestrator = AnalysisOrchestrator()
        analysis_result = orchestrator.run_full_analysis(
            db=db,
            project_id=project_id,
            version_id=version.id,
            phase=phase,
            methodology="STRIDE",
            persist_threats=True,
            trigger_type="integration",
        )
        linked_run_id = _find_linked_analysis_run_id(db, project_id=project_id, version_id=version.id)

    event.linked_run_id = linked_run_id
    event.processed_at = _utcnow()
    event.processing_status = "accepted"
    integration.last_success_at = _utcnow()
    integration.last_error = None
    integration.updated_at = _utcnow()
    db.commit()

    if analysis_result and analysis_result.get("status") == "ready":
        _emit_integration_email(
            integration=integration,
            owner_email=owner.email if owner else None,
            subject=f"ThreatGPT analysis completed ({integration_type})",
            body=f"Project {project_id}, version {version.id} analysis completed successfully.",
        )
    elif analysis_result:
        _emit_integration_email(
            integration=integration,
            owner_email=owner.email if owner else None,
            subject=f"ThreatGPT analysis needs attention ({integration_type})",
            body=(
                f"Project {project_id}, version {version.id} analysis returned status "
                f"{analysis_result.get('status')} with missing_fields={analysis_result.get('missing_fields', [])}."
            ),
        )

    details: dict[str, Any] = {
        "integration_type": integration_type,
        "event_type": event_type,
        "auto_run_analysis": auto_run_analysis,
    }
    if analysis_result is not None:
        details["analysis"] = {
            "status": analysis_result.get("status"),
            "parsing_status": analysis_result.get("parsing_status"),
            "generation_status": analysis_result.get("generation_status"),
            "graph_status": analysis_result.get("graph_status"),
            "scenario_status": analysis_result.get("scenario_status"),
            "saved_artifacts": analysis_result.get("saved_artifacts", {}),
        }

    return schemas.IntegrationWebhookResponse(
        status="accepted",
        message="Webhook processed successfully",
        project_id=project_id,
        version_id=version.id,
        event_id=event.id,
        analysis_run_id=linked_run_id,
        details=details,
    )


def _save_code_files_as_documents(
    db: Session,
    *,
    project_id: str,
    version_id: str,
    code_files: list[dict[str, Any]],
    commit_hash: str,
) -> list[str]:
    """Persist extracted code files as ProjectDocument records.

    Returns the list of created document IDs.
    """
    now = _utcnow()
    code_dir = UPLOAD_ROOT / project_id / "code"
    code_dir.mkdir(parents=True, exist_ok=True)

    incoming_paths = {
        str(code_file.get("relative_path", "")).strip()
        for code_file in code_files
        if str(code_file.get("relative_path", "")).strip()
    }
    if incoming_paths:
        project_code_marker = f"{project_id}\\code\\"
        existing_generated_docs = (
            db.query(models.ProjectDocument)
            .filter(models.ProjectDocument.project_id == project_id)
            .all()
        )
        for existing_doc in existing_generated_docs:
            storage_key = str(existing_doc.storage_key or "").replace("/", "\\").lower()
            linked_versions = existing_doc.linked_version_ids or []
            if (
                existing_doc.name in incoming_paths
                and version_id in linked_versions
                and project_code_marker.lower() in storage_key
            ):
                db.delete(existing_doc)
        db.flush()

    created_ids: list[str] = []
    for code_file in code_files:
        safe_name = f"{uuid.uuid4()}_{commit_hash[:8]}_{Path(code_file['filename']).name}"
        dest_path = code_dir / safe_name
        try:
            dest_path.write_text(code_file["content"], encoding="utf-8")
        except Exception:
            continue

        doc = models.ProjectDocument(
            id=str(uuid.uuid4()),
            project_id=project_id,
            name=code_file["relative_path"],
            type=code_file.get("mime_type", "text/plain"),
            size=code_file.get("size", dest_path.stat().st_size),
            tag=code_file.get("tag", "SAST"),
            phase="in-development",
            uploaded_at=now,
            storage_key=str(dest_path.relative_to(UPLOAD_ROOT)),
            linked_version_ids=[version_id],
            linked_threat_ids=[],
            created_at=now,
            updated_at=now,
        )
        db.add(doc)
        created_ids.append(doc.id)

    return created_ids


def _fetch_and_save_repository_code(
    db: Session,
    *,
    project_id: str,
    version_id: str,
    repo_url: str | None,
    branch: str,
    commit_hash: str,
    access_token: str | None,
) -> tuple[list[str], str | None]:
    if not repo_url:
        return [], "Repository URL is not configured"

    from ..git_service import (
        GitServiceError,
        extract_code_files,
        fetch_repository,
    )

    clone_dir = UPLOAD_ROOT / project_id / "code_clone"
    try:
        fetch_repository(repo_url, branch, clone_dir, access_token, commit_hash=commit_hash)
        code_files = extract_code_files(clone_dir)
        if not code_files:
            return [], "No extractable files found in repository"

        created_doc_ids = _save_code_files_as_documents(
            db,
            project_id=project_id,
            version_id=version_id,
            code_files=code_files,
            commit_hash=commit_hash,
        )
        db.commit()
        return created_doc_ids, None
    except GitServiceError as exc:
        return [], str(exc)
    except Exception as exc:
        return [], f"Unexpected error during code fetch: {exc}"


@router.post("/git/webhook", response_model=schemas.IntegrationWebhookResponse)
def git_webhook(
    project_id: str,
    payload: dict[str, Any],
    x_integration_secret: str | None = Header(default=None, alias="X-Integration-Secret"),
    x_github_delivery: str | None = Header(default=None, alias="X-GitHub-Delivery"),
    x_github_event: str | None = Header(default=None, alias="X-GitHub-Event"),
    integration_secret: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    # ── 1. Extract commit metadata ────────────────────────────────────────────
    event_id = payload.get("event_id") or payload.get("delivery_id") or payload.get("id") or x_github_delivery
    commit_hash = payload.get("commit_hash") or payload.get("after")
    branch = payload.get("branch") or _extract_branch_from_git_ref(payload.get("ref"))
    repository = payload.get("repository") if isinstance(payload.get("repository"), dict) else {}
    head_commit = payload.get("head_commit") if isinstance(payload.get("head_commit"), dict) else {}

    if not commit_hash:
        return schemas.IntegrationWebhookResponse(
            status="failed_validation",
            message="commit_hash is required",
            project_id=project_id,
            details={},
        )

    changed_files = (
        payload.get("changed_files")
        if isinstance(payload.get("changed_files"), list)
        else _extract_changed_files_from_github_push(payload)
    )

    # ── 2. Validate integration config and secret ─────────────────────────────
    integration = _get_integration_config(db, project_id=project_id, integration_type="GIT_WEBHOOK")
    _assert_webhook_secret(x_integration_secret or integration_secret, integration.secret_hash)
    integration_config = integration.config_json if isinstance(integration.config_json, dict) else {}
    auto_run_analysis = bool(integration_config.get("auto_run_analysis", False))

    # repo_url: prefer the one stored in integration config (supports private repos with token)
    # fallback to whatever GitHub sent in the push event
    repo_url: str | None = (
        integration_config.get("repo_url")
        or payload.get("repo_url")
        or repository.get("clone_url")
        or repository.get("html_url")
    )
    access_token: str | None = integration_config.get("access_token") or None
    tracked_branch: str = integration_config.get("branch") or branch or "main"

    # ── 3. Deduplicate ────────────────────────────────────────────────────────
    payload_hash = _hash_payload(payload)
    duplicate = _existing_duplicate_event(
        db,
        integration_id=integration.id,
        external_event_id=str(event_id) if event_id else None,
        payload_hash=payload_hash,
    )
    if duplicate:
        return schemas.IntegrationWebhookResponse(
            status="ignored_duplicate",
            message="Duplicate webhook event ignored",
            project_id=project_id,
            version_id=duplicate.linked_version_id,
            event_id=duplicate.id,
            analysis_run_id=duplicate.linked_run_id,
            details={"integration_type": "GIT_WEBHOOK"},
        )

    # ── 4. Create version — commit metadata only, NOT analysis evidence ───────
    # The context_snapshot records the git event for version history and change
    # tracking. The commit JSON is intentionally NOT saved as a ProjectDocument
    # so it is never fed to the parsing engine as analysis evidence.
    project = _get_project_or_404(db, project_id)
    owner = db.query(models.User).filter(models.User.id == project.owner_id).first() if project.owner_id else None

    commit_metadata: dict[str, Any] = {
        "commit_hash": str(commit_hash),
        "branch": str(branch) if branch else tracked_branch,
        "changed_files": changed_files,
        "commit_message": head_commit.get("message", ""),
        "author": (head_commit.get("author") or {}).get("name", ""),
        "repo_url": repo_url,
        "provider_event": x_github_event,
    }
    version = _create_new_version_for_event(
        db,
        project=project,
        integration_type="GIT_WEBHOOK",
        commit_hash=str(commit_hash),
        branch=str(branch) if branch else None,
        external_event_id=str(event_id) if event_id else None,
        context_details=commit_metadata,
    )

    # ── 5. Create IntegrationEvent record ─────────────────────────────────────
    now = _utcnow()
    event = models.IntegrationEvent(
        id=str(uuid.uuid4()),
        integration_id=integration.id,
        project_id=project_id,
        event_type="git_commit",
        external_event_id=str(event_id) if event_id else None,
        payload_hash=payload_hash,
        payload_storage_key=None,   # no evidence file — commit JSON is in context_snapshot
        raw_payload_json=payload,
        commit_hash=str(commit_hash),
        branch=str(branch) if branch else None,
        processing_status="accepted",
        error_message=None,
        created_at=now,
        processed_at=None,
        linked_version_id=version.id,
        linked_run_id=None,
    )
    db.add(event)
    db.commit()

    # ── 6. Fetch source code (always) then run analysis (if configured) ─────────
    # Fetching is done unconditionally so that even when auto_run_analysis=False,
    # the code documents are available for the user to trigger analysis manually.
    analysis_result: dict[str, Any] | None = None
    linked_run_id: str | None = None

    _created_doc_ids, code_fetch_error = _fetch_and_save_repository_code(
        db,
        project_id=project_id,
        version_id=version.id,
        repo_url=repo_url,
        branch=tracked_branch,
        commit_hash=str(commit_hash),
        access_token=access_token,
    )
    if code_fetch_error:
        event.error_message = f"code_fetch: {code_fetch_error}"
    db.commit()

    # Link all current project documents (manual uploads + newly fetched code)
    _link_all_project_documents_to_version(db, project_id=project_id, version_id=version.id)

    if auto_run_analysis:
        # Run full analysis — parsing engine now sees source code, not commit metadata
        orchestrator = AnalysisOrchestrator()
        analysis_result = orchestrator.run_full_analysis(
            db=db,
            project_id=project_id,
            version_id=version.id,
            phase=PHASE_BY_INTEGRATION["GIT_WEBHOOK"],
            methodology="STRIDE",
            persist_threats=True,
            trigger_type="integration",
        )
        linked_run_id = _find_linked_analysis_run_id(db, project_id=project_id, version_id=version.id)

    event.linked_run_id = linked_run_id
    event.processed_at = _utcnow()
    integration.last_success_at = _utcnow()
    integration.last_error = code_fetch_error
    integration.updated_at = _utcnow()
    db.commit()

    if analysis_result and analysis_result.get("status") == "ready":
        _emit_integration_email(
            integration=integration,
            owner_email=owner.email if owner else None,
            subject=f"ThreatGPT analysis completed (GIT_WEBHOOK)",
            body=(
                f"Project {project_id}, version {version.id} analysis completed. "
                f"Commit: {commit_hash}  Branch: {tracked_branch}"
            ),
        )
    elif analysis_result:
        _emit_integration_email(
            integration=integration,
            owner_email=owner.email if owner else None,
            subject=f"ThreatGPT analysis needs attention (GIT_WEBHOOK)",
            body=(
                f"Project {project_id}, version {version.id} returned status "
                f"{analysis_result.get('status')}. "
                f"missing_fields={analysis_result.get('missing_fields', [])}. "
                + (f"Code fetch error: {code_fetch_error}" if code_fetch_error else "")
            ),
        )

    details: dict[str, Any] = {
        "integration_type": "GIT_WEBHOOK",
        "event_type": "git_commit",
        "commit_hash": str(commit_hash),
        "branch": tracked_branch,
        "auto_run_analysis": auto_run_analysis,
        "repo_url_configured": bool(repo_url),
        "code_documents_created": len(_created_doc_ids),
        "code_fetch_error": code_fetch_error,
    }
    if analysis_result is not None:
        details["analysis"] = {
            "status": analysis_result.get("status"),
            "parsing_status": analysis_result.get("parsing_status"),
            "generation_status": analysis_result.get("generation_status"),
            "graph_status": analysis_result.get("graph_status"),
            "scenario_status": analysis_result.get("scenario_status"),
            "saved_artifacts": analysis_result.get("saved_artifacts", {}),
        }

    return schemas.IntegrationWebhookResponse(
        status="accepted",
        message="Git webhook processed successfully",
        project_id=project_id,
        version_id=version.id,
        event_id=event.id,
        analysis_run_id=linked_run_id,
        details=details,
    )


@router.post("/sast/webhook", response_model=schemas.IntegrationWebhookResponse)
async def sast_webhook(
    project_id: str,
    request: Request,
    x_integration_secret: str | None = Header(default=None, alias="X-Integration-Secret"),
    integration_secret: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    try:
        raw_payload = await request.json()
    except Exception:
        raw_payload = {}
    if isinstance(raw_payload, dict):
        payload = raw_payload
    elif isinstance(raw_payload, list):
        payload = {"findings": raw_payload}
    else:
        payload = {"raw_payload": raw_payload}

    run_id = payload.get("run_id")
    commit_hash = payload.get("commit_hash")
    branch = payload.get("branch")
    tool_name = payload.get("tool_name") or "unknown"
    report_format = (payload.get("report_format") or "json").lower()
    report_content = payload.get("report_content")
    report_url = payload.get("report_url")
    payload_type = _detect_sast_payload_type(payload, report_content)
    semgrep_scan = _extract_nested_object(payload, "semgrep_scan") or {}
    if not run_id and isinstance(semgrep_scan, dict):
        run_id = semgrep_scan.get("id") or semgrep_scan.get("scan_id")
    if not commit_hash and isinstance(semgrep_scan, dict):
        commit_hash = semgrep_scan.get("commit") or semgrep_scan.get("commit_hash")
    if not branch and isinstance(semgrep_scan, dict):
        branch = semgrep_scan.get("branch") or semgrep_scan.get("ref")
    if payload_type.startswith("semgrep"):
        tool_name = payload.get("tool_name") or "semgrep"

    findings, findings_error = _extract_sast_findings(payload, report_content)
    if (not commit_hash or not branch) and findings:
        first_finding = findings[0] if isinstance(findings[0], dict) else {}
        if not commit_hash and isinstance(first_finding, dict):
            commit_hash = first_finding.get("commit_hash")
        if not branch and isinstance(first_finding, dict):
            branch = first_finding.get("branch")

    auth_secret = x_integration_secret or integration_secret

    logger.info(
        "SAST webhook payload_type=%s run_id=%s commit_hash=%s branch=%s findings_count=%s",
        payload_type,
        run_id,
        commit_hash,
        branch,
        len(findings),
    )
    if findings and isinstance(findings[0], dict):
        first = findings[0]
        logger.info(
            "SAST webhook extracted finding rule_id=%s path=%s line=%s severity=%s",
            first.get("rule_id") or first.get("check_id"),
            first.get("path") or first.get("file"),
            first.get("line"),
            first.get("severity"),
        )

    if report_content is None and not report_url and not findings and not isinstance(payload.get("results"), list):
        integration = _get_integration_config(db, project_id=project_id, integration_type="SAST_WEBHOOK")
        _assert_webhook_secret(auth_secret, integration.secret_hash)
        message = "SAST webhook connectivity verified; no findings supplied"
        event_type = "connectivity_check"
        if payload_type == "semgrep_scan":
            message = "Semgrep scan metadata received; awaiting finding events"
            event_type = "semgrep_scan"
        event = _record_non_analysis_integration_event(
            db=db,
            integration=integration,
            project_id=project_id,
            payload=payload,
            event_type=event_type,
            event_id=str(payload.get("event_id") or run_id) if (payload.get("event_id") or run_id) else None,
            commit_hash=str(commit_hash) if commit_hash else None,
            branch=str(branch) if branch else None,
        )
        project = _get_project_or_404(db, project_id)
        owner = db.query(models.User).filter(models.User.id == project.owner_id).first() if project.owner_id else None
        _emit_integration_email(
            integration=integration,
            owner_email=owner.email if owner else None,
            subject="ThreatGPT Semgrep update received",
            body=(
                f"Project {project_id} received a Semgrep webhook update. "
                f"event_type={event_type}, payload_type={payload_type}, event_id={event.id}."
            ),
        )
        return schemas.IntegrationWebhookResponse(
            status="accepted",
            message=message,
            project_id=project_id,
            event_id=event.id,
            details={"integration_type": "SAST_WEBHOOK", "event_type": event_type, "payload_type": payload_type},
        )
    if _is_semgrep_test_notification(payload, findings):
        integration = _get_integration_config(db, project_id=project_id, integration_type="SAST_WEBHOOK")
        _assert_webhook_secret(auth_secret, integration.secret_hash)
        event = _record_non_analysis_integration_event(
            db=db,
            integration=integration,
            project_id=project_id,
            payload=payload,
            event_type="connectivity_check",
            event_id=str(payload.get("event_id") or run_id) if (payload.get("event_id") or run_id) else None,
            commit_hash=str(commit_hash) if commit_hash else None,
            branch=str(branch) if branch else None,
        )
        project = _get_project_or_404(db, project_id)
        owner = db.query(models.User).filter(models.User.id == project.owner_id).first() if project.owner_id else None
        _emit_integration_email(
            integration=integration,
            owner_email=owner.email if owner else None,
            subject="ThreatGPT Semgrep test notification received",
            body=(
                f"Project {project_id} received a Semgrep test notification. "
                f"payload_type={payload_type}, event_id={event.id}."
            ),
        )
        return schemas.IntegrationWebhookResponse(
            status="accepted",
            message="Semgrep test notification verified; no analysis was triggered",
            project_id=project_id,
            event_id=event.id,
            details={"integration_type": "SAST_WEBHOOK", "event_type": "connectivity_check", "payload_type": payload_type},
        )
    if findings_error:
        return schemas.IntegrationWebhookResponse(
            status="failed_validation",
            message=findings_error,
            project_id=project_id,
            details={},
        )

    evidence_payload = {
        "integration_type": "SAST_WEBHOOK",
        "tool_name": tool_name,
        "report_format": report_format,
        "commit_hash": commit_hash,
        "branch": branch,
        "run_id": run_id,
        "report_url": report_url,
        "report_content": report_content,
        "security_findings": {
            "sast": findings,
            "dast": [],
            "sca": [],
            "infrastructure": [],
            "manual_review": [],
        },
        "raw_event": payload,
    }

    return _handle_webhook_event(
        db=db,
        project_id=project_id,
        integration_type="SAST_WEBHOOK",
        payload=payload,
        x_integration_secret=auth_secret,
        phase=PHASE_BY_INTEGRATION["SAST_WEBHOOK"],
        tag="sast",
        event_type="sast_report",
        event_id=str(payload.get("event_id") or run_id) if (payload.get("event_id") or run_id) else None,
        commit_hash=str(commit_hash) if commit_hash else None,
        branch=str(branch) if branch else None,
        evidence_payload=evidence_payload,
        auto_run_analysis=True,
    )


@router.post("/dast/webhook", response_model=schemas.IntegrationWebhookResponse)
def dast_webhook(
    project_id: str,
    payload: dict[str, Any],
    x_integration_secret: str | None = Header(default=None, alias="X-Integration-Secret"),
    db: Session = Depends(get_db),
):
    run_id = payload.get("run_id")
    target_url = payload.get("target_url")
    tool_name = payload.get("tool_name") or "unknown"
    report_format = (payload.get("report_format") or "json").lower()
    report_content = payload.get("report_content")
    report_url = payload.get("report_url")
    findings = payload.get("findings", [])

    if not run_id and not payload.get("event_id"):
        return schemas.IntegrationWebhookResponse(
            status="failed_validation",
            message="run_id or event_id is required",
            project_id=project_id,
            details={},
        )
    if report_content is None and not report_url and not findings:
        return schemas.IntegrationWebhookResponse(
            status="failed_validation",
            message="report_content, report_url, or findings is required",
            project_id=project_id,
            details={},
        )
    if findings and not isinstance(findings, list):
        return schemas.IntegrationWebhookResponse(
            status="failed_validation",
            message="findings must be a list",
            project_id=project_id,
            details={},
        )

    normalized_findings = findings if isinstance(findings, list) else []
    evidence_payload = {
        "integration_type": "DAST_WEBHOOK",
        "tool_name": tool_name,
        "report_format": report_format,
        "run_id": run_id,
        "target_url": target_url,
        "report_url": report_url,
        "report_content": report_content,
        "security_findings": {
            "sast": [],
            "dast": normalized_findings,
            "sca": [],
            "infrastructure": [],
            "manual_review": [],
        },
        "raw_event": payload,
    }

    return _handle_webhook_event(
        db=db,
        project_id=project_id,
        integration_type="DAST_WEBHOOK",
        payload=payload,
        x_integration_secret=x_integration_secret,
        phase=PHASE_BY_INTEGRATION["DAST_WEBHOOK"],
        tag="dast",
        event_type="dast_report",
        event_id=str(payload.get("event_id") or run_id) if (payload.get("event_id") or run_id) else None,
        commit_hash=str(payload.get("commit_hash")) if payload.get("commit_hash") else None,
        branch=str(payload.get("branch")) if payload.get("branch") else None,
        evidence_payload=evidence_payload,
        auto_run_analysis=True,
    )


@router.get("/events", response_model=list[schemas.IntegrationEventOut])
def list_integration_events(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    _get_project_for_owner(db, project_id, current_user.id)
    return (
        db.query(models.IntegrationEvent)
        .filter(models.IntegrationEvent.project_id == project_id)
        .order_by(models.IntegrationEvent.created_at.desc())
        .all()
    )


@router.post("/events/{event_id}/run-analysis", response_model=schemas.IntegrationWebhookResponse)
def run_analysis_for_integration_event(
    project_id: str,
    event_id: str,
    payload: schemas.RunAnalysisRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    _get_project_for_owner(db, project_id, current_user.id)
    event = (
        db.query(models.IntegrationEvent)
        .filter(models.IntegrationEvent.id == event_id, models.IntegrationEvent.project_id == project_id)
        .first()
    )
    if not event:
        raise HTTPException(status_code=404, detail="Integration event not found")
    if not event.linked_version_id:
        raise HTTPException(status_code=400, detail="Integration event is not linked to a version")
    if event.linked_run_id:
        return schemas.IntegrationWebhookResponse(
            status="ignored_duplicate",
            message="Analysis has already been started for this event",
            project_id=project_id,
            version_id=event.linked_version_id,
            event_id=event.id,
            analysis_run_id=event.linked_run_id,
            details={"integration_type": event.event_type},
        )

    code_fetch_error: str | None = None
    created_doc_ids: list[str] = []
    integration = db.query(models.IntegrationConfig).filter(models.IntegrationConfig.id == event.integration_id).first()
    if event.event_type == "git_commit" and integration:
        integration_config = integration.config_json if isinstance(integration.config_json, dict) else {}
        event_context = event.raw_payload_json if isinstance(event.raw_payload_json, dict) else {}
        repository = event_context.get("repository") if isinstance(event_context.get("repository"), dict) else {}
        repo_url = (
            integration_config.get("repo_url")
            or event_context.get("repo_url")
            or repository.get("clone_url")
            or repository.get("html_url")
        )
        branch = integration_config.get("branch") or event.branch or "main"
        commit_hash = event.commit_hash or event_context.get("after")
        if commit_hash:
            created_doc_ids, code_fetch_error = _fetch_and_save_repository_code(
                db,
                project_id=project_id,
                version_id=event.linked_version_id,
                repo_url=repo_url,
                branch=str(branch),
                commit_hash=str(commit_hash),
                access_token=integration_config.get("access_token") or None,
            )
            if code_fetch_error:
                event.error_message = f"code_fetch: {code_fetch_error}"
                if integration:
                    integration.last_error = code_fetch_error
                db.commit()

    _link_all_project_documents_to_version(db, project_id=project_id, version_id=event.linked_version_id)

    orchestrator = AnalysisOrchestrator()
    analysis_result = orchestrator.run_full_analysis(
        db=db,
        project_id=project_id,
        version_id=event.linked_version_id,
        phase=payload.phase,
        methodology=payload.methodology,
        persist_threats=payload.persist_threats,
        trigger_type="integration_manual",
    )
    linked_run_id = _find_linked_analysis_run_id(db, project_id=project_id, version_id=event.linked_version_id)
    event.linked_run_id = linked_run_id
    event.processed_at = _utcnow()
    event.processing_status = "accepted"
    db.commit()

    return schemas.IntegrationWebhookResponse(
        status="accepted",
        message="Analysis started for integration event",
        project_id=project_id,
        version_id=event.linked_version_id,
        event_id=event.id,
        analysis_run_id=linked_run_id,
        details={
            "integration_type": event.event_type,
            "code_documents_created": len(created_doc_ids),
            "code_fetch_error": code_fetch_error,
            "analysis": {
                "status": analysis_result.get("status"),
                "parsing_status": analysis_result.get("parsing_status"),
                "generation_status": analysis_result.get("generation_status"),
                "graph_status": analysis_result.get("graph_status"),
                "scenario_status": analysis_result.get("scenario_status"),
                "saved_artifacts": analysis_result.get("saved_artifacts", {}),
            },
        },
    )


# TODO: Add async/background processing for webhook-triggered analysis runs.
# TODO: Add email template support for richer integration notifications.
# TODO: Add integration dashboard/reporting API with aggregate event health.
