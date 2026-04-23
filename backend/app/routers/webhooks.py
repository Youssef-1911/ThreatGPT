import datetime as dt
import os
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from .. import models
from ..database import SessionLocal
from ..versioning_service import create_project_version

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "dev-webhook-secret")

PHASE_TO_STAGE = {
    "pre-development": "Design",
    "in-development": "Development",
    "testing": "Testing",
}

SOURCE_TO_STAGE = {
    "Architecture": "Design",
    "Git": "Development",
    "SAST": "Development",
    "DAST": "Testing",
    "Pentest": "Testing",
}


def infer_identified_stage(identified_in_phase: str | None, source: str | None) -> str:
    if source in SOURCE_TO_STAGE:
        return SOURCE_TO_STAGE[source]  # type: ignore[index]
    if identified_in_phase in PHASE_TO_STAGE:
        return PHASE_TO_STAGE[identified_in_phase]  # type: ignore[index]
    return "Design"


def require_secret(secret: str | None) -> None:
    if not secret or secret != WEBHOOK_SECRET:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid webhook secret")


def get_project_or_404(db: Session, project_id: str) -> models.Project:
    project = db.query(models.Project).filter(models.Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def create_version(
    db: Session,
    project: models.Project,
    *,
    created_by: str,
    context_snapshot: dict[str, Any],
    threat_ids: list[str],
    mitigation_ids: list[str],
    notes: str,
) -> models.ProjectVersion:
    return create_project_version(
        db,
        project=project,
        created_by=created_by,
        context_snapshot=context_snapshot,
        notes=notes,
        threat_ids=threat_ids,
        mitigation_ids=mitigation_ids,
    )


def capture_version_snapshots(
    db: Session,
    *,
    project_id: str,
    version_id: str,
    threat_ids: list[str] | None,
    mitigation_ids: list[str] | None,
) -> None:
    threat_ids_set = set(threat_ids or [])
    mitigation_ids_set = set(mitigation_ids or [])
    now = dt.datetime.utcnow()

    db.query(models.ThreatSnapshot).filter(models.ThreatSnapshot.version_id == version_id).delete()
    db.query(models.MitigationSnapshot).filter(models.MitigationSnapshot.version_id == version_id).delete()

    if threat_ids_set:
        threats = (
            db.query(models.Threat)
            .filter(models.Threat.project_id == project_id, models.Threat.id.in_(list(threat_ids_set)))
            .all()
        )
        for threat in threats:
            db.add(
                models.ThreatSnapshot(
                    id=str(uuid.uuid4()),
                    version_id=version_id,
                    project_id=project_id,
                    threat_id=threat.id,
                    name=threat.name,
                    severity=threat.severity,
                    status=threat.status,
                    risk_score=threat.risk_score,
                    affected_component=threat.affected_component,
                    identified_stage=threat.identified_stage,
                    source=threat.source,
                    created_at=now,
                )
            )

    if mitigation_ids_set:
        mitigations = (
            db.query(models.Mitigation)
            .filter(models.Mitigation.project_id == project_id, models.Mitigation.id.in_(list(mitigation_ids_set)))
            .all()
        )
        for mitigation in mitigations:
            db.add(
                models.MitigationSnapshot(
                    id=str(uuid.uuid4()),
                    version_id=version_id,
                    project_id=project_id,
                    mitigation_id=mitigation.id,
                    title=mitigation.title,
                    description=mitigation.description,
                    status=mitigation.status,
                    priority=mitigation.priority,
                    type=mitigation.type,
                    assignee=mitigation.assignee,
                    due_date=mitigation.due_date,
                    created_at=now,
                )
            )


def create_threats_from_findings(
    db: Session,
    project: models.Project,
    findings: list[dict[str, Any]],
    *,
    source: str,
    identified_in_phase: str | None,
    version_id: str | None,
) -> list[models.Threat]:
    now = dt.datetime.utcnow()
    created: list[models.Threat] = []
    for finding in findings:
        name = finding.get("name") or finding.get("title") or "Security Finding"
        severity = finding.get("severity") or "Medium"
        description = finding.get("description") or ""
        category = finding.get("category") or "Custom"
        affected_component = finding.get("affected_component") or finding.get("component") or "Unknown"
        likelihood = finding.get("likelihood")
        impact = finding.get("impact")
        risk_score = finding.get("risk_score")
        if risk_score is None and isinstance(likelihood, (int, float)) and isinstance(impact, (int, float)):
            risk_score = float(likelihood) * float(impact)

        stage = infer_identified_stage(identified_in_phase, source)

        threat = models.Threat(
            id=str(uuid.uuid4()),
            project_id=project.id,
            name=name,
            description=description,
            category=category,
            severity=severity,
            likelihood=likelihood,
            impact=impact,
            risk_score=risk_score,
            status="Identified",
            affected_component=affected_component,
            identified_stage=stage,
            source=source,
            commit_hash=finding.get("commit_hash"),
            introduced_in=None,
            identified_in_phase=identified_in_phase,
            introduced_in_version_id=version_id,
            accepted_risk_info=None,
            events=[
                {
                    "id": f"{uuid.uuid4()}",
                    "threatId": "",
                    "type": "created",
                    "versionId": version_id,
                    "timestamp": now.isoformat(),
                    "details": "Threat created from webhook finding",
                }
            ],
            created_at=now,
            updated_at=now,
        )
        db.add(threat)
        created.append(threat)

    for threat in created:
        if threat.events and isinstance(threat.events, list):
            threat.events[0]["threatId"] = threat.id

    return created


@router.post("/github")
def github_webhook(
    payload: dict,
    x_webhook_secret: str | None = Header(default=None, alias="X-Webhook-Secret"),
):
    require_secret(x_webhook_secret)
    project_id = payload.get("project_id")
    if not project_id:
        raise HTTPException(status_code=422, detail="project_id is required")

    db: Session = SessionLocal()
    try:
        project = get_project_or_404(db, project_id)
        commits = payload.get("commits") or []
        head_commit = payload.get("head_commit") or {}
        notes = f"GitHub webhook: {head_commit.get('message', 'New commit')}"
        context_snapshot = {
            "gitEvent": {
                "ref": payload.get("ref"),
                "head_commit": head_commit,
                "commit_count": len(commits),
                "repository": payload.get("repository", {}),
            }
        }
        version = create_version(
            db,
            project,
            created_by="GitHub",
            context_snapshot=context_snapshot,
            threat_ids=[t.id for t in project.threats],
            mitigation_ids=[m.id for m in project.mitigations],
            notes=notes,
        )
        capture_version_snapshots(
            db,
            project_id=project.id,
            version_id=version.id,
            threat_ids=version.threat_ids or [],
            mitigation_ids=version.mitigation_ids or [],
        )
        db.commit()
        return {"status": "ok"}
    finally:
        db.close()


@router.post("/security-findings")
def security_findings_webhook(
    payload: dict,
    x_webhook_secret: str | None = Header(default=None, alias="X-Webhook-Secret"),
):
    require_secret(x_webhook_secret)
    project_id = payload.get("project_id")
    if not project_id:
        raise HTTPException(status_code=422, detail="project_id is required")

    source = payload.get("source") or "SAST"
    if source not in ("SAST", "DAST", "Pentest", "Manual"):
        source = "SAST"

    identified_in_phase = payload.get("identified_in_phase") or None
    findings = payload.get("findings") or []
    if not isinstance(findings, list):
        raise HTTPException(status_code=422, detail="findings must be a list")

    db: Session = SessionLocal()
    try:
        project = get_project_or_404(db, project_id)
        version = create_version(
            db,
            project,
            created_by=source,
            context_snapshot={
                "securityFindings": {
                    "source": source,
                    "count": len(findings),
                }
            },
            threat_ids=[t.id for t in project.threats],
            mitigation_ids=[m.id for m in project.mitigations],
            notes=f"{source} webhook ingest",
        )
        created = create_threats_from_findings(
            db,
            project,
            findings,
            source=source,
            identified_in_phase=identified_in_phase,
            version_id=version.id,
        )
        version.threat_ids = (version.threat_ids or []) + [t.id for t in created]
        capture_version_snapshots(
            db,
            project_id=project.id,
            version_id=version.id,
            threat_ids=version.threat_ids or [],
            mitigation_ids=version.mitigation_ids or [],
        )
        db.commit()
        return {"status": "ok", "created_threats": len(created), "version_id": version.id}
    finally:
        db.close()
