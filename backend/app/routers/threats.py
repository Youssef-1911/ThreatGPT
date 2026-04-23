import datetime as dt
import uuid
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from .. import models, schemas
from ..deps import get_db, get_current_user

router = APIRouter(prefix="/projects/{project_id}/threats", tags=["threats"])

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


def normalize_threat_status(status_value: str | None) -> str | None:
    if status_value is None:
        return None
    mapping = {
        "Open": "Identified",
        "In Progress": "In Review",
        "Identified": "Identified",
        "In Review": "In Review",
        "Mitigated": "Mitigated",
        "Accepted": "Accepted",
    }
    return mapping.get(status_value, status_value)


def _normalize_score_1_to_5(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        numeric = int(round(float(value)))
    elif isinstance(value, str):
        try:
            numeric = int(round(float(value.strip())))
        except (TypeError, ValueError):
            return None
    else:
        return None
    return max(1, min(5, numeric))


def _resolve_risk_score(
    likelihood_value: Any,
    impact_value: Any,
    provided_risk_score: Any,
) -> tuple[int | None, int | None, float | None]:
    likelihood = _normalize_score_1_to_5(likelihood_value)
    impact = _normalize_score_1_to_5(impact_value)
    if likelihood is not None and impact is not None:
        return likelihood, impact, float(likelihood * impact)
    if isinstance(provided_risk_score, (int, float)):
        return likelihood, impact, float(provided_risk_score)
    return likelihood, impact, None


def infer_identified_stage(identified_in_phase: str | None, source: str | None) -> str:
    if source in SOURCE_TO_STAGE:
        return SOURCE_TO_STAGE[source]  # type: ignore[index]
    if identified_in_phase in PHASE_TO_STAGE:
        return PHASE_TO_STAGE[identified_in_phase]  # type: ignore[index]
    return "Design"


def get_project_or_404(db: Session, project_id: str, user_id: str) -> models.Project:
    project = (
        db.query(models.Project)
        .filter(
            models.Project.id == project_id,
            models.Project.owner_id == user_id,
        )
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project

def get_threat_or_404(db: Session, project_id: str, threat_id: str) -> models.Threat:
    threat = (
        db.query(models.Threat)
        .filter(models.Threat.id == threat_id, models.Threat.project_id == project_id)
        .first()
    )
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return threat


def _normalize_phase_key(phase_value: str | None) -> str:
    if not isinstance(phase_value, str):
        return "unknown"
    normalized = phase_value.strip().lower().replace(" ", "-").replace("_", "-")
    return normalized or "unknown"


def _threat_to_board_item(threat: models.Threat) -> dict[str, Any]:
    inferred_stage = infer_identified_stage(threat.identified_in_phase, threat.source)
    identified_stage = threat.identified_stage
    if not identified_stage or (identified_stage == "Design" and inferred_stage != "Design"):
        identified_stage = inferred_stage
    return {
        "id": threat.id,
        "name": threat.name,
        "severity": threat.severity,
        "status": threat.status,
        "identified_in_phase": threat.identified_in_phase,
        "identified_stage": identified_stage,
        "introduced_in_version_id": threat.introduced_in_version_id,
        "affected_component": threat.affected_component,
        "source": threat.source,
    }


def _threats_for_version(
    db: Session,
    *,
    project_id: str,
    version: models.ProjectVersion | None,
) -> list[models.Threat]:
    if not version:
        return []
    threat_ids = [str(item) for item in (version.threat_ids or []) if isinstance(item, str)]
    if threat_ids:
        threats_by_id = {
            threat.id: threat
            for threat in db.query(models.Threat)
            .filter(models.Threat.project_id == project_id, models.Threat.id.in_(threat_ids))
            .all()
        }
        return [threats_by_id[threat_id] for threat_id in threat_ids if threat_id in threats_by_id]
    return (
        db.query(models.Threat)
        .filter(
            models.Threat.project_id == project_id,
            models.Threat.introduced_in_version_id == version.id,
        )
        .order_by(models.Threat.created_at.desc())
        .all()
    )


@router.get("", response_model=list[schemas.ThreatOut])
def list_threats(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    get_project_or_404(db, project_id, current_user.id)
    return db.query(models.Threat).filter(models.Threat.project_id == project_id).all()


@router.get("/sdlc-board")
def get_sdlc_board(
    project_id: str,
    scope: str = Query("current"),
    version_id: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    project = get_project_or_404(db, project_id, current_user.id)
    normalized_scope = scope.strip().lower()
    if normalized_scope not in {"current", "all", "version"}:
        raise HTTPException(status_code=422, detail="scope must be one of: current, all, version")

    effective_version_id: str | None = None
    threats: list[models.Threat]
    if normalized_scope == "current":
        effective_version_id = project.current_version_id
        if effective_version_id:
            version = (
                db.query(models.ProjectVersion)
                .filter(models.ProjectVersion.id == effective_version_id, models.ProjectVersion.project_id == project_id)
                .first()
            )
            threats = _threats_for_version(db, project_id=project_id, version=version)
        else:
            threats = []
    elif normalized_scope == "version":
        if not version_id:
            raise HTTPException(status_code=422, detail="version_id is required when scope=version")
        version = (
            db.query(models.ProjectVersion)
            .filter(models.ProjectVersion.id == version_id, models.ProjectVersion.project_id == project_id)
            .first()
        )
        if not version:
            raise HTTPException(status_code=404, detail="Version not found")
        effective_version_id = version.id
        threats = _threats_for_version(db, project_id=project_id, version=version)
    else:
        threats = (
            db.query(models.Threat)
            .filter(models.Threat.project_id == project_id)
            .order_by(models.Threat.created_at.desc())
            .all()
        )
    grouped: dict[str, list[dict[str, Any]]] = {}
    for threat in threats:
        phase_key = _normalize_phase_key(threat.identified_in_phase or project.current_phase)
        grouped.setdefault(phase_key, [])
        grouped[phase_key].append(_threat_to_board_item(threat))

    configured_phases = []
    if isinstance(project.sdlc_phases, list):
        configured_phases = [_normalize_phase_key(str(phase)) for phase in project.sdlc_phases]
    discovered_phases = [phase for phase in sorted(grouped.keys()) if phase not in configured_phases]
    ordered_phases = configured_phases + discovered_phases

    columns = [
        {
            "phase": phase,
            "threats": grouped.get(phase, []),
            "count": len(grouped.get(phase, [])),
        }
        for phase in ordered_phases
    ]

    return {
        "project_id": project_id,
        "scope": normalized_scope,
        "version_id": effective_version_id,
        "columns": columns,
        "summary": {
            "total_threats": len(threats),
            "phase_count": len(columns),
        },
    }


@router.post("", response_model=schemas.ThreatOut, status_code=status.HTTP_201_CREATED)
def create_threat(
    project_id: str,
    payload: schemas.ThreatCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    project = get_project_or_404(db, project_id, current_user.id)
    if not payload.name:
        raise HTTPException(status_code=422, detail="Threat name is required")

    now = dt.datetime.utcnow()
    identified_in_phase = payload.identified_in_phase or project.current_phase
    identified_stage = payload.identified_stage or infer_identified_stage(identified_in_phase, payload.source)
    events = payload.events if payload.events is not None else [
        {
            "id": f"{uuid.uuid4()}",
            "threatId": "",
            "type": "created",
            "versionId": payload.introduced_in_version_id or payload.introduced_in,
            "timestamp": now.isoformat(),
            "details": "Threat created",
        }
    ]
    normalized_status = normalize_threat_status(payload.status) or "Identified"
    resolved_likelihood, resolved_impact, resolved_risk_score = _resolve_risk_score(
        payload.likelihood,
        payload.impact,
        payload.risk_score,
    )
    threat = models.Threat(
        id=str(uuid.uuid4()),
        project_id=project_id,
        name=payload.name,
        description=payload.description,
        category=payload.category,
        severity=payload.severity,
        likelihood=resolved_likelihood,
        impact=resolved_impact,
        risk_score=resolved_risk_score,
        status=normalized_status,
        affected_component=payload.affected_component,
        identified_stage=identified_stage,
        source=payload.source,
        commit_hash=payload.commit_hash,
        introduced_in=payload.introduced_in,
        identified_in_phase=identified_in_phase,
        introduced_in_version_id=payload.introduced_in_version_id,
        accepted_risk_info=payload.accepted_risk_info,
        events=events,
        created_at=now,
        updated_at=now,
    )
    if threat.events and isinstance(threat.events, list) and len(threat.events) > 0:
        threat.events[0]["threatId"] = threat.id
    db.add(threat)
    db.commit()
    db.refresh(threat)
    return threat

@router.get("/{threat_id}", response_model=schemas.ThreatOut)
def get_threat(
    project_id: str,
    threat_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    get_project_or_404(db, project_id, current_user.id)
    return get_threat_or_404(db, project_id, threat_id)

@router.patch("/{threat_id}", response_model=schemas.ThreatOut)
def update_threat(
    project_id: str,
    threat_id: str,
    payload: schemas.ThreatUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    get_project_or_404(db, project_id, current_user.id)
    threat = get_threat_or_404(db, project_id, threat_id)
    data = payload.model_dump(exclude_unset=True)
    if "status" in data:
        data["status"] = normalize_threat_status(data["status"])
    resolved_likelihood, resolved_impact, resolved_risk_score = _resolve_risk_score(
        data.get("likelihood", threat.likelihood),
        data.get("impact", threat.impact),
        data.get("risk_score", threat.risk_score),
    )
    if resolved_likelihood is not None:
        data["likelihood"] = resolved_likelihood
    if resolved_impact is not None:
        data["impact"] = resolved_impact
    if resolved_risk_score is not None:
        data["risk_score"] = resolved_risk_score
    for key, value in data.items():
        setattr(threat, key, value)
    threat.updated_at = dt.datetime.utcnow()
    if not threat.events:
        threat.events = []
    if isinstance(threat.events, list):
        threat.events.append(
            {
                "id": f"{uuid.uuid4()}",
                "threatId": threat.id,
                "type": "updated",
                "versionId": threat.introduced_in_version_id or threat.introduced_in,
                "timestamp": threat.updated_at.isoformat(),
                "details": "Threat updated",
            }
        )
    db.commit()
    db.refresh(threat)
    return threat


@router.post("/{threat_id}/status", response_model=schemas.ThreatOut)
def update_threat_status(
    project_id: str,
    threat_id: str,
    payload: schemas.ThreatUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    get_project_or_404(db, project_id, current_user.id)
    threat = get_threat_or_404(db, project_id, threat_id)
    if not payload.status:
        raise HTTPException(status_code=422, detail="Status is required")
    now = dt.datetime.utcnow()
    normalized_status = normalize_threat_status(payload.status)
    if not normalized_status:
        raise HTTPException(status_code=422, detail="Status is required")
    prev_status = threat.status
    threat.status = normalized_status
    threat.updated_at = now
    event_type = "updated"
    details = f"Status changed from {prev_status or 'Unknown'} to {normalized_status}"
    if normalized_status == "Mitigated":
        event_type = "closed"
        details = "Threat marked as mitigated"
    elif normalized_status == "In Review":
        event_type = "updated"
        details = "Threat moved to review"
    elif normalized_status == "Identified":
        event_type = "reopened"
        details = "Threat reopened"
    if not threat.events:
        threat.events = []
    if isinstance(threat.events, list):
        threat.events.append(
            {
                "id": f"{uuid.uuid4()}",
                "threatId": threat.id,
                "type": event_type,
                "versionId": threat.introduced_in_version_id or threat.introduced_in,
                "timestamp": now.isoformat(),
                "details": details,
            }
        )
    db.commit()
    db.refresh(threat)
    return threat


@router.post("/{threat_id}/accept-risk", response_model=schemas.ThreatOut)
def accept_risk(
    project_id: str,
    threat_id: str,
    payload: schemas.AcceptRiskPayload,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    get_project_or_404(db, project_id, current_user.id)
    threat = get_threat_or_404(db, project_id, threat_id)
    now = dt.datetime.utcnow()
    threat.status = "Accepted"
    threat.accepted_risk_info = {
        "reason": payload.reason,
        "reasonDetails": payload.reason_details,
        "owner": payload.owner,
        "reviewDate": payload.review_date.isoformat() if payload.review_date else None,
        "acceptedAt": now.isoformat(),
    }
    threat.updated_at = now
    if not threat.events:
        threat.events = []
    if isinstance(threat.events, list):
        threat.events.append(
            {
                "id": f"{uuid.uuid4()}",
                "threatId": threat.id,
                "type": "risk_accepted",
                "versionId": threat.introduced_in_version_id or threat.introduced_in,
                "timestamp": now.isoformat(),
                "details": f"Risk accepted: {payload.reason}",
            }
        )
    db.commit()
    db.refresh(threat)
    return threat


@router.delete("/{threat_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_threat(
    project_id: str,
    threat_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    get_project_or_404(db, project_id, current_user.id)
    threat = get_threat_or_404(db, project_id, threat_id)
    db.delete(threat)
    db.commit()
    return None
