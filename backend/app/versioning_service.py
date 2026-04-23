import datetime as dt
import uuid
from typing import Any

from sqlalchemy.orm import Session

from . import models


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
    db.commit()


def compute_next_version_number(current_version: str | None) -> str:
    """Return the next integer version string (1, 2, 3 …).

    Handles legacy float strings (e.g. '0.9000000000000001') by rounding to
    the nearest integer before incrementing, so old projects upgrade cleanly.
    """
    base = current_version or "0"
    try:
        return str(int(round(float(base))) + 1)
    except Exception:
        return f"{base}-1"


def create_project_version(
    db: Session,
    *,
    project: models.Project,
    created_by: str,
    context_snapshot: dict[str, Any],
    notes: str,
    threat_ids: list[str] | None = None,
    mitigation_ids: list[str] | None = None,
    version_number: str | None = None,
    version_type: str = "analysis",
) -> models.ProjectVersion:
    now = dt.datetime.now(dt.UTC).replace(tzinfo=None)

    # Document-change versions inherit the current project version number.
    # Only analysis versions increment the counter and become the current version.
    if version_type == "document_change":
        resolved_version_number = project.version or "1"
    else:
        resolved_version_number = version_number or compute_next_version_number(project.version)

    version = models.ProjectVersion(
        id=str(uuid.uuid4()),
        project_id=project.id,
        version_number=resolved_version_number,
        version_type=version_type,
        created_at=now,
        created_by=created_by,
        context_snapshot=context_snapshot,
        threat_ids=threat_ids or [],
        mitigation_ids=mitigation_ids or [],
        notes=notes,
    )
    db.add(version)

    # Only analysis versions become the "current" version shown to the user.
    if version_type == "analysis":
        project.current_version_id = version.id
        project.version = version.version_number

    project.updated_at = now

    return version
