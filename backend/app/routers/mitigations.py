import datetime as dt
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from .. import models, schemas
from ..deps import get_db, get_current_user

router = APIRouter(prefix="/projects/{project_id}/mitigations", tags=["mitigations"])


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


def get_mitigation_or_404(db: Session, project_id: str, mitigation_id: str) -> models.Mitigation:
    mitigation = (
        db.query(models.Mitigation)
        .filter(models.Mitigation.id == mitigation_id, models.Mitigation.project_id == project_id)
        .first()
    )
    if not mitigation:
        raise HTTPException(status_code=404, detail="Mitigation not found")
    return mitigation


@router.get("", response_model=list[schemas.MitigationOut])
def list_mitigations(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    get_project_or_404(db, project_id, current_user.id)
    return db.query(models.Mitigation).filter(models.Mitigation.project_id == project_id).all()


@router.get("/{mitigation_id}", response_model=schemas.MitigationOut)
def get_mitigation(
    project_id: str,
    mitigation_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    get_project_or_404(db, project_id, current_user.id)
    return get_mitigation_or_404(db, project_id, mitigation_id)


@router.post("", response_model=schemas.MitigationOut, status_code=status.HTTP_201_CREATED)
def create_mitigation(
    project_id: str,
    payload: schemas.MitigationCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    get_project_or_404(db, project_id, current_user.id)
    now = dt.datetime.utcnow()
    mitigation = models.Mitigation(
        id=str(uuid.uuid4()),
        project_id=project_id,
        threat_id=payload.threat_id,
        title=payload.title,
        description=payload.description,
        status=payload.status,
        owner=payload.owner,
        priority=payload.priority,
        type=payload.type,
        assignee=payload.assignee,
        due_date=payload.due_date,
        introduced_in_version_id=payload.introduced_in_version_id,
        created_at=now,
        updated_at=now,
    )
    db.add(mitigation)
    db.commit()
    db.refresh(mitigation)
    return mitigation


@router.patch("/{mitigation_id}", response_model=schemas.MitigationOut)
def update_mitigation(
    project_id: str,
    mitigation_id: str,
    payload: schemas.MitigationUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    get_project_or_404(db, project_id, current_user.id)
    mitigation = get_mitigation_or_404(db, project_id, mitigation_id)
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(mitigation, key, value)
    mitigation.updated_at = dt.datetime.utcnow()
    db.commit()
    db.refresh(mitigation)
    return mitigation


@router.delete("/{mitigation_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_mitigation(
    project_id: str,
    mitigation_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    get_project_or_404(db, project_id, current_user.id)
    mitigation = get_mitigation_or_404(db, project_id, mitigation_id)
    db.delete(mitigation)
    db.commit()
    return None
