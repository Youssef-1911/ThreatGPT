import datetime as dt
import json
import os
import uuid
from pathlib import Path
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form
from sqlalchemy.orm import Session
from .. import models, schemas
from ..deps import get_db, get_current_user
from ..versioning_service import create_project_version, capture_version_snapshots

router = APIRouter(prefix="/projects/{project_id}/documents", tags=["documents"])
UPLOAD_ROOT = Path(__file__).resolve().parents[1] / "uploads"


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


def get_document_or_404(db: Session, project_id: str, document_id: str) -> models.ProjectDocument:
    document = (
        db.query(models.ProjectDocument)
        .filter(models.ProjectDocument.id == document_id, models.ProjectDocument.project_id == project_id)
        .first()
    )
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    return document


@router.get("", response_model=list[schemas.DocumentOut])
def list_documents(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    get_project_or_404(db, project_id, current_user.id)
    return db.query(models.ProjectDocument).filter(models.ProjectDocument.project_id == project_id).all()

def _parse_id_list(value: str | None) -> List[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return [str(item) for item in parsed]
    except json.JSONDecodeError:
        pass
    return [item.strip() for item in value.split(",") if item.strip()]


def _document_payload(document: models.ProjectDocument) -> dict:
    return {
        "id": document.id,
        "name": document.name,
        "type": document.type,
        "size": document.size,
        "tag": document.tag,
        "phase": document.phase,
        "storage_key": document.storage_key,
        "revision_group_id": document.revision_group_id,
        "revision_number": document.revision_number,
        "supersedes_document_id": document.supersedes_document_id,
        "superseded_by_document_id": document.superseded_by_document_id,
        "is_current": document.is_current,
    }


def _store_upload_file(project_id: str, file: UploadFile, content: bytes) -> tuple[Path, str]:
    project_dir = UPLOAD_ROOT / project_id
    os.makedirs(project_dir, exist_ok=True)
    safe_name = f"{uuid.uuid4()}_{Path(file.filename or 'upload').name}"
    storage_path = project_dir / safe_name
    with storage_path.open("wb") as buffer:
        buffer.write(content)
    return storage_path, str(storage_path.relative_to(UPLOAD_ROOT))


def _create_document_change_version(
    db: Session,
    *,
    project: models.Project,
    created_by: str,
    event_type: str,
    document_payload: dict,
) -> models.ProjectVersion:
    threat_ids = [threat.id for threat in (project.threats or [])]
    mitigation_ids = [mitigation.id for mitigation in (project.mitigations or [])]
    context_snapshot = {
        "documentEvent": {
            "type": event_type,
            "document": document_payload,
        }
    }
    notes = f"Document {event_type.replace('_', ' ')}"
    return create_project_version(
        db,
        project=project,
        created_by=created_by,
        context_snapshot=context_snapshot,
        notes=notes,
        threat_ids=threat_ids,
        mitigation_ids=mitigation_ids,
        version_type="document_change",
    )


@router.post("/upload", response_model=schemas.DocumentOut, status_code=status.HTTP_201_CREATED)
def upload_document(
    project_id: str,
    tag: str = Form(...),
    phase: str | None = Form(default=None),
    file: UploadFile = File(...),
    linked_version_ids: str | None = Form(default=None),
    linked_threat_ids: str | None = Form(default=None),
    supersedes_document_id: str | None = Form(default=None),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    project = get_project_or_404(db, project_id, current_user.id)
    if not file.filename:
        raise HTTPException(status_code=422, detail="File is required")

    MAX_UPLOAD_BYTES = 20 * 1024 * 1024  # 20 MB
    content = file.file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds 20 MB limit")

    now = dt.datetime.utcnow()
    superseded_document: models.ProjectDocument | None = None
    if supersedes_document_id:
        superseded_document = get_document_or_404(db, project_id, supersedes_document_id)
        superseded_document.is_current = False
        superseded_document.updated_at = now

    storage_path, storage_key = _store_upload_file(project_id, file, content)
    revision_group_id = (
        superseded_document.revision_group_id
        if superseded_document and superseded_document.revision_group_id
        else (superseded_document.id if superseded_document else str(uuid.uuid4()))
    )
    revision_number = int((superseded_document.revision_number if superseded_document else 0) or 0) + 1

    version = _create_document_change_version(
        db,
        project=project,
        created_by=current_user.email,
        event_type="uploaded",
        document_payload={
            "name": Path(file.filename).name,
            "type": file.content_type or "application/octet-stream",
            "size": storage_path.stat().st_size,
            "tag": tag,
            "phase": phase,
            "storage_key": storage_key,
            "revision_group_id": revision_group_id,
            "revision_number": revision_number,
            "supersedes_document_id": superseded_document.id if superseded_document else None,
        },
    )

    # Keep document-version linkage for analysis association (set by orchestrator),
    # not for raw upload/change events.
    linked_version_ids_value = _parse_id_list(linked_version_ids)

    document = models.ProjectDocument(
        id=str(uuid.uuid4()),
        project_id=project_id,
        name=Path(file.filename).name,
        type=file.content_type or "application/octet-stream",
        size=storage_path.stat().st_size,
        tag=tag,
        phase=phase,
        uploaded_at=now,
        storage_key=storage_key,
        linked_version_ids=linked_version_ids_value,
        linked_threat_ids=_parse_id_list(linked_threat_ids),
        revision_group_id=revision_group_id,
        revision_number=revision_number,
        supersedes_document_id=superseded_document.id if superseded_document else None,
        superseded_by_document_id=None,
        is_current=True,
        created_at=now,
        updated_at=now,
    )
    db.add(document)
    db.flush()
    if superseded_document:
        superseded_document.superseded_by_document_id = document.id
    db.commit()
    db.refresh(document)

    capture_version_snapshots(
        db,
        project_id=project_id,
        version_id=version.id,
        threat_ids=version.threat_ids,
        mitigation_ids=version.mitigation_ids,
    )

    return document


@router.post("", response_model=schemas.DocumentOut, status_code=status.HTTP_201_CREATED)
def create_document(
    project_id: str,
    payload: schemas.DocumentCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    project = get_project_or_404(db, project_id, current_user.id)
    now = dt.datetime.utcnow()

    version = _create_document_change_version(
        db,
        project=project,
        created_by=current_user.email,
        event_type="created",
        document_payload={
            "name": payload.name,
            "type": payload.type,
            "size": payload.size,
            "tag": payload.tag,
            "phase": payload.phase,
            "storage_key": payload.storage_key,
            "revision_group_id": payload.revision_group_id,
            "revision_number": payload.revision_number,
        },
    )

    # Keep document-version linkage for analysis association (set by orchestrator),
    # not for raw create/change events.
    linked_version_ids_value = list(payload.linked_version_ids or [])

    document = models.ProjectDocument(
        id=str(uuid.uuid4()),
        project_id=project_id,
        name=payload.name,
        type=payload.type,
        size=payload.size,
        tag=payload.tag,
        phase=payload.phase,
        uploaded_at=payload.uploaded_at,
        storage_key=payload.storage_key,
        linked_version_ids=linked_version_ids_value,
        linked_threat_ids=payload.linked_threat_ids or [],
        revision_group_id=payload.revision_group_id or str(uuid.uuid4()),
        revision_number=payload.revision_number or 1,
        supersedes_document_id=payload.supersedes_document_id,
        superseded_by_document_id=payload.superseded_by_document_id,
        is_current=payload.is_current,
        created_at=now,
        updated_at=now,
    )
    db.add(document)
    db.commit()
    db.refresh(document)

    capture_version_snapshots(
        db,
        project_id=project_id,
        version_id=version.id,
        threat_ids=version.threat_ids,
        mitigation_ids=version.mitigation_ids,
    )

    return document


@router.post("/{document_id}/replace", response_model=schemas.DocumentOut, status_code=status.HTTP_201_CREATED)
def replace_document(
    project_id: str,
    document_id: str,
    tag: str | None = Form(default=None),
    phase: str | None = Form(default=None),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    get_project_or_404(db, project_id, current_user.id)
    old_document = get_document_or_404(db, project_id, document_id)
    return upload_document(
        project_id=project_id,
        tag=tag or old_document.tag,
        phase=phase if phase is not None else old_document.phase,
        file=file,
        linked_version_ids="[]",
        linked_threat_ids=json.dumps(old_document.linked_threat_ids or []),
        supersedes_document_id=document_id,
        db=db,
        current_user=current_user,
    )


@router.patch("/{document_id}", response_model=schemas.DocumentOut)
def update_document(
    project_id: str,
    document_id: str,
    payload: schemas.DocumentUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    project = get_project_or_404(db, project_id, current_user.id)
    document = get_document_or_404(db, project_id, document_id)

    payload_data = payload.model_dump(exclude_unset=True)

    # Metadata updates should not create a new project version; this keeps
    # version lineage tied to meaningful evidence/analysis changes.

    for key, value in payload_data.items():
        setattr(document, key, value)

    document.updated_at = dt.datetime.utcnow()
    db.commit()
    db.refresh(document)
    return document


@router.delete("/{document_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_document(
    project_id: str,
    document_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    get_project_or_404(db, project_id, current_user.id)
    document = get_document_or_404(db, project_id, document_id)
    db.delete(document)
    db.commit()
    return None
