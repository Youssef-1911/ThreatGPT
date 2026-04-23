import datetime as dt
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from .. import models, schemas
from ..deps import get_db, get_current_user

router = APIRouter(prefix="/projects", tags=["projects"])

@router.get("", response_model=list[schemas.ProjectOut])
def list_projects(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    return db.query(models.Project).filter(models.Project.owner_id == current_user.id).all()

@router.post("", response_model=schemas.ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project(
    payload: schemas.ProjectCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    now = dt.datetime.utcnow()
    project = models.Project(
        id=str(uuid.uuid4()),
        owner_id=current_user.id,
        name=payload.name,
        description=payload.description,
        methodology=payload.methodology,
        use_case_mode=payload.use_case_mode,
        current_phase=payload.current_phase,
        next_phase=payload.next_phase,
        sdlc_phases=payload.sdlc_phases,
        system_description=payload.system_description,
        pre_development_inputs=payload.pre_development_inputs,
        git_config=payload.git_config,
        security_findings=payload.security_findings,
        components=payload.components,
        data_flows=payload.data_flows,
        trust_boundaries=payload.trust_boundaries,
        current_version_id=payload.current_version_id,
        attack_scenario_nodes=payload.attack_scenario_nodes,
        attack_scenario_edges=payload.attack_scenario_edges,
        integrations=payload.integrations,
        status=payload.status,
        created_at=now,
        updated_at=now,
        version=payload.version,
    )
    db.add(project)

    if payload.versions:
        for version_payload in payload.versions:
            version = models.ProjectVersion(
                id=getattr(version_payload, "id", None) or str(uuid.uuid4()),
                project_id=project.id,
                version_number=version_payload.version_number,
                created_at=version_payload.created_at,
                created_by=version_payload.created_by,
                context_snapshot=version_payload.context_snapshot,
                threat_ids=version_payload.threat_ids or [],
                mitigation_ids=version_payload.mitigation_ids or [],
                notes=version_payload.notes,
            )
            db.add(version)
            project.current_version_id = version.id
            project.version = version.version_number
    else:
        initial_version = models.ProjectVersion(
            id=str(uuid.uuid4()),
            project_id=project.id,
            version_number=payload.version,
            created_at=now,
            created_by="Initial",
            context_snapshot={
                "systemDescription": payload.system_description,
                "preDevelopmentInputs": payload.pre_development_inputs,
                "gitConfig": payload.git_config,
                "securityFindings": payload.security_findings,
            },
            threat_ids=[t.id for t in payload.threats] if payload.threats else [],
            mitigation_ids=[m.id for m in payload.mitigations] if payload.mitigations else [],
            notes="Initial project version",
        )
        db.add(initial_version)
        project.current_version_id = initial_version.id

    for doc in payload.documents or []:
        uploaded_at = doc.uploaded_at or now
        document = models.ProjectDocument(
            id=str(uuid.uuid4()),
            project_id=project.id,
            name=doc.name,
            type=doc.type,
            size=doc.size,
            tag=doc.tag,
            phase=doc.phase,
            uploaded_at=uploaded_at,
            linked_version_ids=doc.linked_version_ids or [],
            linked_threat_ids=doc.linked_threat_ids or [],
            created_at=now,
            updated_at=now,
        )
        db.add(document)

    db.commit()
    db.refresh(project)
    return project

@router.get("/{project_id}", response_model=schemas.ProjectOut)
def get_project(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    project = (
        db.query(models.Project)
        .filter(
            models.Project.id == project_id,
            models.Project.owner_id == current_user.id,
        )
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project

@router.patch("/{project_id}", response_model=schemas.ProjectOut)
def update_project(
    project_id: str,
    payload: schemas.ProjectUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    project = (
        db.query(models.Project)
        .filter(
            models.Project.id == project_id,
            models.Project.owner_id == current_user.id,
        )
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    data = payload.model_dump(exclude_unset=True)
    blocked_fields = {"threats", "mitigations", "versions", "documents"}
    for key, value in data.items():
        if key in blocked_fields:
            continue
        setattr(project, key, value)
    project.updated_at = dt.datetime.utcnow()

    db.commit()
    db.refresh(project)
    return project

@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    project = (
        db.query(models.Project)
        .filter(
            models.Project.id == project_id,
            models.Project.owner_id == current_user.id,
        )
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    db.delete(project)
    db.commit()
    return None


@router.get("/{project_id}/integrations")
def get_project_integrations(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    project = (
        db.query(models.Project)
        .filter(
            models.Project.id == project_id,
            models.Project.owner_id == current_user.id,
        )
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return {"project_id": project_id, "integrations": project.integrations or {}}


@router.put("/{project_id}/integrations")
def update_project_integrations(
    project_id: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    project = (
        db.query(models.Project)
        .filter(
            models.Project.id == project_id,
            models.Project.owner_id == current_user.id,
        )
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    project.integrations = payload.get("integrations", payload)
    project.updated_at = dt.datetime.utcnow()
    db.commit()
    db.refresh(project)
    return {"project_id": project_id, "integrations": project.integrations or {}}


@router.get("/{project_id}/attack-scenarios")
def get_attack_scenarios(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    project = (
        db.query(models.Project)
        .filter(
            models.Project.id == project_id,
            models.Project.owner_id == current_user.id,
        )
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return {
        "project_id": project_id,
        "nodes": project.attack_scenario_nodes or [],
        "edges": project.attack_scenario_edges or [],
    }


@router.put("/{project_id}/attack-scenarios")
def update_attack_scenarios(
    project_id: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    project = (
        db.query(models.Project)
        .filter(
            models.Project.id == project_id,
            models.Project.owner_id == current_user.id,
        )
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    project.attack_scenario_nodes = payload.get("nodes", [])
    project.attack_scenario_edges = payload.get("edges", [])
    project.updated_at = dt.datetime.utcnow()
    db.commit()
    db.refresh(project)
    return {
        "project_id": project_id,
        "nodes": project.attack_scenario_nodes or [],
        "edges": project.attack_scenario_edges or [],
    }
