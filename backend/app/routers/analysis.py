from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas
from ..analysis_orchestrator import AnalysisOrchestrator
from ..deps import get_current_user, get_db
from ..versioning_service import create_project_version

router = APIRouter(prefix="/projects/{project_id}/versions/{version_id}", tags=["analysis"])


@router.post("/run-analysis")
def run_analysis_for_version(
    project_id: str,
    version_id: str,
    payload: schemas.RunAnalysisRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    # Enforce ownership at route layer by confirming project belongs to current user.
    project = (
        db.query(models.Project)
        .filter(models.Project.id == project_id, models.Project.owner_id == current_user.id)
        .first()
    )
    if not project:
        return {
            "status": "failed",
            "project_id": project_id,
            "version_id": version_id,
            "parsing_status": "not_started",
            "generation_status": "not_started",
            "graph_status": "not_started",
            "scenario_status": "not_started",
            "saved_artifacts": {
                "parsed_output": False,
                "threats": 0,
                "graph": False,
                "scenarios": 0,
            },
            "missing_fields": ["project"],
        }

    base_version = (
        db.query(models.ProjectVersion)
        .filter(models.ProjectVersion.id == version_id, models.ProjectVersion.project_id == project_id)
        .first()
    )
    if not base_version:
        return {
            "status": "failed",
            "project_id": project_id,
            "version_id": version_id,
            "parsing_status": "not_started",
            "generation_status": "not_started",
            "graph_status": "not_started",
            "scenario_status": "not_started",
            "saved_artifacts": {
                "parsed_output": False,
                "threats": 0,
                "graph": False,
                "scenarios": 0,
            },
            "missing_fields": ["version"],
        }

    target_version_id = version_id
    if payload.create_new_version:
        base_context_snapshot = (
            dict(base_version.context_snapshot)
            if isinstance(base_version.context_snapshot, dict)
            else {}
        )
        base_context_snapshot["analysis_run"] = {
            "trigger": "manual_route",
            "source_version_id": version_id,
        }

        created_version = create_project_version(
            db,
            project=project,
            created_by=current_user.email,
            context_snapshot=base_context_snapshot,
            notes="Manual run-analysis trigger",
            threat_ids=list(base_version.threat_ids or []),
            mitigation_ids=list(base_version.mitigation_ids or []),
        )
        db.commit()
        db.refresh(created_version)
        target_version_id = created_version.id

    try:
        orchestrator = AnalysisOrchestrator()
        return orchestrator.run_full_analysis(
            db=db,
            project_id=project_id,
            version_id=target_version_id,
            phase=payload.phase,
            methodology=payload.methodology,
            persist_threats=payload.persist_threats,
        )
    except ValueError as exc:
        # Surface missing runtime config as a clear client-visible setup error.
        if "AI_API_KEY" in str(exc):
            raise HTTPException(
                status_code=503,
                detail="Server is missing AI_API_KEY configuration for analysis",
            ) from exc
        raise


@router.get("/runs", response_model=list[schemas.AnalysisRunOut])
def list_analysis_runs(
    project_id: str,
    version_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    project = (
        db.query(models.Project)
        .filter(models.Project.id == project_id, models.Project.owner_id == current_user.id)
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    return (
        db.query(models.AnalysisRun)
        .filter(models.AnalysisRun.project_id == project_id, models.AnalysisRun.version_id == version_id)
        .order_by(models.AnalysisRun.created_at.desc())
        .all()
    )


@router.get("/runs/{run_id}", response_model=schemas.AnalysisRunOut)
def get_analysis_run(
    project_id: str,
    version_id: str,
    run_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    project = (
        db.query(models.Project)
        .filter(models.Project.id == project_id, models.Project.owner_id == current_user.id)
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    run = (
        db.query(models.AnalysisRun)
        .filter(
            models.AnalysisRun.id == run_id,
            models.AnalysisRun.project_id == project_id,
            models.AnalysisRun.version_id == version_id,
        )
        .first()
    )
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run
