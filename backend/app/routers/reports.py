import csv
import io
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy.orm import Session

from .. import models
from ..deps import get_db, get_current_user

router = APIRouter(prefix="/reports", tags=["reports"])


def _project_to_row(project: models.Project) -> dict:
    threats = project.threats or []
    mitigations = project.mitigations or []
    return {
        "project_id": project.id,
        "name": project.name,
        "methodology": project.methodology,
        "status": project.status,
        "current_phase": project.current_phase,
        "version": project.version,
        "threats_count": len(threats),
        "mitigations_count": len(mitigations),
    }


@router.get("/projects/{project_id}")
def export_project_report(
    project_id: str,
    format: str = Query("json"),
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

    row = _project_to_row(project)
    if format == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=row.keys())
        writer.writeheader()
        writer.writerow(row)
        return PlainTextResponse(output.getvalue(), media_type="text/csv")
    if format != "json":
        raise HTTPException(status_code=422, detail="Unsupported format")
    return JSONResponse(row)


@router.get("/projects")
def export_all_projects_report(
    format: str = Query("json"),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    projects = (
        db.query(models.Project)
        .filter(models.Project.owner_id == current_user.id)
        .all()
    )
    rows = [_project_to_row(p) for p in projects]
    if format == "csv":
        output = io.StringIO()
        if rows:
            writer = csv.DictWriter(output, fieldnames=rows[0].keys())
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
        return PlainTextResponse(output.getvalue(), media_type="text/csv")
    if format != "json":
        raise HTTPException(status_code=422, detail="Unsupported format")
    return JSONResponse(rows)
