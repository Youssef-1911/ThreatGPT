import datetime as dt
from sqlalchemy.orm import Session
from .database import SessionLocal
from . import models
from .security import hash_password


ADMIN_USER_ID = "user-admin-0001"
ADMIN_USER_EMAIL = "admin@threatgpt.com"
DEMO_PROJECT_IDS = [
    "proj-ecommerce-0001",
    "proj-banking-0001",
    "proj-health-0001",
]


def seed_data_if_empty() -> None:
    db: Session = SessionLocal()
    try:
        # Remove known demo/mock data if present.
        for project_id in DEMO_PROJECT_IDS:
            db.query(models.Threat).filter(models.Threat.project_id == project_id).delete(
                synchronize_session=False
            )
            db.query(models.Mitigation).filter(models.Mitigation.project_id == project_id).delete(
                synchronize_session=False
            )
            db.query(models.ProjectDocument).filter(
                models.ProjectDocument.project_id == project_id
            ).delete(synchronize_session=False)
            db.query(models.ProjectVersion).filter(
                models.ProjectVersion.project_id == project_id
            ).delete(synchronize_session=False)
            db.query(models.Project).filter(models.Project.id == project_id).delete(
                synchronize_session=False
            )

        # Ensure an admin account exists so approval workflow is usable.
        admin_user = db.query(models.User).filter(models.User.email == ADMIN_USER_EMAIL).first()
        if not admin_user:
            admin_user = models.User(
                id=ADMIN_USER_ID,
                email=ADMIN_USER_EMAIL,
                password_hash=hash_password("Admin12345!"),
                full_name="Admin User",
                role="admin",
                organization="ThreatGPT",
                avatar_url=None,
                account_status="Approved",
                entity_details={
                    "company_name": "ThreatGPT",
                    "industry": "Cybersecurity",
                    "company_size": "11-50",
                    "country": "US",
                    "website": "https://example.com",
                },
                created_at=dt.datetime.utcnow(),
            )
            db.add(admin_user)

        db.commit()
    finally:
        db.close()
