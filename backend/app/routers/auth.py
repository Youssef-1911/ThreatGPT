import datetime as dt
import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .. import models, schemas
from ..deps import get_db, get_current_user, get_current_admin
from ..email_service import EmailService
from ..security import hash_password, verify_password, create_access_token

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/signup", response_model=schemas.AccountRequestOut, status_code=201)
def signup(payload: schemas.UserCreate, db: Session = Depends(get_db)):
    email = payload.email.lower()
    existing = db.query(models.User).filter(models.User.email == email).first()

    if existing and existing.account_status == "Approved":
        raise HTTPException(status_code=400, detail="Email already registered")
    if existing and existing.account_status == "Pending":
        raise HTTPException(status_code=400, detail="Account request already pending admin approval")

    if existing and existing.account_status == "Rejected":
        existing.password_hash = hash_password(payload.password)
        existing.full_name = payload.full_name
        existing.organization = payload.organization
        existing.entity_details = payload.entity_details.model_dump()
        existing.account_status = "Pending"
        existing.rejection_reason = None
        existing.account_reviewed_at = None
        existing.account_reviewed_by = None
        db.commit()
        db.refresh(existing)
        return existing

    user = models.User(
        id=str(uuid.uuid4()),
        email=email,
        password_hash=hash_password(payload.password),
        full_name=payload.full_name,
        role="Security Analyst",
        organization=payload.organization,
        avatar_url=None,
        entity_details=payload.entity_details.model_dump(),
        account_status="Pending",
        created_at=dt.datetime.utcnow(),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@router.post("/login", response_model=schemas.Token)
def login(payload: schemas.UserLogin, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == payload.email.lower()).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if user.account_status == "Pending":
        raise HTTPException(status_code=403, detail="Account pending admin approval")

    if user.account_status == "Rejected":
        if user.rejection_reason:
            raise HTTPException(
                status_code=403,
                detail=f"Account request rejected: {user.rejection_reason}",
            )
        raise HTTPException(status_code=403, detail="Account request rejected")

    token = create_access_token(user.id)
    return {"access_token": token, "token_type": "bearer"}

@router.get("/me", response_model=schemas.UserOut)
def me(current_user: models.User = Depends(get_current_user)):
    return current_user


@router.get("/account-requests/pending", response_model=list[schemas.AccountRequestOut])
def list_pending_account_requests(
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_admin),
):
    return (
        db.query(models.User)
        .filter(models.User.account_status == "Pending")
        .order_by(models.User.created_at.asc())
        .all()
    )


@router.get("/account-requests", response_model=list[schemas.AccountRequestOut])
def list_account_requests(
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_admin),
):
    return (
        db.query(models.User)
        .filter(models.User.role != "admin")
        .order_by(models.User.created_at.desc())
        .all()
    )


@router.post("/account-requests/{user_id}/approve", response_model=schemas.AccountRequestOut)
def approve_account_request(
    user_id: str,
    db: Session = Depends(get_db),
    admin: models.User = Depends(get_current_admin),
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Account request not found")

    user.account_status = "Approved"
    user.rejection_reason = None
    user.account_reviewed_at = dt.datetime.utcnow()
    user.account_reviewed_by = admin.id
    if not user.role:
        user.role = "Security Analyst"

    db.commit()
    db.refresh(user)

    EmailService().send_notification(
        to_email=user.email,
        subject="ThreatGPT account approved",
        body=(
            f"Hello {user.full_name},\n\n"
            "Your ThreatGPT account request has been approved.\n"
            "You can now sign in and start using the platform.\n"
        ),
    )

    return user


@router.post("/account-requests/{user_id}/reject", response_model=schemas.AccountRequestOut)
def reject_account_request(
    user_id: str,
    payload: schemas.AccountDecisionPayload,
    db: Session = Depends(get_db),
    admin: models.User = Depends(get_current_admin),
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Account request not found")

    user.account_status = "Rejected"
    user.rejection_reason = payload.reason
    user.account_reviewed_at = dt.datetime.utcnow()
    user.account_reviewed_by = admin.id

    db.commit()
    db.refresh(user)
    return user


@router.get("/integrations")
def get_integrations(current_user: models.User = Depends(get_current_user)):
    return {"integrations": current_user.integrations or {}}


@router.put("/integrations")
def update_integrations(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    current_user.integrations = payload.get("integrations", payload)
    db.commit()
    db.refresh(current_user)
    return {"integrations": current_user.integrations or {}}
