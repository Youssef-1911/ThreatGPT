import datetime as dt
from sqlalchemy import Boolean, Column, String, DateTime, JSON, Integer, ForeignKey, Text, Float
from sqlalchemy.orm import relationship
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    full_name = Column(String, nullable=False)
    role = Column(String, nullable=False)
    organization = Column(String, nullable=True)
    avatar_url = Column(String, nullable=True)
    integrations = Column(JSON, nullable=True)
    account_status = Column(String, nullable=False, default="Approved")
    entity_details = Column(JSON, nullable=True)
    account_reviewed_at = Column(DateTime, nullable=True)
    account_reviewed_by = Column(String, nullable=True)
    rejection_reason = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=dt.datetime.utcnow)
    projects = relationship("Project", back_populates="owner")

class Project(Base):
    __tablename__ = "projects"

    id = Column(String, primary_key=True, index=True)
    owner_id = Column(String, ForeignKey("users.id"), nullable=True, index=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=False)
    methodology = Column(String, nullable=False)
    use_case_mode = Column(String, nullable=False)
    current_phase = Column(String, nullable=False)
    next_phase = Column(String, nullable=True)
    sdlc_phases = Column(JSON, nullable=False)
    system_description = Column(String, nullable=False)
    pre_development_inputs = Column(JSON, nullable=True)
    git_config = Column(JSON, nullable=True)
    security_findings = Column(JSON, nullable=True)
    components = Column(JSON, nullable=False)
    data_flows = Column(JSON, nullable=False)
    trust_boundaries = Column(JSON, nullable=False)
    current_version_id = Column(String, nullable=True)
    attack_scenario_nodes = Column(JSON, nullable=True)
    attack_scenario_edges = Column(JSON, nullable=True)
    integrations = Column(JSON, nullable=True)
    status = Column(String, nullable=False)
    created_at = Column(DateTime, nullable=False, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=dt.datetime.utcnow)
    version = Column(String, nullable=False)
    owner = relationship("User", back_populates="projects")

    threats = relationship(
        "Threat",
        back_populates="project",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    mitigations = relationship(
        "Mitigation",
        back_populates="project",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    documents = relationship(
        "ProjectDocument",
        back_populates="project",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    versions = relationship(
        "ProjectVersion",
        back_populates="project",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

class Threat(Base):
    __tablename__ = "threats"

    id = Column(String, primary_key=True, index=True)
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String, nullable=True)
    severity = Column(String, nullable=True)
    likelihood = Column(Integer, nullable=True)
    impact = Column(Integer, nullable=True)
    risk_score = Column(Float, nullable=True)
    status = Column(String, nullable=True)
    affected_component = Column(String, nullable=True)
    identified_stage = Column(String, nullable=True)
    source = Column(String, nullable=True)
    commit_hash = Column(String, nullable=True)
    introduced_in = Column(String, nullable=True)
    identified_in_phase = Column(String, nullable=True)
    introduced_in_version_id = Column(String, nullable=True)
    grounded_finding = Column(String, nullable=True)
    accepted_risk_info = Column(JSON, nullable=True)
    events = Column(JSON, nullable=True)
    created_at = Column(DateTime, nullable=False, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=dt.datetime.utcnow)

    project = relationship("Project", back_populates="threats")

class Mitigation(Base):
    __tablename__ = "mitigations"

    id = Column(String, primary_key=True, index=True)
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    threat_id = Column(String, nullable=True, index=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=False)
    status = Column(String, nullable=False)
    owner = Column(String, nullable=True)
    priority = Column(String, nullable=True)
    type = Column(String, nullable=True)
    assignee = Column(String, nullable=True)
    due_date = Column(DateTime, nullable=True)
    introduced_in_version_id = Column(String, nullable=True)
    created_at = Column(DateTime, nullable=False, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=dt.datetime.utcnow)

    project = relationship("Project", back_populates="mitigations")

class ProjectDocument(Base):
    __tablename__ = "project_documents"

    id = Column(String, primary_key=True, index=True)
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String, nullable=False)
    type = Column(String, nullable=False)
    size = Column(Integer, nullable=False)
    tag = Column(String, nullable=False)
    phase = Column(String, nullable=True)
    uploaded_at = Column(DateTime, nullable=False)
    storage_key = Column(String, nullable=True)
    linked_version_ids = Column(JSON, nullable=True)
    linked_threat_ids = Column(JSON, nullable=True)
    revision_group_id = Column(String, nullable=True, index=True)
    revision_number = Column(Integer, nullable=False, default=1)
    supersedes_document_id = Column(String, nullable=True, index=True)
    superseded_by_document_id = Column(String, nullable=True, index=True)
    is_current = Column(Boolean, nullable=False, default=True, index=True)
    created_at = Column(DateTime, nullable=False, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=dt.datetime.utcnow)

    project = relationship("Project", back_populates="documents")

class ProjectVersion(Base):
    __tablename__ = "project_versions"

    id = Column(String, primary_key=True, index=True)
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    version_number = Column(String, nullable=False)
    version_type = Column(String, nullable=False, default="analysis")  # "analysis" | "document_change"
    created_at = Column(DateTime, nullable=False, default=dt.datetime.utcnow)
    created_by = Column(String, nullable=False)
    context_snapshot = Column(JSON, nullable=False)
    threat_ids = Column(JSON, nullable=True)
    mitigation_ids = Column(JSON, nullable=True)
    notes = Column(Text, nullable=True)

    project = relationship("Project", back_populates="versions")


class ThreatSnapshot(Base):
    __tablename__ = "threat_snapshots"

    id = Column(String, primary_key=True, index=True)
    version_id = Column(String, ForeignKey("project_versions.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    threat_id = Column(String, nullable=False, index=True)
    name = Column(String, nullable=False)
    severity = Column(String, nullable=True)
    status = Column(String, nullable=True)
    risk_score = Column(Float, nullable=True)
    affected_component = Column(String, nullable=True)
    identified_stage = Column(String, nullable=True)
    source = Column(String, nullable=True)
    created_at = Column(DateTime, nullable=False, default=dt.datetime.utcnow)


class MitigationSnapshot(Base):
    __tablename__ = "mitigation_snapshots"

    id = Column(String, primary_key=True, index=True)
    version_id = Column(String, ForeignKey("project_versions.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    mitigation_id = Column(String, nullable=False, index=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=False, default="")
    status = Column(String, nullable=False)
    priority = Column(String, nullable=True)
    type = Column(String, nullable=True)
    assignee = Column(String, nullable=True)
    due_date = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=dt.datetime.utcnow)


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"

    id = Column(String, primary_key=True, index=True)
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    version_id = Column(String, ForeignKey("project_versions.id", ondelete="CASCADE"), nullable=False, index=True)
    trigger_type = Column(String, nullable=False, default="manual")
    status = Column(String, nullable=False, default="running")
    started_at = Column(DateTime, nullable=False, default=dt.datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    stage_timings_json = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    missing_fields = Column(JSON, nullable=True)
    summary_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, nullable=False, default=dt.datetime.utcnow)


class IntegrationConfig(Base):
    __tablename__ = "integration_configs"

    id = Column(String, primary_key=True, index=True)
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    integration_type = Column(String, nullable=False, index=True)
    provider = Column(String, nullable=False)
    phase_scope = Column(String, nullable=True)
    trigger_mode = Column(String, nullable=False, default="WEBHOOK")
    status = Column(String, nullable=False, default="CONNECTED")
    config_json = Column(JSON, nullable=True)
    secret_hash = Column(String, nullable=True)
    secret_ref = Column(String, nullable=True)
    last_success_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=dt.datetime.utcnow)


class IntegrationEvent(Base):
    __tablename__ = "integration_events"

    id = Column(String, primary_key=True, index=True)
    integration_id = Column(String, ForeignKey("integration_configs.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type = Column(String, nullable=False)
    external_event_id = Column(String, nullable=True, index=True)
    payload_hash = Column(String, nullable=False, index=True)
    payload_storage_key = Column(String, nullable=True)
    raw_payload_json = Column(JSON, nullable=True)
    commit_hash = Column(String, nullable=True)
    branch = Column(String, nullable=True)
    processing_status = Column(String, nullable=False, default="accepted")
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=dt.datetime.utcnow)
    processed_at = Column(DateTime, nullable=True)
    linked_version_id = Column(String, ForeignKey("project_versions.id", ondelete="SET NULL"), nullable=True)
    linked_run_id = Column(String, ForeignKey("analysis_runs.id", ondelete="SET NULL"), nullable=True)
