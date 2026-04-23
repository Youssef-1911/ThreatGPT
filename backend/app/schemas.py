from __future__ import annotations

import datetime as dt
from typing import Any, List, Optional, Literal
from pydantic import BaseModel, EmailStr, Field, ConfigDict, model_validator

AccountStatus = Literal["Pending", "Approved", "Rejected"]


class EntityDetails(BaseModel):
    company_name: str
    industry: str
    company_size: str
    country: str
    website: str

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    organization: Optional[str] = None
    entity_details: EntityDetails

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: str
    email: EmailStr
    full_name: str
    role: str
    organization: Optional[str] = None
    avatar_url: Optional[str] = None
    integrations: Optional[Any] = None
    account_status: AccountStatus
    entity_details: Optional[Any] = None
    rejection_reason: Optional[str] = None
    created_at: dt.datetime

    model_config = ConfigDict(from_attributes=True)

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class AccountRequestOut(BaseModel):
    id: str
    email: EmailStr
    full_name: str
    organization: Optional[str] = None
    account_status: AccountStatus
    entity_details: Optional[Any] = None
    rejection_reason: Optional[str] = None
    created_at: dt.datetime

    model_config = ConfigDict(from_attributes=True)


class AccountDecisionPayload(BaseModel):
    reason: Optional[str] = None

class ProjectBase(BaseModel):
    owner_id: Optional[str] = None
    name: str
    description: str
    methodology: str
    use_case_mode: str
    current_phase: str
    next_phase: Optional[str] = None
    sdlc_phases: List[Any]
    system_description: str
    pre_development_inputs: Optional[Any] = None
    git_config: Optional[Any] = None
    security_findings: Optional[Any] = None
    components: List[Any]
    data_flows: List[Any]
    trust_boundaries: List[Any]
    threats: List["ThreatOut"] = Field(default_factory=list)
    mitigations: List["MitigationOut"]
    versions: List["VersionOut"]
    current_version_id: Optional[str] = None
    documents: List["DocumentOut"] = Field(default_factory=list)
    attack_scenario_nodes: Optional[Any] = None
    attack_scenario_edges: Optional[Any] = None
    integrations: Optional[Any] = None
    status: str = Field(..., pattern=r"^(Draft|In Progress|Complete)$")
    version: str

class ProjectCreate(ProjectBase):
    documents: List["DocumentCreatePayload"] = Field(default_factory=list)

class ProjectUpdate(BaseModel):
    owner_id: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    methodology: Optional[str] = None
    use_case_mode: Optional[str] = None
    current_phase: Optional[str] = None
    next_phase: Optional[str] = None
    sdlc_phases: Optional[List[Any]] = None
    system_description: Optional[str] = None
    pre_development_inputs: Optional[Any] = None
    git_config: Optional[Any] = None
    security_findings: Optional[Any] = None
    components: Optional[List[Any]] = None
    data_flows: Optional[List[Any]] = None
    trust_boundaries: Optional[List[Any]] = None
    threats: Optional[List["ThreatOut"]] = None
    mitigations: Optional[List["MitigationOut"]] = None
    versions: Optional[List["VersionOut"]] = None
    current_version_id: Optional[str] = None
    documents: Optional[List["DocumentOut"]] = None
    attack_scenario_nodes: Optional[Any] = None
    attack_scenario_edges: Optional[Any] = None
    integrations: Optional[Any] = None
    status: Optional[str] = Field(None, pattern=r"^(Draft|In Progress|Complete)$")
    version: Optional[str] = None

class ProjectOut(ProjectBase):
    id: str
    created_at: dt.datetime
    updated_at: dt.datetime

    model_config = ConfigDict(from_attributes=True)

class ThreatBase(BaseModel):
    project_id: str
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None
    likelihood: Optional[int] = None
    impact: Optional[int] = None
    risk_score: Optional[float] = None
    status: Optional[str] = None
    affected_component: Optional[str] = None
    identified_stage: Optional[str] = None
    source: Optional[str] = None
    commit_hash: Optional[str] = None
    introduced_in: Optional[str] = None
    identified_in_phase: Optional[str] = None
    introduced_in_version_id: Optional[str] = None
    accepted_risk_info: Optional[Any] = None
    events: Optional[List[Any]] = None

class ThreatCreate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None
    likelihood: Optional[int] = None
    impact: Optional[int] = None
    risk_score: Optional[float] = None
    status: Optional[Literal["Identified", "In Review", "Mitigated", "Accepted"]] = None
    affected_component: Optional[str] = None
    identified_stage: Optional[str] = None
    source: Optional[str] = None
    commit_hash: Optional[str] = None
    introduced_in: Optional[str] = None
    identified_in_phase: Optional[str] = None
    introduced_in_version_id: Optional[str] = None
    accepted_risk_info: Optional[Any] = None
    events: Optional[List[Any]] = None

class ThreatUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None
    likelihood: Optional[int] = None
    impact: Optional[int] = None
    risk_score: Optional[float] = None
    status: Optional[Literal["Identified", "In Review", "Mitigated", "Accepted"]] = None
    affected_component: Optional[str] = None
    identified_stage: Optional[str] = None
    source: Optional[str] = None
    commit_hash: Optional[str] = None
    introduced_in: Optional[str] = None
    identified_in_phase: Optional[str] = None
    introduced_in_version_id: Optional[str] = None
    accepted_risk_info: Optional[Any] = None
    events: Optional[List[Any]] = None

class ThreatOut(ThreatBase):
    id: str
    created_at: dt.datetime
    updated_at: dt.datetime
    riskScore: Optional[float] = None
    affectedComponent: Optional[str] = None
    identifiedStage: Optional[str] = None
    commitHash: Optional[str] = None
    identifiedInPhase: Optional[str] = None
    introducedInVersionId: Optional[str] = None
    acceptedRiskInfo: Optional[Any] = None
    createdAt: Optional[dt.datetime] = None
    updatedAt: Optional[dt.datetime] = None

    @model_validator(mode="after")
    def mirror_camel_case_fields(self) -> "ThreatOut":
        self.riskScore = self.riskScore if self.riskScore is not None else self.risk_score
        self.affectedComponent = self.affectedComponent if self.affectedComponent is not None else self.affected_component
        self.identifiedStage = self.identifiedStage if self.identifiedStage is not None else self.identified_stage
        self.commitHash = self.commitHash if self.commitHash is not None else self.commit_hash
        self.identifiedInPhase = self.identifiedInPhase if self.identifiedInPhase is not None else self.identified_in_phase
        self.introducedInVersionId = (
            self.introducedInVersionId
            if self.introducedInVersionId is not None
            else self.introduced_in_version_id
        )
        self.acceptedRiskInfo = self.acceptedRiskInfo if self.acceptedRiskInfo is not None else self.accepted_risk_info
        self.createdAt = self.createdAt if self.createdAt is not None else self.created_at
        self.updatedAt = self.updatedAt if self.updatedAt is not None else self.updated_at
        return self

    model_config = ConfigDict(from_attributes=True)

class MitigationBase(BaseModel):
    project_id: str
    threat_id: Optional[str] = None
    title: str
    description: str
    status: str
    owner: Optional[str] = None
    priority: Optional[str] = None
    type: Optional[str] = None
    assignee: Optional[str] = None
    due_date: Optional[dt.datetime] = None
    introduced_in_version_id: Optional[str] = None

class MitigationCreate(MitigationBase):
    pass

class MitigationUpdate(BaseModel):
    project_id: Optional[str] = None
    threat_id: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    owner: Optional[str] = None
    priority: Optional[str] = None
    type: Optional[str] = None
    assignee: Optional[str] = None
    due_date: Optional[dt.datetime] = None
    introduced_in_version_id: Optional[str] = None

class MitigationOut(MitigationBase):
    id: str
    created_at: dt.datetime
    updated_at: dt.datetime

    model_config = ConfigDict(from_attributes=True)

class DocumentBase(BaseModel):
    project_id: str
    name: str
    type: str
    size: int
    tag: str
    phase: Optional[str] = None
    uploaded_at: dt.datetime
    storage_key: Optional[str] = None
    linked_version_ids: Optional[List[str]] = None
    linked_threat_ids: Optional[List[str]] = None
    revision_group_id: Optional[str] = None
    revision_number: int = 1
    supersedes_document_id: Optional[str] = None
    superseded_by_document_id: Optional[str] = None
    is_current: bool = True

class DocumentCreatePayload(BaseModel):
    name: str
    type: str
    size: int
    tag: str
    phase: Optional[str] = None
    uploaded_at: Optional[dt.datetime] = None
    storage_key: Optional[str] = None
    linked_version_ids: Optional[List[str]] = None
    linked_threat_ids: Optional[List[str]] = None
    revision_group_id: Optional[str] = None
    revision_number: int = 1
    supersedes_document_id: Optional[str] = None
    superseded_by_document_id: Optional[str] = None
    is_current: bool = True

class DocumentCreate(DocumentBase):
    pass

class DocumentUpdate(BaseModel):
    project_id: Optional[str] = None
    name: Optional[str] = None
    type: Optional[str] = None
    size: Optional[int] = None
    tag: Optional[str] = None
    phase: Optional[str] = None
    uploaded_at: Optional[dt.datetime] = None
    linked_version_ids: Optional[List[str]] = None
    linked_threat_ids: Optional[List[str]] = None
    revision_group_id: Optional[str] = None
    revision_number: Optional[int] = None
    supersedes_document_id: Optional[str] = None
    superseded_by_document_id: Optional[str] = None
    is_current: Optional[bool] = None

class DocumentOut(DocumentBase):
    id: str
    created_at: dt.datetime
    updated_at: dt.datetime

    model_config = ConfigDict(from_attributes=True)

class VersionBase(BaseModel):
    project_id: str
    version_number: str
    version_type: str = "analysis"
    created_at: dt.datetime
    created_by: str
    context_snapshot: Any
    threat_ids: Optional[List[str]] = None
    mitigation_ids: Optional[List[str]] = None
    notes: Optional[str] = None

class VersionCreate(VersionBase):
    pass

class VersionUpdate(BaseModel):
    project_id: Optional[str] = None
    version_number: Optional[str] = None
    created_at: Optional[dt.datetime] = None
    created_by: Optional[str] = None
    context_snapshot: Optional[Any] = None
    threat_ids: Optional[List[str]] = None
    mitigation_ids: Optional[List[str]] = None
    notes: Optional[str] = None


class AcceptRiskPayload(BaseModel):
    reason: str
    reason_details: str
    owner: Optional[str] = None
    review_date: Optional[dt.datetime] = None

class VersionOut(VersionBase):
    id: str

    model_config = ConfigDict(from_attributes=True)


class VersionDetailOut(BaseModel):
    project_id: str
    current_version_id: Optional[str] = None
    version: VersionOut
    threats: List[ThreatOut] = Field(default_factory=list)
    mitigations: List[MitigationOut] = Field(default_factory=list)


class AnalysisArtifactsUpsert(BaseModel):
    parsed_output: Optional[Any] = None
    threats: List[Any] = Field(default_factory=list)
    graph: Optional[dict[str, Any]] = None
    scenarios: List[Any] = Field(default_factory=list)
    persist_threats: bool = True
    notes: Optional[str] = None


class AnalysisArtifactsOut(BaseModel):
    project_id: str
    version_id: str
    has_parsed_output: bool
    threats_count: int
    graph_nodes_count: int
    graph_edges_count: int
    scenarios_count: int
    linked_threat_ids: List[str] = Field(default_factory=list)
    artifacts: dict[str, Any] = Field(default_factory=dict)


class RunAnalysisRequest(BaseModel):
    phase: str
    methodology: str = "STRIDE"
    persist_threats: bool = True
    create_new_version: bool = False


class AnalysisRunOut(BaseModel):
    id: str
    project_id: str
    version_id: str
    trigger_type: str
    status: str
    started_at: dt.datetime
    finished_at: Optional[dt.datetime] = None
    duration_ms: Optional[int] = None
    stage_timings_json: Optional[dict[str, Any]] = None
    error_message: Optional[str] = None
    missing_fields: Optional[List[Any]] = None
    summary_json: Optional[dict[str, Any]] = None
    created_at: dt.datetime

    model_config = ConfigDict(from_attributes=True)


IntegrationType = Literal["GIT_WEBHOOK", "SAST_WEBHOOK", "DAST_WEBHOOK", "EMAIL_NOTIFICATION"]
IntegrationTriggerMode = Literal["WEBHOOK", "MANUAL"]
IntegrationStatus = Literal["CONNECTED", "ERROR", "DISABLED"]


class IntegrationConfigCreate(BaseModel):
    integration_type: IntegrationType
    provider: str
    phase_scope: Optional[str] = None
    trigger_mode: IntegrationTriggerMode = "WEBHOOK"
    status: IntegrationStatus = "CONNECTED"
    config_json: Optional[dict[str, Any]] = None
    secret: Optional[str] = None
    secret_ref: Optional[str] = None


class IntegrationConfigUpdate(BaseModel):
    provider: Optional[str] = None
    phase_scope: Optional[str] = None
    trigger_mode: Optional[IntegrationTriggerMode] = None
    status: Optional[IntegrationStatus] = None
    config_json: Optional[dict[str, Any]] = None
    secret: Optional[str] = None
    secret_ref: Optional[str] = None


class IntegrationConfigOut(BaseModel):
    id: str
    project_id: str
    integration_type: IntegrationType
    provider: str
    phase_scope: Optional[str] = None
    trigger_mode: IntegrationTriggerMode
    status: IntegrationStatus
    config_json: Optional[dict[str, Any]] = None
    secret_ref: Optional[str] = None
    last_success_at: Optional[dt.datetime] = None
    last_error: Optional[str] = None
    created_at: dt.datetime
    updated_at: dt.datetime

    @model_validator(mode="after")
    def hide_write_only_token(self) -> "IntegrationConfigOut":
        if isinstance(self.config_json, dict) and "access_token" in self.config_json:
            sanitized = dict(self.config_json)
            sanitized.pop("access_token", None)
            self.config_json = sanitized
        return self

    model_config = ConfigDict(from_attributes=True)


class IntegrationEventOut(BaseModel):
    id: str
    integration_id: str
    project_id: str
    event_type: str
    external_event_id: Optional[str] = None
    payload_hash: str
    payload_storage_key: Optional[str] = None
    commit_hash: Optional[str] = None
    branch: Optional[str] = None
    processing_status: str
    error_message: Optional[str] = None
    created_at: dt.datetime
    processed_at: Optional[dt.datetime] = None
    linked_version_id: Optional[str] = None
    linked_run_id: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class IntegrationWebhookResponse(BaseModel):
    status: Literal["accepted", "ignored_duplicate", "failed_validation", "failed_processing"]
    message: str
    project_id: str
    version_id: Optional[str] = None
    event_id: Optional[str] = None
    analysis_run_id: Optional[str] = None
    details: dict[str, Any] = Field(default_factory=dict)


ProjectBase.model_rebuild()
ProjectUpdate.model_rebuild()
ProjectOut.model_rebuild()
