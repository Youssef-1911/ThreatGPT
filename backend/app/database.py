from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import text

DATABASE_URL = "sqlite:///./backend.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def _sqlite_add_column_if_missing(conn, table_name: str, column_name: str, ddl: str) -> None:
    existing = conn.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
    existing_names = {row[1] for row in existing}
    if column_name not in existing_names:
        conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {ddl}"))


def _sqlite_table_exists(conn, table_name: str) -> bool:
    row = conn.execute(
        text("SELECT name FROM sqlite_master WHERE type='table' AND name=:table_name"),
        {"table_name": table_name},
    ).fetchone()
    return row is not None


def run_sqlite_migrations() -> None:
    with engine.begin() as conn:
        _sqlite_add_column_if_missing(conn, "users", "organization", "organization TEXT")
        _sqlite_add_column_if_missing(conn, "users", "avatar_url", "avatar_url TEXT")
        _sqlite_add_column_if_missing(conn, "users", "integrations", "integrations JSON")
        _sqlite_add_column_if_missing(conn, "users", "account_status", "account_status TEXT DEFAULT 'Approved'")
        _sqlite_add_column_if_missing(conn, "users", "entity_details", "entity_details JSON")
        _sqlite_add_column_if_missing(conn, "users", "account_reviewed_at", "account_reviewed_at DATETIME")
        _sqlite_add_column_if_missing(conn, "users", "account_reviewed_by", "account_reviewed_by TEXT")
        _sqlite_add_column_if_missing(conn, "users", "rejection_reason", "rejection_reason TEXT")

        _sqlite_add_column_if_missing(conn, "projects", "owner_id", "owner_id TEXT")

        _sqlite_add_column_if_missing(conn, "threats", "identified_in_phase", "identified_in_phase TEXT")
        _sqlite_add_column_if_missing(conn, "threats", "introduced_in_version_id", "introduced_in_version_id TEXT")
        _sqlite_add_column_if_missing(conn, "threats", "grounded_finding", "grounded_finding TEXT")
        _sqlite_add_column_if_missing(conn, "threats", "accepted_risk_info", "accepted_risk_info JSON")
        _sqlite_add_column_if_missing(conn, "threats", "events", "events JSON")

        _sqlite_add_column_if_missing(conn, "mitigations", "threat_id", "threat_id TEXT")
        _sqlite_add_column_if_missing(conn, "mitigations", "priority", "priority TEXT")
        _sqlite_add_column_if_missing(conn, "mitigations", "type", "type TEXT")
        _sqlite_add_column_if_missing(conn, "mitigations", "assignee", "assignee TEXT")
        _sqlite_add_column_if_missing(conn, "mitigations", "due_date", "due_date DATETIME")
        _sqlite_add_column_if_missing(conn, "mitigations", "introduced_in_version_id", "introduced_in_version_id TEXT")

        _sqlite_add_column_if_missing(conn, "project_documents", "linked_version_ids", "linked_version_ids JSON")
        _sqlite_add_column_if_missing(conn, "project_documents", "linked_threat_ids", "linked_threat_ids JSON")
        _sqlite_add_column_if_missing(conn, "project_documents", "storage_key", "storage_key TEXT")
        _sqlite_add_column_if_missing(conn, "project_documents", "phase", "phase TEXT")
        _sqlite_add_column_if_missing(conn, "project_documents", "revision_group_id", "revision_group_id TEXT")
        _sqlite_add_column_if_missing(conn, "project_documents", "revision_number", "revision_number INTEGER NOT NULL DEFAULT 1")
        _sqlite_add_column_if_missing(conn, "project_documents", "supersedes_document_id", "supersedes_document_id TEXT")
        _sqlite_add_column_if_missing(conn, "project_documents", "superseded_by_document_id", "superseded_by_document_id TEXT")
        _sqlite_add_column_if_missing(conn, "project_documents", "is_current", "is_current BOOLEAN NOT NULL DEFAULT 1")

        _sqlite_add_column_if_missing(conn, "project_versions", "threat_ids", "threat_ids JSON")
        _sqlite_add_column_if_missing(conn, "project_versions", "mitigation_ids", "mitigation_ids JSON")
        _sqlite_add_column_if_missing(conn, "project_versions", "version_type", "version_type TEXT NOT NULL DEFAULT 'analysis'")

        # Snapshot tables (historical state per version)
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS threat_snapshots (
                    id TEXT PRIMARY KEY,
                    version_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    threat_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    severity TEXT,
                    status TEXT,
                    risk_score FLOAT,
                    affected_component TEXT,
                    identified_stage TEXT,
                    source TEXT,
                    created_at DATETIME NOT NULL
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS mitigation_snapshots (
                    id TEXT PRIMARY KEY,
                    version_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    mitigation_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL,
                    priority TEXT,
                    type TEXT,
                    assignee TEXT,
                    due_date DATETIME,
                    created_at DATETIME NOT NULL
                )
                """
            )
        )

        if _sqlite_table_exists(conn, "threat_snapshots"):
            _sqlite_add_column_if_missing(conn, "threat_snapshots", "severity", "severity TEXT")
            _sqlite_add_column_if_missing(conn, "threat_snapshots", "status", "status TEXT")
            _sqlite_add_column_if_missing(conn, "threat_snapshots", "risk_score", "risk_score FLOAT")
            _sqlite_add_column_if_missing(conn, "threat_snapshots", "affected_component", "affected_component TEXT")
            _sqlite_add_column_if_missing(conn, "threat_snapshots", "identified_stage", "identified_stage TEXT")
            _sqlite_add_column_if_missing(conn, "threat_snapshots", "source", "source TEXT")

        if _sqlite_table_exists(conn, "mitigation_snapshots"):
            _sqlite_add_column_if_missing(conn, "mitigation_snapshots", "priority", "priority TEXT")
            _sqlite_add_column_if_missing(conn, "mitigation_snapshots", "type", "type TEXT")
            _sqlite_add_column_if_missing(conn, "mitigation_snapshots", "assignee", "assignee TEXT")
            _sqlite_add_column_if_missing(conn, "mitigation_snapshots", "due_date", "due_date DATETIME")
            _sqlite_add_column_if_missing(conn, "mitigation_snapshots", "description", "description TEXT")

        # Analysis run logs (operational/audit trail)
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS analysis_runs (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    version_id TEXT NOT NULL,
                    trigger_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at DATETIME NOT NULL,
                    finished_at DATETIME,
                    duration_ms INTEGER,
                    stage_timings_json JSON,
                    error_message TEXT,
                    missing_fields JSON,
                    summary_json JSON,
                    created_at DATETIME NOT NULL
                )
                """
            )
        )

        if _sqlite_table_exists(conn, "analysis_runs"):
            _sqlite_add_column_if_missing(conn, "analysis_runs", "trigger_type", "trigger_type TEXT")
            _sqlite_add_column_if_missing(conn, "analysis_runs", "status", "status TEXT")
            _sqlite_add_column_if_missing(conn, "analysis_runs", "started_at", "started_at DATETIME")
            _sqlite_add_column_if_missing(conn, "analysis_runs", "finished_at", "finished_at DATETIME")
            _sqlite_add_column_if_missing(conn, "analysis_runs", "duration_ms", "duration_ms INTEGER")
            _sqlite_add_column_if_missing(conn, "analysis_runs", "stage_timings_json", "stage_timings_json JSON")
            _sqlite_add_column_if_missing(conn, "analysis_runs", "error_message", "error_message TEXT")
            _sqlite_add_column_if_missing(conn, "analysis_runs", "missing_fields", "missing_fields JSON")
            _sqlite_add_column_if_missing(conn, "analysis_runs", "summary_json", "summary_json JSON")
            _sqlite_add_column_if_missing(conn, "analysis_runs", "created_at", "created_at DATETIME")

        # Integration configuration (per project/provider webhook setup)
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS integration_configs (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    integration_type TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    phase_scope TEXT,
                    trigger_mode TEXT NOT NULL,
                    status TEXT NOT NULL,
                    config_json JSON,
                    secret_hash TEXT,
                    secret_ref TEXT,
                    last_success_at DATETIME,
                    last_error TEXT,
                    created_at DATETIME NOT NULL,
                    updated_at DATETIME NOT NULL
                )
                """
            )
        )
        if _sqlite_table_exists(conn, "integration_configs"):
            _sqlite_add_column_if_missing(conn, "integration_configs", "phase_scope", "phase_scope TEXT")
            _sqlite_add_column_if_missing(conn, "integration_configs", "trigger_mode", "trigger_mode TEXT")
            _sqlite_add_column_if_missing(conn, "integration_configs", "status", "status TEXT")
            _sqlite_add_column_if_missing(conn, "integration_configs", "config_json", "config_json JSON")
            _sqlite_add_column_if_missing(conn, "integration_configs", "secret_hash", "secret_hash TEXT")
            _sqlite_add_column_if_missing(conn, "integration_configs", "secret_ref", "secret_ref TEXT")
            _sqlite_add_column_if_missing(conn, "integration_configs", "last_success_at", "last_success_at DATETIME")
            _sqlite_add_column_if_missing(conn, "integration_configs", "last_error", "last_error TEXT")
            _sqlite_add_column_if_missing(conn, "integration_configs", "created_at", "created_at DATETIME")
            _sqlite_add_column_if_missing(conn, "integration_configs", "updated_at", "updated_at DATETIME")

        # Incoming integration event log + dedupe surface + linkage to versions/runs.
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS integration_events (
                    id TEXT PRIMARY KEY,
                    integration_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    external_event_id TEXT,
                    payload_hash TEXT NOT NULL,
                    payload_storage_key TEXT,
                    raw_payload_json JSON,
                    commit_hash TEXT,
                    branch TEXT,
                    processing_status TEXT NOT NULL,
                    error_message TEXT,
                    created_at DATETIME NOT NULL,
                    processed_at DATETIME,
                    linked_version_id TEXT,
                    linked_run_id TEXT
                )
                """
            )
        )
        if _sqlite_table_exists(conn, "integration_events"):
            _sqlite_add_column_if_missing(conn, "integration_events", "payload_storage_key", "payload_storage_key TEXT")
            _sqlite_add_column_if_missing(conn, "integration_events", "raw_payload_json", "raw_payload_json JSON")
            _sqlite_add_column_if_missing(conn, "integration_events", "commit_hash", "commit_hash TEXT")
            _sqlite_add_column_if_missing(conn, "integration_events", "branch", "branch TEXT")
            _sqlite_add_column_if_missing(conn, "integration_events", "processing_status", "processing_status TEXT")
            _sqlite_add_column_if_missing(conn, "integration_events", "error_message", "error_message TEXT")
            _sqlite_add_column_if_missing(conn, "integration_events", "processed_at", "processed_at DATETIME")
            _sqlite_add_column_if_missing(conn, "integration_events", "linked_version_id", "linked_version_id TEXT")
            _sqlite_add_column_if_missing(conn, "integration_events", "linked_run_id", "linked_run_id TEXT")

        # Threat status normalization (legacy -> frontend vocabulary)
        conn.execute(text("UPDATE threats SET status = 'Identified' WHERE status = 'Open'"))
        conn.execute(text("UPDATE threats SET status = 'In Review' WHERE status = 'In Progress'"))
        conn.execute(
            text("UPDATE threat_snapshots SET status = 'Identified' WHERE status = 'Open'")
        )
        conn.execute(
            text("UPDATE threat_snapshots SET status = 'In Review' WHERE status = 'In Progress'")
        )
        conn.execute(
            text("UPDATE users SET account_status = 'Approved' WHERE account_status IS NULL OR account_status = ''")
        )
