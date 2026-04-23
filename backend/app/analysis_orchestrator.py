from __future__ import annotations

import datetime as dt
import logging
import time
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

from . import models
from .attack_graph_engine import AttackGraphEngine
from .attack_scenario_engine import AttackScenarioEngine
from .document_ingestion import ingest_documents
from .generation_engine import GenerationEngine
from .parsing_engine import ParsingEngine
from .routers.versions import persist_analysis_artifacts_for_version

UPLOAD_ROOT = Path(__file__).resolve().parent / "uploads"


class AnalysisOrchestrator:
    def __init__(
        self,
        parsing_engine: ParsingEngine | None = None,
        generation_engine: GenerationEngine | None = None,
        attack_graph_engine: AttackGraphEngine | None = None,
        attack_scenario_engine: AttackScenarioEngine | None = None,
    ) -> None:
        self.parsing_engine = parsing_engine or ParsingEngine()
        self.generation_engine = generation_engine or GenerationEngine()
        self.attack_graph_engine = attack_graph_engine or AttackGraphEngine()
        self.attack_scenario_engine = attack_scenario_engine or AttackScenarioEngine()

    def run_full_analysis(
        self,
        db: Session,
        project_id: str,
        version_id: str,
        phase: str,
        methodology: str = "STRIDE",
        persist_threats: bool = True,
        trigger_type: str = "manual",
    ) -> dict[str, Any]:
        missing_fields: list[str] = []
        run_started_perf = time.perf_counter()

        parsing_status = "not_started"
        generation_status = "not_started"
        graph_status = "not_started"
        scenario_status = "not_started"
        saved_artifacts = {
            "parsed_output": False,
            "threats": 0,
            "graph": False,
            "scenarios": 0,
        }
        stage_timings_ms: dict[str, int] = {}

        project = db.query(models.Project).filter(models.Project.id == project_id).first()
        if not project:
            return self._build_response(
                status="failed",
                project_id=project_id,
                version_id=version_id,
                parsing_status=parsing_status,
                generation_status=generation_status,
                graph_status=graph_status,
                scenario_status=scenario_status,
                saved_artifacts=saved_artifacts,
                missing_fields=["project"],
            )

        version = (
            db.query(models.ProjectVersion)
            .filter(models.ProjectVersion.id == version_id, models.ProjectVersion.project_id == project_id)
            .first()
        )
        if not version:
            return self._build_response(
                status="failed",
                project_id=project_id,
                version_id=version_id,
                parsing_status=parsing_status,
                generation_status=generation_status,
                graph_status=graph_status,
                scenario_status=scenario_status,
                saved_artifacts=saved_artifacts,
                missing_fields=["version"],
            )

        analysis_run = self._start_analysis_run(
            db,
            project_id=project_id,
            version_id=version_id,
            trigger_type=trigger_type,
        )

        try:
            stage_start = time.perf_counter()
            document_records = (
                db.query(models.ProjectDocument)
                .filter(models.ProjectDocument.project_id == project_id)
                .order_by(models.ProjectDocument.created_at.asc())
                .all()
            )

            version_linked_documents = [
                document
                for document in document_records
                if isinstance(document.linked_version_ids, list) and version_id in document.linked_version_ids
            ]

            # Always use analysis-eligible project documents so new uploads between
            # analysis runs are included while transport metadata (Git webhook JSON)
            # never becomes architecture evidence.
            selected_documents = [
                document
                for document in document_records
                if self._is_current_document(document) and self._is_analysis_eligible_document(document)
            ]
            if not selected_documents:
                missing_fields.append("documents")
            selected_document_ids = [
                document.id
                for document in selected_documents
                if isinstance(document.id, str) and document.id
            ]
            stage_timings_ms["document_selection"] = self._elapsed_ms(stage_start)

            stage_start = time.perf_counter()
            ingest_requests: list[dict[str, Any]] = []
            for document in selected_documents:
                resolved_file_path = self._resolve_document_file_path(document)
                if not resolved_file_path:
                    missing_fields.append(f"documents[{document.id}].storage_key")
                    continue
                if not resolved_file_path.exists():
                    missing_fields.append(f"documents[{document.id}].file_not_found")
                    continue

                ingest_requests.append(
                    {
                        "file_path": str(resolved_file_path),
                        "file_type": self._infer_file_type(document, resolved_file_path),
                        "phase": document.phase or phase,
                        "tag": document.tag,
                    }
                )

            ingestion_result = ingest_documents(ingest_requests) if ingest_requests else {
                "documents": [],
                "errors": [],
                "raw_text": "",
                "security_findings": {
                    "sast": [],
                    "dast": [],
                    "sca": [],
                    "infrastructure": [],
                    "manual_review": [],
                },
                "evidence_by_category": {
                    "architecture": [],
                    "data_flows": [],
                    "source_code": [],
                    "sast": [],
                    "dast": [],
                    "sca": [],
                    "infrastructure": [],
                    "manual_review": [],
                    "git_metadata": [],
                },
                "source_map": [],
            }

            ingestion_errors = ingestion_result.get("errors")
            if isinstance(ingestion_errors, list) and ingestion_errors:
                missing_fields.append("ingestion.errors")
            ingestion_summary = self._build_ingestion_summary(ingestion_result)
            stage_timings_ms["ingestion"] = self._elapsed_ms(stage_start)

            stage_start = time.perf_counter()
            evidence_package = {
                "phase": phase,
                "raw_text": ingestion_result.get("raw_text", ""),
                "security_findings": ingestion_result.get("security_findings", {}),
                "evidence_by_category": ingestion_result.get("evidence_by_category", {}),
                "source_map": ingestion_result.get("source_map", []),
            }

            evidence_package = self._truncate_evidence_package(evidence_package)
            if evidence_package.get("truncation_warning"):
                missing_fields.append("evidence.truncated")

            evidence_hash = self.parsing_engine.compute_evidence_hash(evidence_package)
            cached_parsed_output = self._find_cached_parsed_output(db, project_id, evidence_hash)
            if cached_parsed_output is not None:
                logger.info("Parse cache hit for hash %s — skipping GPT parse call", evidence_hash)
                parsing_result = {"status": "ready", "parsed_data": cached_parsed_output, "missing_fields": []}
            else:
                existing_entities = self._load_existing_parsed_entities(db, project_id)
                parsing_result = self.parsing_engine.parse_evidence_package(
                    evidence_package,
                    existing_components=existing_entities.get("components"),
                    existing_entry_points=existing_entities.get("entry_points"),
                    existing_assets=existing_entities.get("assets"),
                )
            parsing_status = (
                parsing_result.get("status", "missing_fields")
                if isinstance(parsing_result, dict)
                else "missing_fields"
            )
            parsing_missing = parsing_result.get("missing_fields") if isinstance(parsing_result, dict) else []
            if isinstance(parsing_missing, list):
                missing_fields.extend(str(item) for item in parsing_missing)

            parsed_data = parsing_result.get("parsed_data") if isinstance(parsing_result, dict) else {}
            if not isinstance(parsed_data, dict):
                parsed_data = {}
            stage_timings_ms["parsing"] = self._elapsed_ms(stage_start)

            if parsing_status != "ready":
                response = self._build_response(
                    status="failed",
                    project_id=project_id,
                    version_id=version_id,
                    parsing_status=parsing_status,
                    generation_status=generation_status,
                    graph_status=graph_status,
                    scenario_status=scenario_status,
                    saved_artifacts=saved_artifacts,
                    missing_fields=list(dict.fromkeys(missing_fields)),
                )
                self._finalize_analysis_run(
                    db,
                    analysis_run=analysis_run,
                    status=response["status"],
                    stage_timings_ms=stage_timings_ms,
                    missing_fields=response["missing_fields"],
                    summary_json={
                        "saved_artifacts": saved_artifacts,
                        "threats_count": 0,
                        "graph_nodes_count": 0,
                        "graph_edges_count": 0,
                        "scenarios_count": 0,
                    },
                    total_duration_ms=self._elapsed_ms(run_started_perf),
                )
                return response

            stage_start = time.perf_counter()
            # TODO: Expand DREAD/custom methodology support in generation validation and downstream scoring.
            generation_result = self.generation_engine.generate_threats(
                parsed_data=parsed_data,
                phase=phase,
                methodology=methodology,
                evidence_package=evidence_package,
            )
            generation_status = (
                generation_result.get("status", "invalid_output")
                if isinstance(generation_result, dict)
                else "invalid_output"
            )
            generation_missing = generation_result.get("missing_fields") if isinstance(generation_result, dict) else []
            if isinstance(generation_missing, list):
                missing_fields.extend(str(item) for item in generation_missing)

            threats = generation_result.get("threats") if isinstance(generation_result, dict) else []
            if not isinstance(threats, list):
                threats = []
            ungrounded_count = generation_result.get("ungrounded_count", 0) if isinstance(generation_result, dict) else 0
            stage_timings_ms["generation"] = self._elapsed_ms(stage_start)

            if generation_status == "invalid_output":
                response = self._build_response(
                    status="failed",
                    project_id=project_id,
                    version_id=version_id,
                    parsing_status=parsing_status,
                    generation_status=generation_status,
                    graph_status=graph_status,
                    scenario_status=scenario_status,
                    saved_artifacts=saved_artifacts,
                    missing_fields=list(dict.fromkeys(missing_fields)),
                )
                self._finalize_analysis_run(
                    db,
                    analysis_run=analysis_run,
                    status=response["status"],
                    stage_timings_ms=stage_timings_ms,
                    missing_fields=response["missing_fields"],
                    summary_json={
                        "saved_artifacts": saved_artifacts,
                        "threats_count": len(threats),
                        "graph_nodes_count": 0,
                        "graph_edges_count": 0,
                        "scenarios_count": 0,
                    },
                    total_duration_ms=self._elapsed_ms(run_started_perf),
                )
                return response

            stage_start = time.perf_counter()
            graph = self.attack_graph_engine.build_graph(parsed_data=parsed_data, threats=threats)
            graph_nodes = graph.get("nodes") if isinstance(graph, dict) else []
            graph_edges = graph.get("edges") if isinstance(graph, dict) else []
            graph_status = "ready" if isinstance(graph_nodes, list) and isinstance(graph_edges, list) else "failed"
            if graph_status != "ready":
                missing_fields.append("graph")
            stage_timings_ms["graph"] = self._elapsed_ms(stage_start)

            stage_start = time.perf_counter()
            scenario_result = self.attack_scenario_engine.generate_scenarios(
                graph=graph if isinstance(graph, dict) else {},
                parsed_data=parsed_data,
                threats=threats,
            )
            scenario_status = (
                scenario_result.get("status", "invalid_output")
                if isinstance(scenario_result, dict)
                else "invalid_output"
            )
            scenarios = scenario_result.get("scenarios") if isinstance(scenario_result, dict) else []
            if not isinstance(scenarios, list):
                scenarios = []
            scenario_missing = scenario_result.get("missing_fields") if isinstance(scenario_result, dict) else []
            if isinstance(scenario_missing, list):
                missing_fields.extend(str(item) for item in scenario_missing)
            stage_timings_ms["scenarios"] = self._elapsed_ms(stage_start)

            stage_start = time.perf_counter()
            persistence_result = persist_analysis_artifacts_for_version(
                db,
                project=project,
                version=version,
                parsed_output=parsed_data,
                threats=threats,
                graph=graph if isinstance(graph, dict) else {"nodes": [], "edges": []},
                scenarios=scenarios,
                persist_threats=persist_threats,
                notes=f"Run full analysis pipeline ({phase}/{methodology})",
                evidence_hash=evidence_hash,
            )
            stage_timings_ms["persistence"] = self._elapsed_ms(stage_start)

            self._link_documents_to_analysis_version(
                db=db,
                project_id=project_id,
                document_ids=selected_document_ids,
                version_id=version_id,
            )

            saved_artifacts = {
                "parsed_output": bool(persistence_result.get("has_parsed_output")),
                "threats": int(persistence_result.get("threats_count", 0)),
                "graph": bool(
                    persistence_result.get("graph_nodes_count", 0)
                    or persistence_result.get("graph_edges_count", 0)
                ),
                "scenarios": int(persistence_result.get("scenarios_count", 0)),
                "ungrounded_threats": ungrounded_count,
            }

            overall_status = "ready"
            if scenario_status != "ready":
                overall_status = "partial"
            if graph_status != "ready":
                overall_status = "failed"

            response = self._build_response(
                status=overall_status,
                project_id=project_id,
                version_id=version_id,
                parsing_status=parsing_status,
                generation_status=generation_status,
                graph_status=graph_status,
                scenario_status=scenario_status,
                saved_artifacts=saved_artifacts,
                missing_fields=list(dict.fromkeys(missing_fields)),
            )

            self._finalize_analysis_run(
                db,
                analysis_run=analysis_run,
                status=overall_status,
                stage_timings_ms=stage_timings_ms,
                missing_fields=response["missing_fields"],
                summary_json={
                    "saved_artifacts": saved_artifacts,
                    "threats_count": len(threats),
                    "ungrounded_threats_count": ungrounded_count,
                    "graph_nodes_count": len(graph_nodes) if isinstance(graph_nodes, list) else 0,
                    "graph_edges_count": len(graph_edges) if isinstance(graph_edges, list) else 0,
                    "scenarios_count": len(scenarios),
                    "ingestion_summary": ingestion_summary,
                },
                total_duration_ms=self._elapsed_ms(run_started_perf),
            )

            # TODO: Move orchestration execution to async/background jobs for long-running pipelines.
            # TODO: Add integration-triggered execution hooks (Git/webhooks/connectors) with policy controls.
            # TODO: Add retry_count and retry support for transient AI/network failures.
            # TODO: Add metrics aggregation dashboard over analysis run logs.
            # TODO: Add retention/cleanup policy for historical run logs.
            return response

        except Exception as exc:
            failure_response = self._build_response(
                status="failed",
                project_id=project_id,
                version_id=version_id,
                parsing_status=parsing_status,
                generation_status=generation_status,
                graph_status=graph_status,
                scenario_status=scenario_status,
                saved_artifacts=saved_artifacts,
                missing_fields=list(dict.fromkeys(missing_fields + ["analysis_exception"])),
            )
            self._finalize_analysis_run(
                db,
                analysis_run=analysis_run,
                status="failed",
                stage_timings_ms=stage_timings_ms,
                missing_fields=failure_response["missing_fields"],
                summary_json={
                    "saved_artifacts": saved_artifacts,
                    "threats_count": 0,
                    "graph_nodes_count": 0,
                    "graph_edges_count": 0,
                    "scenarios_count": 0,
                },
                total_duration_ms=self._elapsed_ms(run_started_perf),
                error_message=str(exc),
            )
            return failure_response

    def _find_cached_parsed_output(
        self,
        db: Session,
        project_id: str,
        evidence_hash: str,
    ) -> dict[str, Any] | None:
        """Return the cached parsed_output from the most recent version of this project
        whose context_snapshot carries a matching evidence_hash, or None if not found."""
        versions = (
            db.query(models.ProjectVersion)
            .filter(
                models.ProjectVersion.project_id == project_id,
                models.ProjectVersion.version_type == "analysis",
            )
            .order_by(models.ProjectVersion.created_at.desc())
            .limit(20)
            .all()
        )
        for v in versions:
            snapshot = v.context_snapshot
            if not isinstance(snapshot, dict):
                continue
            if snapshot.get("evidence_hash") != evidence_hash:
                continue
            artifacts = snapshot.get("analysis_artifacts")
            if not isinstance(artifacts, dict):
                continue
            parsed_output = artifacts.get("parsed_output")
            if isinstance(parsed_output, dict) and parsed_output:
                return parsed_output
        return None

    def _load_existing_parsed_entities(
        self,
        db: Session,
        project_id: str,
    ) -> dict[str, list[dict[str, Any]]]:
        """Return components, entry_points, and assets from the most recent analysis version.

        Used as stable ID anchors so that re-runs reuse the same IDs for matching
        entities rather than letting the AI invent new ones.  Returns an empty dict
        when no prior version exists (version 1 of a project).
        """
        versions = (
            db.query(models.ProjectVersion)
            .filter(
                models.ProjectVersion.project_id == project_id,
                models.ProjectVersion.version_type == "analysis",
            )
            .order_by(models.ProjectVersion.created_at.desc())
            .limit(5)
            .all()
        )
        for v in versions:
            snapshot = v.context_snapshot
            if not isinstance(snapshot, dict):
                continue
            artifacts = snapshot.get("analysis_artifacts")
            if not isinstance(artifacts, dict):
                continue
            parsed_output = artifacts.get("parsed_output")
            if not isinstance(parsed_output, dict):
                continue
            components = parsed_output.get("components")
            if not (isinstance(components, list) and components):
                continue
            entry_points = parsed_output.get("entry_points") or []
            assets = parsed_output.get("assets") or []
            logger.debug(
                "Loaded %d components, %d entry points, %d assets from version %s for ID stability",
                len(components),
                len(entry_points),
                len(assets),
                v.id,
            )
            return {
                "components": components,
                "entry_points": entry_points if isinstance(entry_points, list) else [],
                "assets": assets if isinstance(assets, list) else [],
            }
        return {}

    def _resolve_document_file_path(self, document: models.ProjectDocument) -> Path | None:
        storage_key = document.storage_key
        if isinstance(storage_key, str) and storage_key.strip():
            return UPLOAD_ROOT / storage_key
        return None

    def _infer_file_type(self, document: models.ProjectDocument, file_path: Path) -> str:
        suffix = file_path.suffix.lower().lstrip(".")
        if suffix:
            return suffix

        document_type = document.type.lower() if isinstance(document.type, str) else ""
        mapping = {
            "text/plain": "txt",
            "application/json": "json",
            "application/pdf": "pdf",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
        }
        return mapping.get(document_type, "txt")

    def _is_analysis_eligible_document(self, document: models.ProjectDocument) -> bool:
        tag = document.tag.strip().lower().replace(" ", "_").replace("-", "_") if isinstance(document.tag, str) else ""
        name = document.name.strip().lower() if isinstance(document.name, str) else ""
        storage_key = document.storage_key.strip().lower() if isinstance(document.storage_key, str) else ""
        if tag in {"git_metadata", "webhook", "webhook_metadata"}:
            return False
        if name.startswith("git_webhook_") or "git_webhook_git_commit" in storage_key:
            return False
        return True

    def _is_current_document(self, document: models.ProjectDocument) -> bool:
        return bool(getattr(document, "is_current", True))

    def _link_documents_to_analysis_version(
        self,
        *,
        db: Session,
        project_id: str,
        document_ids: list[str],
        version_id: str,
    ) -> None:
        if not document_ids:
            return

        documents = (
            db.query(models.ProjectDocument)
            .filter(
                models.ProjectDocument.project_id == project_id,
                models.ProjectDocument.id.in_(document_ids),
            )
            .all()
        )
        updated = False
        for document in documents:
            linked_version_ids = list(document.linked_version_ids or [])
            if version_id in linked_version_ids:
                continue
            linked_version_ids.append(version_id)
            document.linked_version_ids = linked_version_ids
            document.updated_at = dt.datetime.utcnow()
            updated = True

        if updated:
            db.commit()

    def _start_analysis_run(
        self,
        db: Session,
        *,
        project_id: str,
        version_id: str,
        trigger_type: str,
    ) -> models.AnalysisRun:
        now = self._utcnow()
        run = models.AnalysisRun(
            id=str(uuid.uuid4()),
            project_id=project_id,
            version_id=version_id,
            trigger_type=trigger_type,
            status="running",
            started_at=now,
            finished_at=None,
            duration_ms=None,
            stage_timings_json={},
            error_message=None,
            missing_fields=None,
            summary_json=None,
            created_at=now,
        )
        db.add(run)
        db.commit()
        db.refresh(run)
        return run

    def _finalize_analysis_run(
        self,
        db: Session,
        *,
        analysis_run: models.AnalysisRun,
        status: str,
        stage_timings_ms: dict[str, int],
        missing_fields: list[str],
        summary_json: dict[str, Any],
        total_duration_ms: int,
        error_message: str | None = None,
    ) -> None:
        analysis_run.status = status
        analysis_run.finished_at = self._utcnow()
        analysis_run.duration_ms = total_duration_ms
        analysis_run.stage_timings_json = dict(stage_timings_ms)
        analysis_run.error_message = error_message
        analysis_run.missing_fields = list(dict.fromkeys(missing_fields))
        analysis_run.summary_json = dict(summary_json)
        db.commit()

    def _elapsed_ms(self, perf_start: float) -> int:
        return max(0, int((time.perf_counter() - perf_start) * 1000))

    def _utcnow(self) -> dt.datetime:
        return dt.datetime.now(dt.UTC).replace(tzinfo=None)

    def _truncate_evidence_package(self, evidence_package: dict[str, Any]) -> dict[str, Any]:
        """Ensure the evidence package stays within a safe prompt size.

        Priority order (highest → lowest): architecture, data_flows, manual_review,
        sast, infrastructure, sca, dast.  High-priority evidence is kept in full;
        lower-priority sections are truncated proportionally when the total exceeds
        MAX_EVIDENCE_CHARS.  A truncation_warning is added to missing_fields when
        any content is cut so the caller can surface it in the analysis response.
        """
        MAX_EVIDENCE_CHARS = 80_000

        raw_text: str = evidence_package.get("raw_text") or ""
        if len(raw_text) <= MAX_EVIDENCE_CHARS:
            return evidence_package

        # Priority order for keeping evidence
        PRIORITY_CATEGORIES = [
            "architecture",
            "data_flows",
            "source_code",
            "manual_review",
            "sast",
            "infrastructure",
            "sca",
            "dast",
        ]

        evidence_by_category: dict[str, Any] = dict(evidence_package.get("evidence_by_category") or {})
        security_findings: dict[str, Any] = dict(evidence_package.get("security_findings") or {})

        # Rebuild raw_text from category buckets in priority order, stopping at the limit.
        budget = MAX_EVIDENCE_CHARS
        truncated_parts: list[str] = []
        truncated = False

        for category in PRIORITY_CATEGORIES:
            items = evidence_by_category.get(category)
            if not isinstance(items, list):
                continue
            for item in items:
                chunk = item.get("raw_text") or ""
                header = f"[Category: {category}]\n"
                full = header + chunk
                if len(full) <= budget:
                    truncated_parts.append(full)
                    budget -= len(full)
                else:
                    # Take as much of this chunk as fits.
                    remaining = budget - len(header)
                    if remaining > 200:
                        truncated_parts.append(header + chunk[:remaining] + "\n[...truncated]")
                    truncated = True
                    budget = 0
                    break
            if budget <= 0:
                truncated = True
                break

        truncated_raw_text = "\n\n".join(truncated_parts)

        result = dict(evidence_package)
        result["raw_text"] = truncated_raw_text
        if truncated:
            result["truncation_warning"] = (
                f"Evidence truncated to {MAX_EVIDENCE_CHARS} chars. "
                "Lower-priority categories (dast, sca, infrastructure) may be partially excluded."
            )
        return result

    def _build_ingestion_summary(self, ingestion_result: dict[str, Any]) -> dict[str, Any]:
        source_map = ingestion_result.get("source_map") or []
        errors = ingestion_result.get("errors") or []
        security_findings = ingestion_result.get("security_findings") or {}

        source_map_clean = [
            {
                "file_name": entry.get("file_name", ""),
                "category": entry.get("category", ""),
                "phase_bucket": entry.get("phase_bucket", ""),
            }
            for entry in source_map
            if isinstance(entry, dict)
        ]

        errors_clean = [
            {
                "file_name": str(Path(e.get("file_path", "")).name) if e.get("file_path") else "",
                "file_type": e.get("file_type", ""),
                "error": e.get("error", ""),
            }
            for e in errors
            if isinstance(e, dict)
        ]

        findings_counts = {
            key: len(val) if isinstance(val, list) else 0
            for key, val in security_findings.items()
        }

        return {
            "files_processed": len(source_map_clean),
            "files_failed": len(errors_clean),
            "source_map": source_map_clean,
            "errors": errors_clean,
            "security_findings_counts": findings_counts,
        }

    def _build_response(
        self,
        *,
        status: str,
        project_id: str,
        version_id: str,
        parsing_status: str,
        generation_status: str,
        graph_status: str,
        scenario_status: str,
        saved_artifacts: dict[str, Any],
        missing_fields: list[str],
    ) -> dict[str, Any]:
        return {
            "status": status,
            "project_id": project_id,
            "version_id": version_id,
            "parsing_status": parsing_status,
            "generation_status": generation_status,
            "graph_status": graph_status,
            "scenario_status": scenario_status,
            "saved_artifacts": saved_artifacts,
            "missing_fields": missing_fields,
        }
