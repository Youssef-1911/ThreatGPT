import datetime as dt
import re
import uuid
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from .. import models, schemas
from ..deps import get_db, get_current_user
from ..versioning_service import capture_version_snapshots

router = APIRouter(prefix="/projects/{project_id}/versions", tags=["versions"])


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


def get_version_or_404(db: Session, project_id: str, version_id: str) -> models.ProjectVersion:
    version = (
        db.query(models.ProjectVersion)
        .filter(models.ProjectVersion.id == version_id, models.ProjectVersion.project_id == project_id)
        .first()
    )
    if not version:
        raise HTTPException(status_code=404, detail="Version not found")
    return version



def _threat_state_for_version(
    db: Session,
    *,
    project_id: str,
    version: models.ProjectVersion,
) -> dict[str, dict]:
    snapshots = (
        db.query(models.ThreatSnapshot)
        .filter(models.ThreatSnapshot.version_id == version.id)
        .all()
    )
    if snapshots:
        return {
            s.threat_id: {
                "id": s.threat_id,
                "name": s.name,
                "severity": s.severity,
                "status": s.status,
                "risk_score": s.risk_score,
            }
            for s in snapshots
        }

    # Fallback for versions created before snapshots were introduced.
    threat_ids = set(version.threat_ids or [])
    if not threat_ids:
        return {}
    threats = (
        db.query(models.Threat)
        .filter(models.Threat.project_id == project_id, models.Threat.id.in_(list(threat_ids)))
        .all()
    )
    return {
        t.id: {
            "id": t.id,
            "name": t.name,
            "severity": t.severity,
            "status": t.status,
            "risk_score": t.risk_score,
        }
        for t in threats
    }


def _mitigation_state_for_version(
    db: Session,
    *,
    project_id: str,
    version: models.ProjectVersion,
) -> dict[str, dict]:
    snapshots = (
        db.query(models.MitigationSnapshot)
        .filter(models.MitigationSnapshot.version_id == version.id)
        .all()
    )
    if snapshots:
        return {
            s.mitigation_id: {
                "id": s.mitigation_id,
                "name": s.title,
                "description": s.description,
                "status": s.status,
            }
            for s in snapshots
        }

    # Fallback for versions created before snapshots were introduced.
    mitigation_ids = set(version.mitigation_ids or [])
    if not mitigation_ids:
        return {}
    mitigations = (
        db.query(models.Mitigation)
        .filter(models.Mitigation.project_id == project_id, models.Mitigation.id.in_(list(mitigation_ids)))
        .all()
    )
    return {
        m.id: {
            "id": m.id,
            "name": m.title,
            "description": m.description,
            "status": m.status,
        }
        for m in mitigations
    }


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return []


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _get_analysis_artifacts_from_version(version: models.ProjectVersion) -> dict[str, Any]:
    context_snapshot = _as_dict(version.context_snapshot)
    return _as_dict(context_snapshot.get("analysis_artifacts"))


def _extract_artifact_snapshot(version: models.ProjectVersion) -> dict[str, Any]:
    artifacts = _get_analysis_artifacts_from_version(version)
    graph = _as_dict(artifacts.get("graph"))
    threats = _as_list(artifacts.get("threats"))
    linked_threat_ids = [str(item) for item in _as_list(artifacts.get("linked_threat_ids")) if isinstance(item, str)]
    enriched_threats: list[Any] = []
    for index, threat in enumerate(threats):
        if not isinstance(threat, dict):
            enriched_threats.append(threat)
            continue
        threat_copy = dict(threat)
        if index < len(linked_threat_ids):
            threat_copy["persisted_threat_id"] = linked_threat_ids[index]
        enriched_threats.append(threat_copy)
    return {
        "parsed_output": _as_dict(artifacts.get("parsed_output")),
        "threats": enriched_threats,
        "graph_nodes": _as_list(graph.get("nodes")),
        "graph_edges": _as_list(graph.get("edges")),
        "scenarios": _as_list(artifacts.get("scenarios")),
    }


def _list_of_dicts(items: list[Any]) -> list[dict[str, Any]]:
    return [item for item in items if isinstance(item, dict)]


def _name_slug(name: Any) -> str:
    """Normalize any name to lowercase alphanumerics for semantic matching."""
    if not isinstance(name, str):
        return ""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _threat_semantic_key(threat: dict[str, Any]) -> str:
    """Stable key for diff display: category + component + compact title."""
    stored_threat_key = threat.get("threat_key")
    if isinstance(stored_threat_key, str) and stored_threat_key.strip():
        return stored_threat_key.strip().lower()
    stored_semantic_key = threat.get("semantic_key")
    if isinstance(stored_semantic_key, str) and stored_semantic_key.strip():
        return stored_semantic_key.strip().lower()
    title = _name_slug(threat.get("title") or threat.get("name") or "")[:50]
    category = (threat.get("category") or "").strip().lower()
    component = (threat.get("affected_component_id") or threat.get("affected_component") or "").strip().lower()
    return f"{category}|{component}|{title}"


def _threat_persistence_key(threat: dict[str, Any]) -> str:
    """Deterministic fingerprint used to preserve DB threat IDs across versions.

    This key intentionally prefers stable model references over natural-language
    titles so adding SAST evidence can enrich an existing risk instead of making
    the same risk look like a delete+add pair.
    """
    stored_threat_key = threat.get("threat_key")
    if isinstance(stored_threat_key, str) and stored_threat_key.strip():
        return stored_threat_key.strip().lower()
    stored_semantic_key = threat.get("semantic_key")
    if isinstance(stored_semantic_key, str) and stored_semantic_key.strip():
        return stored_semantic_key.strip().lower()

    category = (threat.get("category") or "").strip().lower()
    component = (threat.get("affected_component_id") or threat.get("affected_component") or "").strip().lower()
    entry_point = (threat.get("entry_point_id") or "").strip().lower()
    asset = (threat.get("asset_id") or "").strip().lower()
    grounding = (threat.get("grounded_finding") or "").strip().lower()
    title_slug = _name_slug(threat.get("title") or threat.get("name") or "")[:80]

    # Use grounded finding when present, but keep title fallback because
    # architecture-only versions usually have no CWE/finding ID.
    weakness = grounding or title_slug
    return "|".join([
        category or "unknown_category",
        component or "unknown_component",
        entry_point or "unknown_entry",
        asset or "unknown_asset",
        weakness or "unknown_weakness",
    ])


def _threat_structural_key(threat: dict[str, Any]) -> str:
    """Stable key for the same risk gaining new evidence, such as SAST CWE data."""
    category = (threat.get("category") or "").strip().lower()
    component = (threat.get("affected_component_id") or threat.get("affected_component") or "").strip().lower()
    entry_point = (threat.get("entry_point_id") or "").strip().lower()
    asset = (threat.get("asset_id") or "").strip().lower()
    return "|".join([
        category or "unknown_category",
        component or "unknown_component",
        entry_point or "unknown_entry",
        asset or "unknown_asset",
    ])


def _legacy_threat_persistence_key(threat: dict[str, Any]) -> tuple[str, str, str]:
    """Compatibility key for threats saved before semantic keys existed."""
    title = threat.get("title") or threat.get("name") or ""
    category = threat.get("category") or ""
    component = threat.get("affected_component_id") or threat.get("affected_component") or ""
    return (
        title.strip().lower()[:60] if isinstance(title, str) else "",
        category.strip().lower() if isinstance(category, str) else "",
        component.strip().lower() if isinstance(component, str) else "",
    )


def _ep_semantic_key(ep: dict[str, Any]) -> str:
    """Stable key: type + exposure + name slug."""
    ep_type = (ep.get("type") or "").strip().lower()
    exposure = (ep.get("exposure") or "").strip().lower()
    name = _name_slug(ep.get("name") or "")
    return f"{ep_type}|{exposure}|{name}"


def _asset_semantic_key(asset: dict[str, Any]) -> str:
    """Stable key: type + sensitivity + name slug."""
    asset_type = (asset.get("type") or "").strip().lower()
    sensitivity = (asset.get("sensitivity") or "").strip().lower()
    name = _name_slug(asset.get("name") or "")
    return f"{asset_type}|{sensitivity}|{name}"


def _component_semantic_key(comp: dict[str, Any]) -> str:
    """Stable key: name slug only — type can drift between runs."""
    return _name_slug(comp.get("name") or "")


def _severity_rank(severity: Any) -> int:
    order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(str(severity or "").strip().lower(), 0)


def _sast_finding_fingerprint(finding: dict[str, Any]) -> str:
    if not isinstance(finding, dict):
        return ""
    existing = finding.get("finding_fingerprint")
    if isinstance(existing, str) and existing.strip():
        return existing.strip().lower()

    rule_id = (
        finding.get("rule_id")
        or finding.get("ruleId")
        or finding.get("check_id")
        or finding.get("id")
        or "unknown"
    )
    file_path = finding.get("file") or finding.get("path") or finding.get("filename") or ""
    line = str(finding.get("line") or finding.get("lineNumber") or "")
    locations = finding.get("locations")
    logical_location = ""
    if isinstance(locations, list) and locations:
        loc = locations[0]
        if isinstance(loc, dict):
            phys = loc.get("physicalLocation") or {}
            if isinstance(phys, dict):
                artifact = phys.get("artifactLocation") or {}
                region = phys.get("region") or {}
                if isinstance(artifact, dict):
                    file_path = file_path or artifact.get("uri") or ""
                if isinstance(region, dict):
                    line = line or str(region.get("startLine") or "")
            logical_locations = loc.get("logicalLocations")
            if isinstance(logical_locations, list) and logical_locations:
                logical = logical_locations[0]
                if isinstance(logical, dict):
                    logical_location = str(logical.get("name") or "")
    return "|".join([
        str(rule_id).strip().lower(),
        str(file_path or "unknown").strip().lower(),
        str(line or "unknown").strip().lower(),
        _name_slug(logical_location or "finding"),
    ])


def _sast_finding_diff(parsed_a: dict[str, Any], parsed_b: dict[str, Any]) -> dict[str, Any]:
    findings_a = _as_list(_as_dict(parsed_a.get("security_findings")).get("sast"))
    findings_b = _as_list(_as_dict(parsed_b.get("security_findings")).get("sast"))
    by_key_a = {
        _sast_finding_fingerprint(f): f
        for f in _list_of_dicts(findings_a)
        if _sast_finding_fingerprint(f)
    }
    by_key_b = {
        _sast_finding_fingerprint(f): f
        for f in _list_of_dicts(findings_b)
        if _sast_finding_fingerprint(f)
    }
    keys_a = set(by_key_a)
    keys_b = set(by_key_b)
    return {
        "resolved": [by_key_a[key] for key in sorted(keys_a - keys_b)],
        "persisting": [{"from": by_key_a[key], "to": by_key_b[key]} for key in sorted(keys_a & keys_b)],
        "new": [by_key_b[key] for key in sorted(keys_b - keys_a)],
    }


def _classify_threat_transitions(threat_diff: dict[str, Any]) -> dict[str, list[Any]]:
    resolved: list[Any] = []
    downgraded: list[Any] = []
    persisting: list[Any] = []

    for item in threat_diff.get("removed") or []:
        if isinstance(item, dict) and (item.get("source_type") == "sast" or item.get("grounded_finding")):
            resolved.append(item)

    for item in threat_diff.get("unchanged") or []:
        if isinstance(item, dict):
            persisting.append(item)

    for item in threat_diff.get("modified") or []:
        if not isinstance(item, dict):
            continue
        left = _as_dict(item.get("from"))
        right = _as_dict(item.get("to"))
        if left and right and (
            _severity_rank(right.get("severity")) < _severity_rank(left.get("severity"))
            or (
                left.get("control_status") != right.get("control_status")
                and right.get("control_status") in {"partially_mitigated", "mitigated"}
            )
        ):
            downgraded.append(item)
        else:
            persisting.append(item)

    return {
        "resolved": resolved,
        "downgraded": downgraded,
        "persisting": persisting,
    }


def _semantic_diff(
    left_items: list[Any],
    right_items: list[Any],
    *,
    id_key: str = "id",
    semantic_key_fn: Any,
) -> dict[str, Any]:
    """Diff two entity lists using ID matching with a semantic-key fallback.

    Returns:
        unchanged  — matched by ID or semantics, no field differences
        modified   — matched by ID or semantics, at least one field changed
        added      — in right only
        removed    — in left only
        match_method — "id" or "semantic" per matched pair (for diagnostics)
    """
    left_dicts = _list_of_dicts(left_items)
    right_dicts = _list_of_dicts(right_items)

    def _entity_id(item: dict[str, Any]) -> str:
        value = item.get(id_key)
        if isinstance(value, str) and value:
            return value
        if id_key != "id":
            fallback = item.get("id")
            if isinstance(fallback, str) and fallback:
                return fallback
        return ""

    left_by_id: dict[str, dict] = {
        _entity_id(item): item
        for item in left_dicts
        if _entity_id(item)
    }
    right_by_id: dict[str, dict] = {
        _entity_id(item): item
        for item in right_dicts
        if _entity_id(item)
    }

    left_by_semantic: dict[str, dict] = {}
    for item in left_dicts:
        key = semantic_key_fn(item)
        if key:
            left_by_semantic[key] = item

    unchanged: list[dict] = []
    modified: list[dict] = []
    matched_left_ids: set[str] = set()
    matched_right_ids: set[str] = set()

    for right_id, right_item in right_by_id.items():
        # Strategy 1: exact ID match.
        if right_id in left_by_id:
            left_item = left_by_id[right_id]
            matched_left_ids.add(right_id)
            matched_right_ids.add(right_id)
            if left_item == right_item:
                unchanged.append({"id": right_id, "item": right_item, "match": "id"})
            else:
                modified.append({
                    "id": right_id,
                    "match": "id",
                    "from": left_item,
                    "to": right_item,
                })
            continue

        # Strategy 2: semantic key fallback.
        sem_key = semantic_key_fn(right_item)
        if sem_key and sem_key in left_by_semantic:
            left_item = left_by_semantic[sem_key]
            left_id = _entity_id(left_item)
            matched_left_ids.add(left_id)
            matched_right_ids.add(right_id)
            if left_item == right_item:
                unchanged.append({"id": right_id, "item": right_item, "match": "semantic"})
            else:
                modified.append({
                    "id": right_id,
                    "id_in_a": left_id,
                    "match": "semantic",
                    "from": left_item,
                    "to": right_item,
                })

    added = [
        item for item in right_dicts
        if _entity_id(item) not in matched_right_ids
    ]
    removed = [
        item for item in left_dicts
        if _entity_id(item) not in matched_left_ids
    ]

    return {
        "unchanged": unchanged,
        "modified": modified,
        "added": added,
        "removed": removed,
    }


def _detect_parser_drift(
    left_components: list[Any],
    right_components: list[Any],
) -> list[dict[str, Any]]:
    """Flag components that matched semantically but changed type or trust_zone."""
    left_by_slug = {
        _component_semantic_key(c): c
        for c in _list_of_dicts(left_components)
        if _component_semantic_key(c)
    }
    drift: list[dict] = []
    for comp in _list_of_dicts(right_components):
        slug = _component_semantic_key(comp)
        left = left_by_slug.get(slug)
        if not left:
            continue
        changes: dict[str, Any] = {}
        if left.get("type") != comp.get("type"):
            changes["type"] = {"from": left.get("type"), "to": comp.get("type")}
        if left.get("trust_zone") != comp.get("trust_zone"):
            changes["trust_zone"] = {"from": left.get("trust_zone"), "to": comp.get("trust_zone")}
        if changes:
            drift.append({
                "id": comp.get("id"),
                "name": comp.get("name"),
                "changes": changes,
            })
    return drift


def _diff_parsed_output(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    left_keys = set(left.keys())
    right_keys = set(right.keys())

    added_keys = sorted(right_keys - left_keys)
    removed_keys = sorted(left_keys - right_keys)
    shared_keys = sorted(left_keys & right_keys)
    changed_keys = [key for key in shared_keys if left.get(key) != right.get(key)]

    return {
        "added_fields": {key: right.get(key) for key in added_keys},
        "removed_fields": {key: left.get(key) for key in removed_keys},
        "changed_fields": {
            key: {"from": left.get(key), "to": right.get(key)}
            for key in changed_keys
        },
    }


def _edge_signature(edge: dict[str, Any]) -> str:
    from_id = edge.get("from")
    to_id = edge.get("to")
    edge_type = edge.get("type")
    return f"{from_id}|{to_id}|{edge_type}"


def _diff_graph(left_nodes: list[Any], right_nodes: list[Any], left_edges: list[Any], right_edges: list[Any]) -> dict[str, Any]:
    node_diff = _semantic_diff(
        left_nodes, right_nodes,
        id_key="id",
        semantic_key_fn=lambda n: _name_slug(n.get("label") or n.get("id") or ""),
    )

    left_edge_map = {
        _edge_signature(edge): edge
        for edge in _list_of_dicts(left_edges)
        if isinstance(edge.get("from"), str)
        and isinstance(edge.get("to"), str)
        and isinstance(edge.get("type"), str)
    }
    right_edge_map = {
        _edge_signature(edge): edge
        for edge in _list_of_dicts(right_edges)
        if isinstance(edge.get("from"), str)
        and isinstance(edge.get("to"), str)
        and isinstance(edge.get("type"), str)
    }

    left_edge_keys = set(left_edge_map.keys())
    right_edge_keys = set(right_edge_map.keys())

    added_edge_keys = sorted(right_edge_keys - left_edge_keys)
    removed_edge_keys = sorted(left_edge_keys - right_edge_keys)

    return {
        "nodes": node_diff,
        "edges": {
            "added": [right_edge_map[key] for key in added_edge_keys],
            "removed": [left_edge_map[key] for key in removed_edge_keys],
        },
    }


def _normalize_severity(value: Any) -> str:
    if not isinstance(value, str):
        return "Medium"
    normalized = value.strip().lower()
    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    }
    return mapping.get(normalized, "Medium")


def _normalize_score_1_to_5(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        numeric = int(round(float(value)))
    elif isinstance(value, str):
        try:
            numeric = int(round(float(value.strip())))
        except (TypeError, ValueError):
            return None
    else:
        return None
    return max(1, min(5, numeric))


def _default_score_from_severity(severity: str) -> int:
    mapping = {
        "Critical": 5,
        "High": 4,
        "Medium": 3,
        "Low": 2,
        "Info": 1,
    }
    return mapping.get(severity, 3)


def _resolve_threat_risk_values(threat_data: dict[str, Any]) -> tuple[str, int, int, float]:
    severity = _normalize_severity(threat_data.get("severity"))
    default_score = _default_score_from_severity(severity)

    likelihood = _normalize_score_1_to_5(threat_data.get("likelihood"))
    impact = _normalize_score_1_to_5(threat_data.get("impact"))

    resolved_likelihood = likelihood if likelihood is not None else default_score
    resolved_impact = impact if impact is not None else default_score
    risk_score = float(resolved_likelihood * resolved_impact)
    return severity, resolved_likelihood, resolved_impact, risk_score


def _unique_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    unique_values: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique_values.append(value)
    return unique_values


def _upsert_generated_threats_for_version(
    db: Session,
    *,
    project: models.Project,
    version: models.ProjectVersion,
    generated_threats: list[Any],
    existing_id_map: dict[str, str],
) -> tuple[list[str], dict[str, str]]:
    now = dt.datetime.utcnow()
    linked_threat_ids: list[str] = []
    linked_seen: set[str] = set()
    id_map = dict(existing_id_map)

    valid_existing_ids = {
        threat_id
        for (threat_id,) in db.query(models.Threat.id)
        .filter(models.Threat.project_id == project.id, models.Threat.id.in_(list(id_map.values())))
        .all()
    }
    id_map = {k: v for k, v in id_map.items() if v in valid_existing_ids}

    # Build a semantic fallback map: (name_lower[:60], category_lower, affected_component_lower)
    # → db threat id. The three-part key reduces false merges when threat titles change
    # slightly between re-analyses (e.g. minor title rewording by the AI) while still
    # catching the case where only the AI-generated string ID changed.
    existing_threats = (
        db.query(models.Threat)
        .filter(models.Threat.project_id == project.id)
        .all()
    )
    semantic_map: dict[str, str] = {}
    legacy_semantic_map: dict[tuple[str, str, str], str] = {}
    for existing in existing_threats:
        existing_as_generated = {
            "title": existing.name,
            "category": existing.category,
            "affected_component_id": existing.affected_component,
            "entry_point_id": "unknown",
            "asset_id": "unknown",
            "grounded_finding": existing.grounded_finding,
        }
        semantic_key = _threat_persistence_key(existing_as_generated)
        structural_key = _threat_structural_key(existing_as_generated)
        if semantic_key:
            semantic_map.setdefault(semantic_key, existing.id)
        if structural_key:
            semantic_map.setdefault(f"structural:{structural_key}", existing.id)
        legacy_semantic_map.setdefault(_legacy_threat_persistence_key(existing_as_generated), existing.id)

    for index, threat_data in enumerate(generated_threats):
        if not isinstance(threat_data, dict):
            continue

        generated_id_value = threat_data.get("id")
        generated_id = (
            generated_id_value.strip()
            if isinstance(generated_id_value, str) and generated_id_value.strip()
            else f"generated_threat_{index + 1}"
        )
        semantic_key = _threat_persistence_key(threat_data)
        structural_key = _threat_structural_key(threat_data)
        legacy_semantic_key = _legacy_threat_persistence_key(threat_data)
        threat_data["semantic_key"] = semantic_key

        severity, likelihood, impact, risk_score = _resolve_threat_risk_values(threat_data)

        existing_threat_id = id_map.get(generated_id)

        # If the AI-generated ID changed between runs, fall back to stable
        # semantic identity. This prevents comparisons from becoming
        # "all removed + all added" when the same risk is regenerated.
        if not existing_threat_id:
            existing_threat_id = (
                id_map.get(f"semantic:{semantic_key}")
                or id_map.get(f"structural:{structural_key}")
                or semantic_map.get(semantic_key)
                or semantic_map.get(f"structural:{structural_key}")
                or legacy_semantic_map.get(legacy_semantic_key)
            )
            if existing_threat_id:
                id_map[generated_id] = existing_threat_id
                id_map[f"semantic:{semantic_key}"] = existing_threat_id
                id_map[f"structural:{structural_key}"] = existing_threat_id

        if existing_threat_id:
            existing_threat = (
                db.query(models.Threat)
                .filter(models.Threat.id == existing_threat_id, models.Threat.project_id == project.id)
                .first()
            )
            if existing_threat:
                existing_threat.severity = severity
                existing_threat.likelihood = likelihood
                existing_threat.impact = impact
                existing_threat.risk_score = risk_score
                existing_threat.grounded_finding = threat_data.get("grounded_finding")
                title = threat_data.get("title")
                if isinstance(title, str) and title.strip():
                    existing_threat.name = title.strip()
                description = threat_data.get("description")
                if isinstance(description, str):
                    existing_threat.description = description
                category = threat_data.get("category")
                if isinstance(category, str):
                    existing_threat.category = category
                affected_component = threat_data.get("affected_component_id")
                if isinstance(affected_component, str):
                    existing_threat.affected_component = affected_component
                existing_threat.updated_at = now
            if existing_threat_id not in linked_seen:
                linked_seen.add(existing_threat_id)
                linked_threat_ids.append(existing_threat_id)
            continue

        title = threat_data.get("title")
        threat_name = title.strip() if isinstance(title, str) and title.strip() else f"Generated Threat {index + 1}"
        description = threat_data.get("description")
        category = threat_data.get("category")
        affected_component = threat_data.get("affected_component_id")
        grounded_finding = threat_data.get("grounded_finding")

        new_threat = models.Threat(
            id=str(uuid.uuid4()),
            project_id=project.id,
            name=threat_name,
            description=description if isinstance(description, str) else None,
            category=category if isinstance(category, str) else None,
            severity=severity,
            likelihood=likelihood,
            impact=impact,
            risk_score=risk_score,
            status="Identified",
            affected_component=affected_component if isinstance(affected_component, str) else None,
            grounded_finding=grounded_finding if isinstance(grounded_finding, str) else None,
            identified_stage="Design",
            source="Generated",
            commit_hash=None,
            introduced_in=version.version_number,
            identified_in_phase=project.current_phase,
            introduced_in_version_id=version.id,
            accepted_risk_info=None,
            events=[
                {
                    "id": str(uuid.uuid4()),
                    "threatId": "",
                    "type": "created",
                    "versionId": version.id,
                    "timestamp": now.isoformat(),
                    "details": "Threat persisted from generated analysis artifacts",
                }
            ],
            created_at=now,
            updated_at=now,
        )
        db.add(new_threat)
        db.flush()

        if isinstance(new_threat.events, list) and new_threat.events:
            new_threat.events[0]["threatId"] = new_threat.id

        id_map[generated_id] = new_threat.id
        id_map[f"semantic:{semantic_key}"] = new_threat.id
        id_map[f"structural:{structural_key}"] = new_threat.id
        if new_threat.id not in linked_seen:
            linked_seen.add(new_threat.id)
            linked_threat_ids.append(new_threat.id)

    return linked_threat_ids, id_map


def _upsert_generated_mitigations_for_version(
    db: Session,
    *,
    project: models.Project,
    version: models.ProjectVersion,
    generated_threats: list[Any],
    generated_threat_id_map: dict[str, str],
) -> list[str]:
    now = dt.datetime.utcnow()
    linked_mitigation_ids: list[str] = []
    linked_seen: set[str] = set()

    for index, threat_data in enumerate(generated_threats):
        if not isinstance(threat_data, dict):
            continue

        generated_id_value = threat_data.get("id")
        generated_id = (
            generated_id_value.strip()
            if isinstance(generated_id_value, str) and generated_id_value.strip()
            else f"generated_threat_{index + 1}"
        )
        linked_threat_id = generated_threat_id_map.get(generated_id)
        if not linked_threat_id:
            continue

        mitigation_text = threat_data.get("mitigation")
        if not isinstance(mitigation_text, str) or not mitigation_text.strip():
            continue

        title_source = threat_data.get("title")
        threat_title = (
            title_source.strip()
            if isinstance(title_source, str) and title_source.strip()
            else f"Generated Threat {index + 1}"
        )
        mitigation_title = f"Mitigate: {threat_title}"
        severity = threat_data.get("severity")
        priority = severity if isinstance(severity, str) and severity.strip() else "Medium"

        existing = (
            db.query(models.Mitigation)
            .filter(
                models.Mitigation.project_id == project.id,
                models.Mitigation.threat_id == linked_threat_id,
            )
            .order_by(models.Mitigation.created_at.asc())
            .first()
        )
        if existing:
            existing.title = mitigation_title
            existing.description = mitigation_text.strip()
            existing.priority = priority
            existing.type = existing.type or "Prevent"
            existing.status = existing.status or "Planned"
            existing.updated_at = now
            if existing.id not in linked_seen:
                linked_seen.add(existing.id)
                linked_mitigation_ids.append(existing.id)
            continue

        mitigation = models.Mitigation(
            id=str(uuid.uuid4()),
            project_id=project.id,
            threat_id=linked_threat_id,
            title=mitigation_title,
            description=mitigation_text.strip(),
            status="Planned",
            owner=None,
            priority=priority,
            type="Prevent",
            assignee=None,
            due_date=None,
            introduced_in_version_id=version.id,
            created_at=now,
            updated_at=now,
        )
        db.add(mitigation)
        db.flush()
        if mitigation.id not in linked_seen:
            linked_seen.add(mitigation.id)
            linked_mitigation_ids.append(mitigation.id)

    return linked_mitigation_ids


def persist_analysis_artifacts_for_version(
    db: Session,
    *,
    project: models.Project,
    version: models.ProjectVersion,
    parsed_output: dict[str, Any] | None,
    threats: list[Any],
    graph: dict[str, Any] | None,
    scenarios: list[Any],
    persist_threats: bool = True,
    notes: str | None = None,
    evidence_hash: str | None = None,
) -> dict[str, Any]:
    # Use fresh dict/list objects so SQLAlchemy JSON fields are marked dirty.
    context_snapshot = dict(_as_dict(version.context_snapshot))
    artifacts = dict(_as_dict(context_snapshot.get("analysis_artifacts")))

    generated_threats = list(threats) if isinstance(threats, list) else []
    graph_value = graph if isinstance(graph, dict) else {}
    scenarios_value = list(scenarios) if isinstance(scenarios, list) else []

    linked_threat_ids: list[str] = []
    linked_mitigation_ids: list[str] = []
    generated_threat_id_map = _as_dict(artifacts.get("generated_threat_id_map"))
    normalized_generated_threat_id_map = {
        str(key): str(value)
        for key, value in generated_threat_id_map.items()
        if isinstance(key, str) and isinstance(value, str)
    }

    if persist_threats and generated_threats:
        linked_threat_ids, normalized_generated_threat_id_map = _upsert_generated_threats_for_version(
            db,
            project=project,
            version=version,
            generated_threats=generated_threats,
            existing_id_map=normalized_generated_threat_id_map,
        )
        linked_mitigation_ids = _upsert_generated_mitigations_for_version(
            db,
            project=project,
            version=version,
            generated_threats=generated_threats,
            generated_threat_id_map=normalized_generated_threat_id_map,
        )

    if persist_threats and generated_threats:
        # Replace (not accumulate): each analysis run defines the complete threat set for this version.
        # Accumulation caused duplicates when the AI generated different IDs for the same threat across runs.
        version.threat_ids = _unique_preserve_order(linked_threat_ids)
        version.mitigation_ids = _unique_preserve_order(linked_mitigation_ids)

    graph_nodes = _as_list(graph_value.get("nodes"))
    graph_edges = _as_list(graph_value.get("edges"))

    artifacts.update(
        {
            "parsed_output": parsed_output if isinstance(parsed_output, dict) else {},
            "threats": generated_threats,
            "graph": {
                "nodes": graph_nodes,
                "edges": graph_edges,
            },
            "scenarios": scenarios_value,
            "generated_threat_id_map": normalized_generated_threat_id_map,
            "linked_threat_ids": _unique_preserve_order(linked_threat_ids),
            "updated_at": dt.datetime.utcnow().isoformat(),
            "notes": notes,
        }
    )

    context_snapshot["analysis_artifacts"] = dict(artifacts)
    if evidence_hash is not None:
        context_snapshot["evidence_hash"] = evidence_hash
    version.context_snapshot = dict(context_snapshot)

    if graph_nodes:
        project.attack_scenario_nodes = list(graph_nodes)
    if graph_edges:
        project.attack_scenario_edges = list(graph_edges)

    project.updated_at = dt.datetime.utcnow()

    capture_version_snapshots(
        db,
        project_id=project.id,
        version_id=version.id,
        threat_ids=version.threat_ids or [],
        mitigation_ids=version.mitigation_ids or [],
    )
    db.commit()
    db.refresh(version)

    refreshed_context_snapshot = _as_dict(version.context_snapshot)
    refreshed_artifacts = _as_dict(refreshed_context_snapshot.get("analysis_artifacts"))
    refreshed_graph = _as_dict(refreshed_artifacts.get("graph"))
    refreshed_linked_threat_ids = _as_list(refreshed_artifacts.get("linked_threat_ids"))

    return {
        "project_id": project.id,
        "version_id": version.id,
        "has_parsed_output": isinstance(refreshed_artifacts.get("parsed_output"), dict),
        "threats_count": len(_as_list(refreshed_artifacts.get("threats"))),
        "graph_nodes_count": len(_as_list(refreshed_graph.get("nodes"))),
        "graph_edges_count": len(_as_list(refreshed_graph.get("edges"))),
        "scenarios_count": len(_as_list(refreshed_artifacts.get("scenarios"))),
        "linked_threat_ids": [str(item) for item in refreshed_linked_threat_ids if isinstance(item, str)],
        "artifacts": refreshed_artifacts,
    }


@router.get("", response_model=list[schemas.VersionOut])
def list_versions(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    get_project_or_404(db, project_id, current_user.id)
    return (
        db.query(models.ProjectVersion)
        .filter(models.ProjectVersion.project_id == project_id)
        .order_by(models.ProjectVersion.created_at.desc())
        .all()
    )


@router.post("", response_model=schemas.VersionOut, status_code=status.HTTP_201_CREATED)
def create_version(
    project_id: str,
    payload: schemas.VersionCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    project = get_project_or_404(db, project_id, current_user.id)
    version = models.ProjectVersion(
        id=str(uuid.uuid4()),
        project_id=project_id,
        version_number=payload.version_number,
        created_at=payload.created_at,
        created_by=payload.created_by,
        context_snapshot=payload.context_snapshot,
        threat_ids=payload.threat_ids or [],
        mitigation_ids=payload.mitigation_ids or [],
        notes=payload.notes,
    )
    db.add(version)
    project.current_version_id = version.id
    project.version = payload.version_number
    project.updated_at = dt.datetime.utcnow()
    capture_version_snapshots(
        db,
        project_id=project_id,
        version_id=version.id,
        threat_ids=payload.threat_ids or [],
        mitigation_ids=payload.mitigation_ids or [],
    )
    db.commit()
    db.refresh(version)
    return version


@router.patch("/{version_id}", response_model=schemas.VersionOut)
def update_version(
    project_id: str,
    version_id: str,
    payload: schemas.VersionUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    get_project_or_404(db, project_id, current_user.id)
    version = get_version_or_404(db, project_id, version_id)
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(version, key, value)
    capture_version_snapshots(
        db,
        project_id=project_id,
        version_id=version.id,
        threat_ids=version.threat_ids or [],
        mitigation_ids=version.mitigation_ids or [],
    )
    db.commit()
    db.refresh(version)
    return version


@router.post(
    "/{version_id}/analysis-artifacts",
    response_model=schemas.AnalysisArtifactsOut,
    status_code=status.HTTP_201_CREATED,
)
def upsert_analysis_artifacts(
    project_id: str,
    version_id: str,
    payload: schemas.AnalysisArtifactsUpsert,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    project = get_project_or_404(db, project_id, current_user.id)
    version = get_version_or_404(db, project_id, version_id)
    return persist_analysis_artifacts_for_version(
        db,
        project=project,
        version=version,
        parsed_output=payload.parsed_output if isinstance(payload.parsed_output, dict) else {},
        threats=payload.threats if isinstance(payload.threats, list) else [],
        graph=payload.graph if isinstance(payload.graph, dict) else {"nodes": [], "edges": []},
        scenarios=payload.scenarios if isinstance(payload.scenarios, list) else [],
        persist_threats=payload.persist_threats,
        notes=payload.notes,
    )


@router.get("/{version_id}/analysis-artifacts", response_model=schemas.AnalysisArtifactsOut)
def get_analysis_artifacts(
    project_id: str,
    version_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    get_project_or_404(db, project_id, current_user.id)
    version = get_version_or_404(db, project_id, version_id)
    context_snapshot = _as_dict(version.context_snapshot)
    artifacts = _as_dict(context_snapshot.get("analysis_artifacts"))
    graph = _as_dict(artifacts.get("graph"))
    linked_threat_ids = [str(item) for item in _as_list(artifacts.get("linked_threat_ids")) if isinstance(item, str)]

    return {
        "project_id": project_id,
        "version_id": version.id,
        "has_parsed_output": isinstance(artifacts.get("parsed_output"), dict),
        "threats_count": len(_as_list(artifacts.get("threats"))),
        "graph_nodes_count": len(_as_list(graph.get("nodes"))),
        "graph_edges_count": len(_as_list(graph.get("edges"))),
        "scenarios_count": len(_as_list(artifacts.get("scenarios"))),
        "linked_threat_ids": linked_threat_ids,
        "artifacts": artifacts,
    }


@router.get("/{version_id}/analysis-artifacts/parsed-output")
def get_version_parsed_output(
    project_id: str,
    version_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    get_project_or_404(db, project_id, current_user.id)
    version = get_version_or_404(db, project_id, version_id)
    artifacts = _get_analysis_artifacts_from_version(version)

    return {
        "project_id": project_id,
        "version_id": version.id,
        "parsed_output": _as_dict(artifacts.get("parsed_output")),
    }


@router.get("/{version_id}/analysis-artifacts/threats")
def get_version_analysis_threats(
    project_id: str,
    version_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    get_project_or_404(db, project_id, current_user.id)
    version = get_version_or_404(db, project_id, version_id)
    artifacts = _get_analysis_artifacts_from_version(version)

    return {
        "project_id": project_id,
        "version_id": version.id,
        "threats": _as_list(artifacts.get("threats")),
        "linked_threat_ids": [item for item in _as_list(artifacts.get("linked_threat_ids")) if isinstance(item, str)],
    }


@router.get("/{version_id}/analysis-artifacts/graph")
def get_version_analysis_graph(
    project_id: str,
    version_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    get_project_or_404(db, project_id, current_user.id)
    version = get_version_or_404(db, project_id, version_id)
    artifacts = _get_analysis_artifacts_from_version(version)
    graph = _as_dict(artifacts.get("graph"))

    graph_summary = graph.get("graph_summary")

    return {
        "project_id": project_id,
        "version_id": version.id,
        "graph": {
            "nodes": _as_list(graph.get("nodes")),
            "edges": _as_list(graph.get("edges")),
            "graph_summary": graph_summary if isinstance(graph_summary, dict) else None,
        },
    }


@router.get("/{version_id}/analysis-artifacts/scenarios")
def get_version_analysis_scenarios(
    project_id: str,
    version_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    get_project_or_404(db, project_id, current_user.id)
    version = get_version_or_404(db, project_id, version_id)
    artifacts = _get_analysis_artifacts_from_version(version)

    return {
        "project_id": project_id,
        "version_id": version.id,
        "scenarios": _as_list(artifacts.get("scenarios")),
    }


@router.get("/analysis-artifacts/compare")
def compare_analysis_artifacts(
    project_id: str,
    a: str = Query(...),
    b: str = Query(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    get_project_or_404(db, project_id, current_user.id)
    version_a = get_version_or_404(db, project_id, a)
    version_b = get_version_or_404(db, project_id, b)

    snapshot_a = _extract_artifact_snapshot(version_a)
    snapshot_b = _extract_artifact_snapshot(version_b)

    parsed_a = snapshot_a["parsed_output"]
    parsed_b = snapshot_b["parsed_output"]

    # Semantic diff for all model entity types.
    threat_diff = _semantic_diff(
        snapshot_a["threats"], snapshot_b["threats"],
        id_key="persisted_threat_id", semantic_key_fn=_threat_semantic_key,
    )
    threat_transitions = _classify_threat_transitions(threat_diff)
    sast_diff = _sast_finding_diff(parsed_a, parsed_b)
    ep_diff = _semantic_diff(
        _as_list(parsed_a.get("entry_points")), _as_list(parsed_b.get("entry_points")),
        id_key="id", semantic_key_fn=_ep_semantic_key,
    )
    asset_diff = _semantic_diff(
        _as_list(parsed_a.get("assets")), _as_list(parsed_b.get("assets")),
        id_key="id", semantic_key_fn=_asset_semantic_key,
    )
    component_diff = _semantic_diff(
        _as_list(parsed_a.get("components")), _as_list(parsed_b.get("components")),
        id_key="id", semantic_key_fn=_component_semantic_key,
    )
    graph_diff = _diff_graph(
        snapshot_a["graph_nodes"], snapshot_b["graph_nodes"],
        snapshot_a["graph_edges"], snapshot_b["graph_edges"],
    )
    scenario_diff = _semantic_diff(
        snapshot_a["scenarios"], snapshot_b["scenarios"],
        id_key="id", semantic_key_fn=lambda s: _name_slug(s.get("title") or s.get("name") or ""),
    )

    # Parser drift: components that matched semantically but changed type or trust_zone.
    parser_drift = _detect_parser_drift(
        _as_list(parsed_a.get("components")),
        _as_list(parsed_b.get("components")),
    )

    # Tag new threats with whether they are CWE-grounded.
    def _enrich_threat(t: dict[str, Any]) -> dict[str, Any]:
        grounding = t.get("grounded_finding") or ""
        return {**t, "sast_backed": bool(grounding and grounding.lower() != "none")}

    added_threats = [_enrich_threat(t) for t in threat_diff["added"]]
    sast_backed_count = sum(1 for t in added_threats if t["sast_backed"])

    return {
        "project_id": project_id,
        "version_a": {"id": version_a.id, "version_number": version_a.version_number},
        "version_b": {"id": version_b.id, "version_number": version_b.version_number},
        "summary": {
            "threats_unchanged": len(threat_diff["unchanged"]),
            "threats_modified": len(threat_diff["modified"]),
            "threats_added": len(threat_diff["added"]),
            "threats_removed": len(threat_diff["removed"]),
            "threats_resolved": len(threat_transitions["resolved"]),
            "threats_downgraded": len(threat_transitions["downgraded"]),
            "threats_added_sast_backed": sast_backed_count,
            "sast_findings_resolved": len(sast_diff["resolved"]),
            "sast_findings_persisting": len(sast_diff["persisting"]),
            "sast_findings_new": len(sast_diff["new"]),
            "entry_points_unchanged": len(ep_diff["unchanged"]),
            "entry_points_modified": len(ep_diff["modified"]),
            "entry_points_added": len(ep_diff["added"]),
            "entry_points_removed": len(ep_diff["removed"]),
            "assets_unchanged": len(asset_diff["unchanged"]),
            "assets_modified": len(asset_diff["modified"]),
            "assets_added": len(asset_diff["added"]),
            "assets_removed": len(asset_diff["removed"]),
            "components_unchanged": len(component_diff["unchanged"]),
            "components_modified": len(component_diff["modified"]),
            "components_added": len(component_diff["added"]),
            "components_removed": len(component_diff["removed"]),
            "parser_drift_count": len(parser_drift),
            "graph_nodes_added": len(graph_diff["nodes"]["added"]),
            "graph_nodes_removed": len(graph_diff["nodes"]["removed"]),
            "graph_edges_added": len(graph_diff["edges"]["added"]),
            "graph_edges_removed": len(graph_diff["edges"]["removed"]),
            "scenarios_unchanged": len(scenario_diff["unchanged"]),
            "scenarios_modified": len(scenario_diff["modified"]),
            "scenarios_added": len(scenario_diff["added"]),
            "scenarios_removed": len(scenario_diff["removed"]),
        },
        "threats": {
            "unchanged": threat_diff["unchanged"],
            "modified": threat_diff["modified"],
            "added": added_threats,
            "removed": threat_diff["removed"],
            "resolved": threat_transitions["resolved"],
            "downgraded": threat_transitions["downgraded"],
            "persisting": threat_transitions["persisting"],
        },
        "sast_findings": sast_diff,
        "entry_points": ep_diff,
        "assets": asset_diff,
        "components": component_diff,
        "parser_drift": parser_drift,
        "graph_diff": graph_diff,
        "scenarios": scenario_diff,
    }


@router.get("/compare")
def compare_versions(
    project_id: str,
    a: str = Query(...),
    b: str = Query(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    get_project_or_404(db, project_id, current_user.id)
    version_a = get_version_or_404(db, project_id, a)
    version_b = get_version_or_404(db, project_id, b)

    threat_state_a = _threat_state_for_version(db, project_id=project_id, version=version_a)
    threat_state_b = _threat_state_for_version(db, project_id=project_id, version=version_b)
    mitigation_state_a = _mitigation_state_for_version(db, project_id=project_id, version=version_a)
    mitigation_state_b = _mitigation_state_for_version(db, project_id=project_id, version=version_b)

    threat_ids_a = set(threat_state_a.keys())
    threat_ids_b = set(threat_state_b.keys())
    mitigation_ids_a = set(mitigation_state_a.keys())
    mitigation_ids_b = set(mitigation_state_b.keys())

    # Semantic fallback: pair unmatched DB threats from A and B by normalized name.
    # This handles the case where entity ID stability was not yet in place for old versions,
    # so the same real threat was persisted under two different DB IDs.
    unmatched_a = threat_ids_a - threat_ids_b
    unmatched_b = threat_ids_b - threat_ids_a

    # Build name-slug → id map for each unmatched set.
    a_slug_to_id: dict[str, str] = {
        _name_slug(threat_state_a[tid].get("name") or ""): tid
        for tid in unmatched_a
        if _name_slug(threat_state_a[tid].get("name") or "")
    }
    semantic_pairs: dict[str, str] = {}  # b_id → a_id
    truly_new: set[str] = set()
    for tid in unmatched_b:
        slug = _name_slug(threat_state_b[tid].get("name") or "")
        if slug and slug in a_slug_to_id:
            semantic_pairs[tid] = a_slug_to_id[slug]
        else:
            truly_new.add(tid)

    truly_removed = unmatched_a - set(semantic_pairs.values())

    new_threats = [
        {"id": tid, "name": threat_state_b[tid]["name"], "severity": threat_state_b[tid]["severity"]}
        for tid in sorted(truly_new)
    ]
    removed_threats = [
        {"id": tid, "name": threat_state_a[tid]["name"], "severity": threat_state_a[tid]["severity"]}
        for tid in sorted(truly_removed)
    ]

    # Treat semantically paired threats as shared for scoring comparisons.
    shared_pairs: list[tuple[str, str]] = (
        [(tid, tid) for tid in sorted(threat_ids_a & threat_ids_b)]
        + [(b_id, a_id) for b_id, a_id in sorted(semantic_pairs.items())]
    )

    SEVERITY_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

    risk_score_changes = []
    severity_changes = []
    for b_tid, a_tid in shared_pairs:
        threat_a = threat_state_a[a_tid]
        threat_b = threat_state_b[b_tid]

        old_score = threat_a.get("risk_score")
        new_score = threat_b.get("risk_score")
        if isinstance(old_score, (int, float)) and isinstance(new_score, (int, float)) and old_score != new_score:
            risk_score_changes.append(
                {
                    "id": b_tid,
                    "name": threat_b["name"],
                    "old_score": old_score,
                    "new_score": new_score,
                    "improved": new_score < old_score,
                }
            )

        old_sev = threat_a.get("severity") or ""
        new_sev = threat_b.get("severity") or ""
        if old_sev != new_sev and old_sev and new_sev:
            old_rank = SEVERITY_ORDER.get(old_sev, 0)
            new_rank = SEVERITY_ORDER.get(new_sev, 0)
            severity_changes.append(
                {
                    "id": b_tid,
                    "name": threat_b["name"],
                    "old_severity": old_sev,
                    "new_severity": new_sev,
                    "escalated": new_rank > old_rank,
                }
            )

    mitigation_changes = []
    for mid in sorted(mitigation_ids_a | mitigation_ids_b):
        old_status = mitigation_state_a.get(mid, {}).get("status")
        new_status = mitigation_state_b.get(mid, {}).get("status")
        if old_status == new_status:
            continue
        name = mitigation_state_b.get(mid, {}).get("name") or mitigation_state_a.get(mid, {}).get("name") or mid
        mitigation_changes.append(
            {
                "id": mid,
                "name": name,
                "old_status": old_status or "N/A",
                "new_status": new_status or "N/A",
            }
        )

    threats_shared = len(threat_ids_a & threat_ids_b) + len(semantic_pairs)
    return {
        "version_a": {"id": version_a.id, "version_number": version_a.version_number},
        "version_b": {"id": version_b.id, "version_number": version_b.version_number},
        "summary": {
            "threats_added": len(truly_new),
            "threats_removed": len(truly_removed),
            "threats_shared": threats_shared,
            "threats_matched_by_id": len(threat_ids_a & threat_ids_b),
            "threats_matched_by_name": len(semantic_pairs),
            "severity_escalations": sum(1 for s in severity_changes if s["escalated"]),
            "severity_improvements": sum(1 for s in severity_changes if not s["escalated"]),
            "mitigations_added": len(mitigation_ids_b - mitigation_ids_a),
            "mitigations_removed": len(mitigation_ids_a - mitigation_ids_b),
            "mitigations_shared": len(mitigation_ids_a & mitigation_ids_b),
        },
        "new_threats": new_threats,
        "removed_threats": removed_threats,
        "severity_changes": severity_changes,
        "risk_score_changes": risk_score_changes,
        "mitigation_changes": mitigation_changes,
    }


@router.get("/{version_id}", response_model=schemas.VersionDetailOut)
def get_version_detail(
    project_id: str,
    version_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    project = get_project_or_404(db, project_id, current_user.id)
    version = get_version_or_404(db, project_id, version_id)

    threat_snapshots = (
        db.query(models.ThreatSnapshot)
        .filter(models.ThreatSnapshot.version_id == version.id)
        .all()
    )
    mitigation_snapshots = (
        db.query(models.MitigationSnapshot)
        .filter(models.MitigationSnapshot.version_id == version.id)
        .all()
    )

    if threat_snapshots or mitigation_snapshots:
        version_threats = [
            {
                "id": s.threat_id,
                "project_id": project_id,
                "name": s.name,
                "description": None,
                "category": None,
                "severity": s.severity,
                "likelihood": None,
                "impact": None,
                "risk_score": s.risk_score,
                "status": s.status,
                "affected_component": s.affected_component,
                "identified_stage": s.identified_stage,
                "source": s.source,
                "commit_hash": None,
                "introduced_in": None,
                "identified_in_phase": None,
                "introduced_in_version_id": version.id,
                "accepted_risk_info": None,
                "events": None,
                "created_at": s.created_at,
                "updated_at": s.created_at,
            }
            for s in threat_snapshots
        ]
        version_mitigations = [
            {
                "id": s.mitigation_id,
                "project_id": project_id,
                "threat_id": None,
                "title": s.title,
                "description": s.description,
                "status": s.status,
                "owner": None,
                "priority": s.priority,
                "type": s.type,
                "assignee": s.assignee,
                "due_date": s.due_date,
                "introduced_in_version_id": version.id,
                "created_at": s.created_at,
                "updated_at": s.created_at,
            }
            for s in mitigation_snapshots
        ]
    else:
        threat_ids = set(version.threat_ids or [])
        mitigation_ids = set(version.mitigation_ids or [])

        threats = (
            db.query(models.Threat)
            .filter(models.Threat.project_id == project_id)
            .all()
        )
        mitigations = (
            db.query(models.Mitigation)
            .filter(models.Mitigation.project_id == project_id)
            .all()
        )

        version_threats = [t for t in threats if t.id in threat_ids]
        version_mitigations = [m for m in mitigations if m.id in mitigation_ids]

    return {
        "project_id": project_id,
        "current_version_id": project.current_version_id,
        "version": version,
        "threats": version_threats,
        "mitigations": version_mitigations,
    }
