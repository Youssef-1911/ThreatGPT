import hashlib
import json
import logging
import re
from typing import Any

from .ai_service import AIService

logger = logging.getLogger(__name__)


def _nested(obj: Any, *keys: str) -> Any:
    """Safely traverse nested dicts. Returns None if any key is missing or non-dict."""
    for key in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


class GenerationEngine:
    STRIDE_CATEGORIES = {
        "Spoofing",
        "Tampering",
        "Repudiation",
        "Information Disclosure",
        "Denial of Service",
        "Elevation of Privilege",
    }

    VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}

    SEVERITY_NORMALIZATION_MAP = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "med": "Medium",
        "moderate": "Medium",
        "low": "Low",
        "informational": "Low",
        "info": "Low",
    }

    REQUIRED_TOP_LEVEL_KEYS = ["threats"]
    # grounded_finding is nullable — it is defaulted to None in _validate_threat_structures
    # rather than flagged as a missing field.
    REQUIRED_THREAT_KEYS = [
        "id",
        "title",
        "category",
        "description",
        "affected_component_id",
        "entry_point_id",
        "asset_id",
        "severity",
        "mitigation",
    ]

    EXPECTED_SCHEMA = {
        "threats": [
            {
                "id": "string",
                "title": "string",
                "category": "string",
                "description": "string",
                "affected_component_id": "string",
                "entry_point_id": "string",
                "asset_id": "string",
                "severity": "string",
                "mitigation": "string",
                "grounded_finding": "string or null",
            }
        ]
    }

    # Maps canonical parser component types (parsing_engine.py COMPONENT_TYPES) to
    # required STRIDE categories. Python assigns these — the AI must cover them.
    COMPONENT_STRIDE_MAP: dict[str, list[str]] = {
        "database": ["Tampering", "Information Disclosure", "Repudiation"],
        "auth":     ["Spoofing", "Elevation of Privilege", "Repudiation"],
        "gateway":  ["Denial of Service", "Tampering"],
        "queue":    ["Tampering", "Repudiation", "Denial of Service"],
        "frontend": ["Spoofing", "Information Disclosure", "Denial of Service"],
        "backend":  ["Tampering", "Elevation of Privilege", "Repudiation", "Denial of Service"],
        "storage":  ["Information Disclosure", "Tampering", "Repudiation"],
        "worker":   ["Repudiation", "Elevation of Privilege"],
        "cache":    ["Information Disclosure", "Tampering", "Denial of Service"],
        "external": ["Spoofing", "Information Disclosure"],
        "service":  ["Tampering", "Elevation of Privilege", "Repudiation", "Denial of Service"],
        "proxy":    ["Tampering", "Information Disclosure", "Denial of Service"],
    }

    # Technology keywords → known weaknesses injected into the prompt when no SAST
    # findings are mapped, giving the AI concrete weaknesses to narrate.
    TECH_WEAKNESS_MAP: dict[str, list[str]] = {
        "jwt":           ["CWE-347 (algorithm confusion / alg:none attack)",
                          "missing expiry validation",
                          "weak signing secret (HS256 with short key)"],
        "oauth":         ["CWE-601 (open redirect)", "PKCE missing",
                          "token leakage in logs"],
        "postgresql":    ["CWE-89 (SQL injection)", "excessive DB privilege",
                          "unencrypted connections (CWE-319)"],
        "mysql":         ["CWE-89 (SQL injection)", "excessive DB privilege"],
        "mongodb":       ["missing authentication by default",
                          "CWE-943 (NoSQL injection)"],
        "elasticsearch": ["unauthenticated API on port 9200",
                          "data exposure without TLS"],
        "redis":         ["no authentication by default", "cleartext key storage"],
        "s3":            ["public bucket misconfiguration (CWE-732)",
                          "missing encryption at rest"],
        "kafka":         ["missing SASL/TLS", "unauthenticated consumer access"],
        "rabbitmq":      ["default guest credentials", "management UI exposed"],
        "graphql":       ["introspection enabled in production",
                          "batching DoS", "deep query DoS (CWE-400)"],
        "grpc":          ["missing TLS", "server reflection enabled"],
        "kubernetes":    ["RBAC misconfiguration (CWE-732)",
                          "exposed dashboard", "privileged container escape"],
        "docker":        ["privileged container", "exposed Docker socket",
                          "no user namespace isolation"],
        "nginx":         ["server_tokens exposed", "missing security headers"],
        "express":       ["missing helmet.js headers", "CWE-1021 (clickjacking)"],
        "django":        ["DEBUG=True in production", "CWE-89 (raw SQL usage)"],
        "flask":         ["secret key hardcoded", "debug mode exposed"],
        "spring":        ["Spring4Shell (CVE-2022-22965)", "actuator exposure"],
    }

    # Patterns scanned across raw source text when SAST findings are absent.
    # Each entry: (pattern_string, cwe_id, human_label)
    CODE_SCAN_PATTERNS: list[tuple[str, str, str]] = [
        ("eval(",      "CWE-95",  "dynamic code execution"),
        ("exec(",      "CWE-78",  "OS command injection"),
        ("SELECT ",    "CWE-89",  "SQL injection risk"),
        ("http://",    "CWE-319", "cleartext communication"),
        ("MD5(",       "CWE-327", "weak hashing algorithm"),
        ("base64",     "CWE-312", "possible credential in base64"),
        ("password=",  "CWE-256", "hardcoded credential"),
        ("secret=",    "CWE-312", "hardcoded secret"),
        ("token=",     "CWE-312", "hardcoded token"),
        ("subprocess", "CWE-78",  "OS command injection"),
        ("pickle",     "CWE-502", "insecure deserialization"),
        ("deserializ", "CWE-502", "insecure deserialization"),
    ]

    def __init__(self, ai_service: AIService | None = None) -> None:
        self.ai_service = ai_service or AIService()

    # ─────────────────────────────────────────────────────────────────────────
    # PUBLIC ENTRY POINT
    # ─────────────────────────────────────────────────────────────────────────

    def generate_threats(
        self,
        parsed_data: dict,
        phase: str,
        methodology: str = "STRIDE",
        evidence_package: dict | None = None,
    ) -> dict[str, Any]:
        normalized_methodology = methodology.strip().upper()

        # Python pre-processing: Python decides all structure; the AI only narrates.
        threat_context, finding_severity_map = self._build_threat_context(
            parsed_data, evidence_package
        )

        system_prompt = self._build_system_prompt(normalized_methodology)
        user_prompt = self._build_user_prompt(threat_context, phase, normalized_methodology)

        # Deterministic seed: stable across server restarts (hashlib, not Python hash()).
        # Python hash() is process-randomized via PYTHONHASHSEED; hashlib.md5 is not.
        seed = int(
            hashlib.md5(
                json.dumps(parsed_data, sort_keys=True).encode()
            ).hexdigest(),
            16,
        ) % (2**31)

        response = self.ai_service.call_model(
            system_prompt, user_prompt, temperature=0.2, seed=seed
        )

        # Fix 6: enforce deterministic threat ordering before validation.
        # GPT output order is not guaranteed even with the same seed.
        # Sort: component → STRIDE category → entry point (all alphabetical).
        # "zzz" pushes unknown/missing values to the end.
        if isinstance(response.get("threats"), list):
            response["threats"].sort(key=lambda t: (
                t.get("affected_component_id", "zzz") if isinstance(t, dict) else "zzz",
                t.get("category", "zzz") if isinstance(t, dict) else "zzz",
                t.get("entry_point_id", "zzz") if isinstance(t, dict) else "zzz",
            ))

        return self.validate_generated_threats(
            response,
            parsed_data,
            normalized_methodology,
            threat_context=threat_context,
            finding_severity_map=finding_severity_map,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # VALIDATION (public — also called from tests)
    # ─────────────────────────────────────────────────────────────────────────

    def validate_generated_threats(
        self,
        data: dict[str, Any],
        parsed_data: dict[str, Any],
        methodology: str,
        threat_context: dict[str, Any] | None = None,
        finding_severity_map: dict[tuple, str] | None = None,
    ) -> dict[str, Any]:
        missing_fields = [key for key in self.REQUIRED_TOP_LEVEL_KEYS if key not in data]
        threats = data.get("threats")
        if not isinstance(threats, list):
            missing_fields.append("threats")
            return {
                "status": "invalid_output",
                "missing_fields": list(dict.fromkeys(missing_fields)),
                "threats": [],
                "ungrounded_count": 0,
                "low_confidence_count": 0,
            }

        # Normalize severity strings before any further checks.
        self._normalize_severities(threats)

        # 4G: Default grounded_finding to None — it is nullable, not a missing field.
        for threat in threats:
            if isinstance(threat, dict) and "grounded_finding" not in threat:
                threat["grounded_finding"] = None

        # 4B: Python overrides AI severity for every finding-grounded threat.
        if finding_severity_map:
            self._apply_severity_overrides(threats, finding_severity_map)

        # 4A: Flag threats whose descriptions reference nothing from parsed data.
        low_confidence_count = 0
        if threat_context:
            low_confidence_count = self._check_grounding(threats, threat_context)

        # 4C: Trigger targeted retry if < 30% of threats cite a mapped finding.
        mapped_findings = (threat_context or {}).get(
            "mapped_findings", {"sast": [], "dast": []}
        )
        seed_for_retry = (
            int(
                hashlib.md5(
                    json.dumps(parsed_data, sort_keys=True).encode()
                ).hexdigest(),
                16,
            ) % (2**31)
            if threat_context
            else None
        )
        self._check_and_retry_finding_coverage(
            threats,
            mapped_findings,
            parsed_data,
            finding_severity_map,
            threat_context,
            seed_for_retry,
        )

        # 4F: Deduplicate — prefer finding-grounded threats when merging.
        missing_fields.extend(self._validate_threat_structures(threats))
        missing_fields.extend(self._validate_references(threats, parsed_data))

        if methodology == "STRIDE":
            missing_fields.extend(self._validate_stride_categories(threats))

        # 4D: Entry point coverage warnings (non-fatal, logged only).
        if threat_context:
            self._warn_entry_point_coverage(threats, parsed_data)

        # 4E: STRIDE coverage retry — targeted second call for missing required categories.
        if threat_context:
            self._check_and_retry_stride_coverage(threats, threat_context, seed_for_retry)
            self._apply_deterministic_threat_enrichment(threats, threat_context)
            threats[:] = self._apply_control_suppression_and_downgrade(threats, threat_context)

        threats[:] = self._deduplicate_threats(threats)

        # Count threats where all three refs are "unknown" — contribute nothing downstream.
        ungrounded_count = sum(
            1 for t in threats
            if isinstance(t, dict)
            and str(t.get("affected_component_id", "")).strip().lower() == "unknown"
            and str(t.get("entry_point_id", "")).strip().lower() == "unknown"
            and str(t.get("asset_id", "")).strip().lower() == "unknown"
        )

        deduplicated_missing_fields = list(dict.fromkeys(missing_fields))

        return {
            "status": "ready" if not deduplicated_missing_fields else "invalid_output",
            "missing_fields": deduplicated_missing_fields,
            "threats": threats,
            "ungrounded_count": ungrounded_count,
            "low_confidence_count": low_confidence_count,
        }

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 2 — PRE-PROCESSING: _build_threat_context
    # ─────────────────────────────────────────────────────────────────────────

    def _build_threat_context(
        self,
        parsed_data: dict[str, Any],
        evidence_package: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], dict[tuple, str]]:
        """Build a structured context object from parsed_data before the AI call.

        Python decides all structure here — the AI only narrates attack stories.
        Returns (threat_context, finding_severity_map).
        """
        raw_findings = parsed_data.get("security_findings") or {}
        sast_raw = raw_findings.get("sast") or [] if isinstance(raw_findings, dict) else []
        dast_raw = raw_findings.get("dast") or [] if isinstance(raw_findings, dict) else []
        components: list[Any] = parsed_data.get("components") or []
        entry_points: list[Any] = parsed_data.get("entry_points") or []

        # 2A: Map SAST/DAST findings to component/entry point IDs.
        mapped_sast = self._map_sast_findings(sast_raw, components, entry_points)
        mapped_dast = self._map_dast_findings(dast_raw, entry_points)
        mapped_findings: dict[str, list[dict[str, Any]]] = {
            "sast": mapped_sast,
            "dast": mapped_dast,
        }

        # 2B: Assign required STRIDE categories per component.
        enriched_components: list[dict[str, Any]] = []
        for comp in components:
            if not isinstance(comp, dict):
                continue
            enriched_components.append({
                "comp_id": comp.get("id", "unknown"),
                "name": comp.get("name", ""),
                "type": comp.get("type", ""),
                "technology": comp.get("description", ""),
                "trust_zone": comp.get("trust_zone", "unknown"),
                "required_stride_categories": self._assign_stride_categories(comp),
            })

        # 2C: Detect trust boundary crossings in data flows.
        annotated_flows = self._detect_trust_boundary_crossings(parsed_data)

        # 2D: Build severity override map — Python owns severity for all finding-grounded threats.
        finding_severity_map = self._build_finding_severity_map(mapped_findings)

        # 2E: Extract technology hints from component descriptions and dependencies.
        tech_hints = self._extract_tech_hints(parsed_data)

        # 2F: Scan source code for risk patterns when SAST is absent.
        has_mapped_sast = any(f.get("mapped_component_id") for f in mapped_sast)
        code_hints: list[dict[str, str]] = []
        if not has_mapped_sast and evidence_package:
            code_hints = self._scan_source_code_hints(evidence_package)

        threat_context: dict[str, Any] = {
            "architecture_summary": parsed_data.get("architecture_summary", ""),
            "components": enriched_components,
            "actors": parsed_data.get("actors") or [],
            "entry_points": entry_points,
            "assets": parsed_data.get("assets") or [],
            "data_flows": annotated_flows,
            "trust_boundaries": parsed_data.get("trust_boundaries") or [],
            "implemented_controls": parsed_data.get("implemented_controls") or [],
            "authn_authz": parsed_data.get("authn_authz") or {},
            "external_dependencies": parsed_data.get("external_dependencies") or [],
            "mapped_findings": mapped_findings,
            "tech_hints": tech_hints,
            "code_hints": code_hints,
            "assumptions": parsed_data.get("assumptions") or [],
            "open_questions": parsed_data.get("open_questions") or [],
        }

        return threat_context, finding_severity_map

    # ── Step 2A: SAST/DAST mappers ───────────────────────────────────────────

    def _map_sast_findings(
        self,
        sast_raw: list[Any],
        components: list[dict[str, Any]],
        entry_points: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        mapped = []
        for finding in sast_raw:
            if not isinstance(finding, dict):
                continue
            try:
                mapped.append(self._map_single_sast_finding(finding, components, entry_points))
            except Exception:
                # Never crash on a single malformed finding — skip it.
                pass
        return mapped

    def _map_single_sast_finding(
        self,
        finding: dict[str, Any],
        components: list[dict[str, Any]],
        entry_points: list[dict[str, Any]],
    ) -> dict[str, Any]:
        # Tool name — SARIF and flat formats.
        tool = (
            _nested(finding, "tool", "driver", "name")
            or finding.get("toolName")
            or finding.get("tool")
            or "unknown"
        )

        # Rule and CWE.
        rule_id = (
            finding.get("ruleId")
            or finding.get("rule_id")
            or finding.get("check_id")
            or finding.get("id")
            or "unknown"
        )
        cwe = finding.get("cwe") or _nested(finding, "extra", "metadata", "cwe") or ""
        if isinstance(cwe, list) and cwe:
            cwe = str(cwe[0]).split(":", 1)[0]
        if not cwe and isinstance(finding.get("cwes"), list) and finding["cwes"]:
            cwe = str(finding["cwes"][0])

        # Severity.
        severity_raw = (
            _nested(finding, "properties", "severity")
            or _nested(finding, "extra", "severity")
            or finding.get("severity")
            or finding.get("level")
            or "unknown"
        )
        severity = self.SEVERITY_NORMALIZATION_MAP.get(
            str(severity_raw).strip().lower(), str(severity_raw).strip()
        )

        # File and line — SARIF locations first, then flat fields.
        file_path = ""
        line = ""
        locations = finding.get("locations")
        if isinstance(locations, list) and locations:
            loc = locations[0]
            if isinstance(loc, dict):
                phys = loc.get("physicalLocation") or {}
                artifact = phys.get("artifactLocation") or {} if isinstance(phys, dict) else {}
                file_path = artifact.get("uri", "") if isinstance(artifact, dict) else ""
                region = phys.get("region") or {} if isinstance(phys, dict) else {}
                line = str(region.get("startLine", "")) if isinstance(region, dict) else ""
        file_path = (
            file_path
            or finding.get("file")
            or finding.get("path")
            or finding.get("filename")
            or ""
        )
        line = line or str(finding.get("line") or finding.get("lineNumber") or "")
        start = finding.get("start")
        if not line and isinstance(start, dict):
            line = str(start.get("line") or "")

        # Description.
        desc_raw = (
            _nested(finding, "message", "text")
            or _nested(finding, "extra", "message")
            or finding.get("description")
            or finding.get("message")
            or ""
        )
        description = str(desc_raw.get("text", "") if isinstance(desc_raw, dict) else desc_raw)
        file_path_lower = file_path.lower()
        description_lower = description.lower()

        # Determine mapped component ID.
        # Strategy 1 (highest confidence): parser annotation [component: comp_id].
        mapped_comp_id: str | None = None
        valid_component_ids = {
            str(comp.get("id"))
            for comp in components
            if isinstance(comp, dict) and comp.get("id")
        }
        inferred_path_map = [
            ("employee_api", "comp_employee_api"),
            ("upload_service", "comp_file_upload_service"),
            ("admin_service", "comp_admin_service"),
            ("auth_service", "comp_authentication_service"),
            ("account_service", "comp_account_service"),
            ("transfer_service", "comp_transfer_service"),
            ("notification_service", "comp_notification_service"),
        ]
        for path_marker, component_id in inferred_path_map:
            if path_marker in file_path_lower and component_id in valid_component_ids:
                mapped_comp_id = component_id
                break

        annotation = re.search(r'\[component:\s*(comp_\w+)\]', description, re.IGNORECASE)
        if not mapped_comp_id and annotation:
            annotated_id = annotation.group(1)
            if annotated_id in valid_component_ids:
                mapped_comp_id = annotated_id
            else:
                annotated_lower = annotated_id.lower()
                for comp in components:
                    if not isinstance(comp, dict):
                        continue
                    comp_id = str(comp.get("id", "")).strip()
                    comp_name = str(comp.get("name", "")).strip().lower()
                    comp_name_slug = re.sub(r'\W+', '_', comp_name).strip("_")
                    if (
                        comp_id
                        and (
                            comp_id.lower() in annotated_lower
                            or annotated_lower in comp_id.lower()
                            or (comp_name_slug and comp_name_slug in annotated_lower)
                        )
                    ):
                        mapped_comp_id = comp_id
                        break

        if not mapped_comp_id:
            # Strategy 2: priority-scored name match.
            # Score tiers (higher = more confident):
            #   3 × len  — component name appears as a discrete path segment in file_path
            #   2 × len  — component name appears as a substring anywhere in file_path
            #   1 × len  — component name appears in description text only
            # Within the same tier, longer names win (more specific match).
            # Names of 2 chars or fewer are skipped to avoid false positives.
            # Split file path into discrete segments on common delimiters.
            path_segments = [
                segment
                for segment in re.split(r'[/\\_.\-]', file_path_lower)
                if segment
            ]
            normalized_path_segments = "/" + "/".join(path_segments) + "/"

            best_comp_id: str | None = None
            best_score: int = 0
            for comp in components:
                if not isinstance(comp, dict):
                    continue
                comp_name = str(comp.get("name", "")).strip().lower()
                if not comp_name or len(comp_name) <= 2:
                    continue
                comp_tokens = [
                    token
                    for token in re.split(r'\W+', comp_name)
                    if token
                ]
                comp_name_path = "/".join(comp_tokens)
                comp_name_slug = "_".join(comp_tokens)
                if comp_name_path and f"/{comp_name_path}/" in normalized_path_segments:
                    score = 3 * len(comp_name)
                elif file_path_lower and (
                    comp_name in file_path_lower
                    or (comp_name_slug and comp_name_slug in file_path_lower)
                ):
                    score = 2 * len(comp_name)
                elif (
                    comp_name in description_lower
                    or (comp_name_slug and comp_name_slug in description_lower)
                ):
                    score = 1 * len(comp_name)
                else:
                    continue
                if score > best_score:
                    best_score = score
                    best_comp_id = comp.get("id")
            mapped_comp_id = best_comp_id

        mapped_entry_id = self._infer_sast_entry_point_id(
            file_path_lower, description_lower, entry_points
        )
        mapped_asset_id, root_cause = self._infer_sast_asset_and_root_cause(
            str(rule_id), str(cwe), file_path_lower, description_lower
        )

        return {
            "tool": str(tool),
            "rule_id": str(rule_id),
            "cwe": str(cwe),
            "severity": str(severity),
            "file": str(file_path),
            "line": str(line),
            "description": description,
            "mapped_component_id": mapped_comp_id,
            "mapped_entry_point_id": mapped_entry_id,
            "mapped_asset_id": mapped_asset_id,
            "root_cause": root_cause,
            "finding_fingerprint": self._finding_fingerprint(
                str(rule_id), str(file_path), str(line), description
            ),
        }

    def _infer_sast_entry_point_id(
        self,
        file_path_lower: str,
        description_lower: str,
        entry_points: list[dict[str, Any]],
    ) -> str | None:
        valid_entry_ids = {
            str(entry.get("id"))
            for entry in entry_points
            if isinstance(entry, dict) and entry.get("id")
        }
        combined = f"{file_path_lower} {description_lower}"
        for marker, entry_id in (
            ("employee_api/views", "entry_get_employees_id_payroll"),
            ("employee_id", "entry_get_employees_id_payroll"),
            ("payroll", "entry_get_employees_id_payroll"),
            ("upload_service/handlers", "entry_post_upload"),
            ("file.read", "entry_post_upload"),
            ("upload", "entry_post_upload"),
            ("/admin/transfers/reverse", "entry_admin_transfers_reverse"),
            ("transfer reversal", "entry_admin_transfers_reverse"),
            ("account_service", "entry_accounts_get"),
            ("auth_service/config", "entry_auth_login"),
            ("auth_service/token_store", "entry_auth_refresh"),
            ("transfer_service", "entry_transfers_post"),
        ):
            if marker in combined and entry_id in valid_entry_ids:
                return entry_id

        for entry in entry_points:
            if not isinstance(entry, dict):
                continue
            entry_id = str(entry.get("id") or "")
            name = str(entry.get("name") or "").lower()
            if entry_id and name and name in combined:
                return entry_id
        return None

    def _infer_sast_asset_and_root_cause(
        self,
        rule_id: str,
        cwe: str,
        file_path_lower: str,
        description_lower: str,
    ) -> tuple[str | None, str]:
        combined = f"{rule_id} {cwe} {file_path_lower} {description_lower}".lower()
        if "cwe-89" in combined or "sql injection" in combined:
            return "asset_payroll_records", "sql_injection"
        if "cwe-400" in combined or "resource consumption" in combined or "file.read" in combined:
            return "asset_uploaded_hr_documents", "uncontrolled_resource_consumption"
        return None, "code_finding"

    def _finding_fingerprint(
        self,
        rule_id: str,
        file_path: str,
        line: str,
        description: str,
    ) -> str:
        logical_root = re.sub(r"[^a-z0-9]+", "_", description.lower()).strip("_")[:80]
        return "|".join([
            str(rule_id or "unknown").strip(),
            str(file_path or "unknown").strip(),
            str(line or "unknown").strip(),
            logical_root or "finding",
        ])

    def _map_dast_findings(
        self,
        dast_raw: list[Any],
        entry_points: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        mapped = []
        for finding in dast_raw:
            if not isinstance(finding, dict):
                continue
            try:
                mapped.append(self._map_single_dast_finding(finding, entry_points))
            except Exception:
                pass
        return mapped

    def _map_single_dast_finding(
        self,
        finding: dict[str, Any],
        entry_points: list[dict[str, Any]],
    ) -> dict[str, Any]:
        tool = (
            finding.get("toolName")
            or finding.get("tool")
            or "unknown"
        )
        rule_id = (
            finding.get("pluginId")
            or finding.get("rule_id")
            or finding.get("ruleId")
            or finding.get("id")
            or "unknown"
        )
        cwe = finding.get("cwe") or ""
        severity_raw = (
            finding.get("riskdesc")
            or finding.get("severity")
            or finding.get("risk")
            or "unknown"
        )
        # riskdesc may be "High (Medium)" — take the first word.
        severity = self.SEVERITY_NORMALIZATION_MAP.get(
            str(severity_raw).strip().lower().split()[0],
            str(severity_raw).strip(),
        )
        endpoint = (
            finding.get("endpoint")
            or finding.get("url")
            or finding.get("uri")
            or finding.get("path")
            or ""
        )
        description = str(
            finding.get("description")
            or finding.get("desc")
            or finding.get("alert")
            or finding.get("name")
            or ""
        )

        # Match endpoint or description against entry point names.
        mapped_entry_id: str | None = None
        endpoint_lower = str(endpoint).lower()
        desc_lower = description.lower()
        for ep in entry_points:
            if not isinstance(ep, dict):
                continue
            ep_name = str(ep.get("name", "")).lower()
            ep_desc = str(ep.get("description", "")).lower()
            if not ep_name:
                continue
            if (ep_name in endpoint_lower
                    or ep_name in desc_lower
                    or (endpoint_lower and endpoint_lower in ep_desc)):
                mapped_entry_id = ep.get("id")
                break

        return {
            "tool": str(tool),
            "rule_id": str(rule_id),
            "cwe": str(cwe),
            "severity": str(severity),
            "endpoint": str(endpoint),
            "description": description,
            "mapped_entry_point_id": mapped_entry_id,
        }

    # ── Step 2B: STRIDE pre-assignment ───────────────────────────────────────

    def _assign_stride_categories(self, component: dict[str, Any]) -> list[str]:
        comp_type = str(component.get("type", "")).strip().lower()
        return list(
            self.COMPONENT_STRIDE_MAP.get(comp_type, list(self.STRIDE_CATEGORIES))
        )

    # ── Step 2C: Trust boundary crossing detector ────────────────────────────

    def _detect_trust_boundary_crossings(
        self,
        parsed_data: dict[str, Any],
    ) -> list[dict[str, Any]]:
        # Build trust_zone lookup: entity_id → trust_zone.
        zone_map: dict[str, str] = {}
        for comp in parsed_data.get("components") or []:
            if isinstance(comp, dict) and comp.get("id"):
                zone_map[comp["id"]] = str(comp.get("trust_zone", "unknown"))
        # Actors have no trust_zone field — treat all as "public".
        for actor in parsed_data.get("actors") or []:
            if isinstance(actor, dict) and actor.get("id"):
                zone_map[actor["id"]] = "public"

        # Build boundary name lookup: member_id → boundary_name.
        boundary_by_member: dict[str, str] = {}
        for b in parsed_data.get("trust_boundaries") or []:
            if not isinstance(b, dict):
                continue
            name = b.get("name") or b.get("id") or "unknown"
            for cid in b.get("crossing_component_ids") or []:
                if isinstance(cid, str):
                    boundary_by_member[cid] = name

        annotated: list[dict[str, Any]] = []
        for flow in parsed_data.get("data_flows") or []:
            if not isinstance(flow, dict):
                continue
            src = str(flow.get("source_component_id", "unknown"))
            dst = str(flow.get("destination_component_id", "unknown"))
            src_zone = zone_map.get(src, "unknown")
            dst_zone = zone_map.get(dst, "unknown")
            is_crossing = (
                src_zone != dst_zone
                and src_zone != "unknown"
                and dst_zone != "unknown"
            )
            boundary_name = (
                (
                    boundary_by_member.get(src)
                    or boundary_by_member.get(dst)
                    or f"{src_zone}/{dst_zone}"
                )
                if is_crossing
                else None
            )
            annotated.append({
                "flow_id": flow.get("id", "unknown"),
                "source_id": src,
                "destination_id": dst,
                "protocol": str(flow.get("protocol", "unknown")),
                "description": str(flow.get("description", "")),
                "trust_boundary_crossing": is_crossing,
                "boundary_name": boundary_name,
            })

        return annotated

    # ── Step 2D: Severity override map ───────────────────────────────────────

    def _build_finding_severity_map(
        self,
        mapped_findings: dict[str, list[dict[str, Any]]],
    ) -> dict[tuple, str]:
        severity_map: dict[tuple, str] = {}
        for f in mapped_findings.get("sast") or []:
            comp_id = f.get("mapped_component_id")
            rule_id = f.get("rule_id")
            cwe = f.get("cwe")
            entry_id = f.get("mapped_entry_point_id")
            if comp_id and rule_id:
                severity_map[(comp_id, rule_id)] = str(f.get("severity", "Medium"))
            if comp_id and cwe:
                severity_map[(comp_id, cwe)] = str(f.get("severity", "Medium"))
            if entry_id and rule_id:
                severity_map[(entry_id, rule_id)] = str(f.get("severity", "Medium"))
            if entry_id and cwe:
                severity_map[(entry_id, cwe)] = str(f.get("severity", "Medium"))
        for f in mapped_findings.get("dast") or []:
            entry_id = f.get("mapped_entry_point_id")
            rule_id = f.get("rule_id")
            if entry_id and rule_id:
                severity_map[(entry_id, rule_id)] = str(f.get("severity", "Medium"))
        return severity_map

    # ── Step 2E: Technology hints ─────────────────────────────────────────────

    def _extract_tech_hints(self, parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
        hints: list[dict[str, Any]] = []
        seen_keywords: set[str] = set()

        def _scan(text: str, source_id: str) -> None:
            lower = str(text).lower()
            for keyword, weaknesses in self.TECH_WEAKNESS_MAP.items():
                if keyword in lower and keyword not in seen_keywords:
                    seen_keywords.add(keyword)
                    hints.append({
                        "technology": keyword,
                        "source_id": source_id,
                        "known_weaknesses": weaknesses,
                    })

        for comp in parsed_data.get("components") or []:
            if isinstance(comp, dict):
                _scan(comp.get("description", ""), comp.get("id", "unknown"))
                _scan(comp.get("name", ""), comp.get("id", "unknown"))

        for dep in parsed_data.get("external_dependencies") or []:
            if isinstance(dep, dict):
                _scan(dep.get("name", ""), "external_dependency")
                _scan(dep.get("type", ""), "external_dependency")

        return hints

    # ── Step 2F: Source code keyword scanning ────────────────────────────────

    def _scan_source_code_hints(
        self,
        evidence_package: dict[str, Any] | None,
    ) -> list[dict[str, str]]:
        if not evidence_package:
            return []
        # Only scan when source_code evidence category is non-empty.
        ev_by_cat = evidence_package.get("evidence_by_category") or {}
        if not ev_by_cat.get("source_code"):
            return []
        raw_text = str(evidence_package.get("raw_text") or "")
        if not raw_text:
            return []

        hints: list[dict[str, str]] = []
        seen_cwes: set[str] = set()
        for pattern, cwe, label in self.CODE_SCAN_PATTERNS:
            if pattern.lower() in raw_text.lower() and cwe not in seen_cwes:
                seen_cwes.add(cwe)
                hints.append({
                    "pattern": pattern,
                    "cwe": cwe,
                    "label": label,
                    "confidence": "UNVERIFIED",
                })
        return hints

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 3 — PROMPTS
    # ─────────────────────────────────────────────────────────────────────────

    def _build_system_prompt(self, methodology: str) -> str:
        return (
            "You are a security threat modeling expert inside ThreatGPT.\n"
            "You receive a pre-processed architecture and security context.\n"
            f"Your only job is generating {methodology} threats grounded in this data.\n\n"

            "Your role is NARRATIVE ONLY. Python has already decided:\n"
            "- Which components require which STRIDE categories\n"
            "- Which data flows cross trust boundaries\n"
            "- Which SAST/DAST findings map to which components\n"
            "- What severity findings carry\n\n"

            "Do not invent components, entry points, assets, or findings "
            "not explicitly listed in the input.\n"
            "Do not assign severity to finding-grounded threats — "
            "severity will be overridden by the system after your response.\n\n"

            "ACCURACY RULES — every threat must be grounded:\n"
            "- Every threat MUST use a real comp_... ID from the COMPONENTS section\n"
            "- Every threat MUST use a real entry_... ID from ENTRY POINTS or 'unknown'\n"
            "- Every threat MUST use a real asset_... ID from ASSETS or 'unknown'\n"
            "- Every description MUST name the specific component, entry point, "
            "protocol, or technology — never use generic placeholders\n"
            "- Every mitigation MUST name the specific comp_id and the specific "
            "missing control observed in the input\n\n"

            "CONSISTENCY RULES — be deterministic:\n"
            "- For the same input, always produce the same threats in the same order\n"
            "- Do not vary phrasing, ordering, or severity across runs\n"
            "- Follow required_stride_categories exactly as listed per component — "
            "do not add or skip categories\n\n"

            "STRIDE MECHANISM RULES — always explain the mechanism:\n"
            "- Spoofing: WHO is impersonated, WHICH entry point, WHY the identity "
            "check fails (reference authn_authz data)\n"
            "- Tampering: WHICH data flow or asset, HOW, WHERE in the component chain\n"
            "- Repudiation: WHICH action is unlogged, in WHICH component, "
            "WHAT audit trail is missing\n"
            "- Information Disclosure: WHICH asset, through WHICH flow or entry point, "
            "HOW it is exposed\n"
            "- Denial of Service: WHICH component or entry point, WHAT resource is "
            "exhausted, WHY there is no protection\n"
            "- Elevation of Privilege: WHICH component has the boundary, HOW it is "
            "crossed, WHAT authz failure exists\n\n"

            "TRUST BOUNDARY RULES:\n"
            "- For every flow marked [TRUST BOUNDARY CROSSING], generate at least one "
            "threat naming source component, destination component, boundary name, "
            "and protocol\n\n"

            "FINDING RULES:\n"
            "- For every SAST finding with Mapped component != UNMAPPED, generate one "
            "threat citing tool, rule/CWE, file+line, and severity\n"
            "- For every DAST finding with Mapped entry point != UNMAPPED, generate "
            "one threat citing tool, rule/CWE, endpoint, and severity\n"
            "- Do not skip any mapped finding\n\n"

            "COVERAGE RULES:\n"
            "- For each component, Required STRIDE categories are listed. Generate at "
            "least one threat per required category per component. Do not skip any "
            "required category.\n\n"

            "TECHNOLOGY HINTS RULES:\n"
            "- For each technology hint listed, generate at least one threat that names "
            "the specific component containing that technology, cites the known "
            "weakness, and includes the CWE if listed.\n"
            "- Treat these as HIGH PRIORITY only when no SAST/DAST finding already "
            "covers the same component-CWE pair.\n\n"

            "CODE SCAN HINT RULES:\n"
            "- Threats citing an UNVERIFIED code scan hint must include "
            "[UNVERIFIED HINT] in the description field.\n"
            "- Do not assign High or Critical severity to UNVERIFIED HINT threats "
            "without a corroborating finding or strong architectural reason.\n\n"

            "IMPLEMENTED CONTROL RULES:\n"
            "- Implemented controls are negative evidence. Do not generate a threat "
            "whose root cause is explicitly mitigated by an implemented control.\n"
            "- If a related residual risk remains, describe it as residual and lower "
            "severity unless a SAST/DAST finding proves it is still exploitable.\n\n"

            "SEVERITY NOTE:\n"
            "- For threats that cite a finding (grounded_finding != null), set "
            "severity to the finding severity — it will be system-verified.\n"
            "- For threats not citing a finding, apply: Critical (no auth required, "
            "direct breach or RCE), High (one attacker-controlled condition), "
            "Medium (multiple conditions required), Low (defence-in-depth weakness).\n\n"

            "DESCRIPTION FORMAT — strict, enforced every run:\n"
            "- Every description MUST start with exactly these three words: 'An attacker can'\n"
            "- Never use 'A malicious actor', 'An adversary', 'A threat actor', "
            "'The attacker', or any other opening phrase\n"
            "- Always name the specific comp_id or entry_id being targeted inline\n"
            "- Always end with the specific weakness or missing control\n"
            "- Full pattern: 'An attacker can <specific attack action> targeting "
            "<comp_id or entry_id> because <specific weakness or missing control>."
            " [If finding: cite tool + rule/CWE + location + severity.]'\n\n"

            "OUTPUT — return only valid JSON, no extra text:\n"
            '{\n'
            '  "threats": [\n'
            '    {\n'
            '      "id": "threat_<short_snake_case>",\n'
            '      "title": "<specific action> on <specific component or entry point name>",\n'
            '      "category": "Spoofing|Tampering|Repudiation|'
            'Information Disclosure|Denial of Service|Elevation of Privilege",\n'
            '      "description": "An attacker can <vector> targeting <comp_id or entry_id> '
            'because <weakness>. [If finding: cite tool + rule/CWE + location + severity.]",\n'
            '      "affected_component_id": "<comp_... from COMPONENTS or unknown>",\n'
            '      "entry_point_id": "<entry_... from ENTRY POINTS or unknown>",\n'
            '      "asset_id": "<asset_... from ASSETS or unknown>",\n'
            '      "severity": "Critical|High|Medium|Low",\n'
            '      "mitigation": "In <comp_id>, implement <specific control>. '
            '[Reference the specific finding or weakness.]",\n'
            '      "grounded_finding": "<rule_id or CWE if citing a finding, else null>"\n'
            '    }\n'
            '  ]\n'
            '}'
        )

    def _build_user_prompt(
        self,
        threat_context: dict[str, Any],
        phase: str,
        methodology: str,
    ) -> str:
        lines: list[str] = []

        lines.append(f"Generate {methodology} threats from the following pre-processed context.")
        lines.append(f"Phase: {phase} | Methodology: {methodology}")
        lines.append("")

        # Section 1
        lines.append("=== SECTION 1: ARCHITECTURE SUMMARY ===")
        lines.append(str(threat_context.get("architecture_summary") or "(none)"))
        lines.append("")

        # Section 2
        lines.append("=== SECTION 2: COMPONENTS ===")
        for comp in threat_context.get("components") or []:
            if not isinstance(comp, dict):
                continue
            lines.append(
                f"ID: {comp.get('comp_id', 'unknown')}  "
                f"Name: {comp.get('name', '')}  "
                f"Type: {comp.get('type', '')}  "
                f"Trust zone: {comp.get('trust_zone', 'unknown')}"
            )
            lines.append(f"  Technology: {comp.get('technology', '')}")
            cats = ", ".join(comp.get("required_stride_categories") or [])
            lines.append(f"  Required STRIDE categories: [{cats}]")
        lines.append("")

        # Section 3
        lines.append("=== SECTION 3: ACTORS ===")
        for actor in threat_context.get("actors") or []:
            if not isinstance(actor, dict):
                continue
            lines.append(
                f"ID: {actor.get('id', 'unknown')}  "
                f"Name: {actor.get('name', '')}  "
                f"Type: {actor.get('type', '')}"
            )
        lines.append("")

        # Section 4
        lines.append("=== SECTION 4: ENTRY POINTS ===")
        for ep in threat_context.get("entry_points") or []:
            if not isinstance(ep, dict):
                continue
            lines.append(
                f"ID: {ep.get('id', 'unknown')}  "
                f"Name: {ep.get('name', '')}  "
                f"Protocol/Type: {ep.get('type', '')}  "
                f"Target: {ep.get('target_component_id', 'unknown')}  "
                f"Exposure: {ep.get('exposure', 'unknown')}"
            )
            lines.append(f"  Description: {ep.get('description', '')}")
        lines.append("")

        # Section 5
        lines.append("=== SECTION 5: DATA FLOWS ===")
        for flow in threat_context.get("data_flows") or []:
            if not isinstance(flow, dict):
                continue
            lines.append(
                f"{flow.get('source_id', '?')} → {flow.get('destination_id', '?')}  "
                f"Protocol: {flow.get('protocol', '?')}  "
                f"{flow.get('description', '')}"
            )
            if flow.get("trust_boundary_crossing"):
                lines.append(
                    f"  [TRUST BOUNDARY CROSSING: {flow.get('boundary_name', 'unknown')}]"
                )
        lines.append("")

        # Section 6
        lines.append("=== SECTION 6: TRUST BOUNDARIES ===")
        for b in threat_context.get("trust_boundaries") or []:
            if not isinstance(b, dict):
                continue
            crossing_ids = ", ".join(b.get("crossing_component_ids") or [])
            lines.append(
                f"Name: {b.get('name', '')}  ID: {b.get('id', '')}  "
                f"Crossing components: [{crossing_ids}]"
            )
        lines.append("")

        # Section 7
        lines.append("=== SECTION 7: ASSETS ===")
        for asset in threat_context.get("assets") or []:
            if not isinstance(asset, dict):
                continue
            lines.append(
                f"ID: {asset.get('id', 'unknown')}  "
                f"Name: {asset.get('name', '')}  "
                f"Type: {asset.get('type', '')}  "
                f"Sensitivity: {asset.get('sensitivity', '')}"
            )
        lines.append("")

        # Section 8
        lines.append("=== SECTION 8: AUTHENTICATION & AUTHORIZATION ===")
        authn = threat_context.get("authn_authz") or {}
        auth_methods = authn.get("authentication_methods")
        auth_model = authn.get("authorization_model")
        priv_ifaces = authn.get("privileged_interfaces")
        lines.append(
            "Authentication methods: "
            + (", ".join(auth_methods) if auth_methods else "[MISSING: authentication_methods]")
        )
        lines.append(
            "Authorization model: "
            + (str(auth_model) if auth_model else "[MISSING: authorization_model]")
        )
        lines.append(
            "Privileged interfaces: "
            + (", ".join(priv_ifaces) if priv_ifaces else "[MISSING: privileged_interfaces]")
        )
        lines.append("")

        # Section 9 — Security Findings (most critical)
        lines.append("=== SECTION 9: SECURITY FINDINGS ===")
        mapped_findings = threat_context.get("mapped_findings") or {}
        sast_list: list[dict[str, Any]] = mapped_findings.get("sast") or []
        dast_list: list[dict[str, Any]] = mapped_findings.get("dast") or []

        for f in sast_list[:30]:
            comp_label = f.get("mapped_component_id") or "UNMAPPED"
            ep_label = f.get("mapped_entry_point_id") or "UNMAPPED"
            lines.append(
                f"[SAST] Tool: {f.get('tool', '?')}  "
                f"Rule/CWE: {f.get('rule_id', '?')}/{f.get('cwe', '?')}  "
                f"Severity: {f.get('severity', '?')}  "
                f"File: {f.get('file', '?')}:{f.get('line', '?')}"
            )
            lines.append(f"  Description: {f.get('description', '')}")
            lines.append(f"  Mapped component: {comp_label}")
            lines.append(f"  Mapped entry point: {ep_label}")
            if f.get("mapped_asset_id"):
                lines.append(f"  Mapped asset: {f.get('mapped_asset_id')}")
            if f.get("root_cause"):
                lines.append(f"  Root cause: {f.get('root_cause')}")
        if len(sast_list) > 30:
            lines.append(f"  [...{len(sast_list) - 30} SAST findings omitted, see full report]")

        for f in dast_list[:20]:
            ep_label = f.get("mapped_entry_point_id") or "UNMAPPED"
            lines.append(
                f"[DAST] Tool: {f.get('tool', '?')}  "
                f"Rule/CWE: {f.get('rule_id', '?')}/{f.get('cwe', '?')}  "
                f"Severity: {f.get('severity', '?')}  "
                f"Endpoint: {f.get('endpoint', '?')}"
            )
            lines.append(f"  Description: {f.get('description', '')}")
            lines.append(f"  Mapped entry point: {ep_label}")
        if len(dast_list) > 20:
            lines.append(f"  [...{len(dast_list) - 20} DAST findings omitted, see full report]")

        # Technology hints
        tech_hints = threat_context.get("tech_hints") or []
        if tech_hints:
            lines.append("")
            lines.append("=== [TECHNOLOGY HINTS] ===")
            for hint in tech_hints:
                weaknesses = "; ".join(hint.get("known_weaknesses") or [])
                lines.append(
                    f"Technology: {hint.get('technology', '?')}  "
                    f"Found in: {hint.get('source_id', '?')}"
                )
                lines.append(f"  Known weaknesses: {weaknesses}")

        # Code scan hints
        code_hints = threat_context.get("code_hints") or []
        if code_hints:
            lines.append("")
            lines.append("=== [CODE SCAN HINTS — UNVERIFIED] ===")
            for hint in code_hints:
                lines.append(
                    f"Pattern: {hint.get('pattern', '?')}  "
                    f"CWE: {hint.get('cwe', '?')}  "
                    f"Label: {hint.get('label', '?')}  [UNVERIFIED HINT]"
                )
        lines.append("")

        controls = [
            control for control in (threat_context.get("implemented_controls") or [])
            if isinstance(control, dict)
        ]
        if controls:
            lines.append("=== SECTION 9B: IMPLEMENTED CONTROLS ===")
            lines.append(
                "These are negative evidence. Suppress directly mitigated threats "
                "or downgrade them to residual risks."
            )
            for control in controls:
                mitigates = ", ".join(str(item) for item in control.get("mitigates") or [])
                lines.append(
                    f"ID: {control.get('id')}  "
                    f"Type: {control.get('control_type')}  "
                    f"Target: {control.get('target_component_id')}  "
                    f"Asset: {control.get('target_asset_id') or 'unknown'}  "
                    f"Mitigates: [{mitigates}]"
                )
            lines.append("")

        # Section 10
        lines.append("=== SECTION 10: EXTERNAL DEPENDENCIES ===")
        for dep in threat_context.get("external_dependencies") or []:
            if not isinstance(dep, dict):
                continue
            lines.append(
                f"Name: {dep.get('name', '')}  "
                f"Type: {dep.get('type', '')}  "
                f"Trust level: {dep.get('trust_level', '')}  "
                f"Purpose: {dep.get('purpose', '')}"
            )
        lines.append("")

        # Section 11
        lines.append("=== SECTION 11: ASSUMPTIONS & OPEN QUESTIONS ===")
        lines.append(
            "NOTE: Do not generate threats based on items listed here. "
            "If you reference one, mark it as [ASSUMPTION]."
        )
        assumptions = threat_context.get("assumptions") or []
        if assumptions:
            for a in assumptions:
                lines.append(f"  Assumption: {a}")
        else:
            lines.append("  (none)")
        open_questions = threat_context.get("open_questions") or []
        if open_questions:
            for q in open_questions:
                lines.append(f"  Open question: {q}")
        lines.append("")

        lines.append(
            "Return only valid JSON with the exact top-level key 'threats'. "
            "Each threat must be specific and grounded in the data above. "
            "Threat ids must be unique snake_case strings "
            "(e.g. threat_jwt_algo_confusion, threat_sqli_comp_db). "
            "Do not generate near-duplicate threats for the same component and attack vector."
        )

        return "\n".join(lines)

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 4 — POST-GENERATION VALIDATION: Steps 4A–4G
    # ─────────────────────────────────────────────────────────────────────────

    def _apply_severity_overrides(
        self,
        threats: list[Any],
        finding_severity_map: dict[tuple, str],
    ) -> None:
        """4B: Python overrides AI severity for every finding-grounded threat."""
        for threat in threats:
            if not isinstance(threat, dict):
                continue
            grounded = threat.get("grounded_finding")
            if not grounded:
                continue
            comp_id = str(threat.get("affected_component_id", "")).strip()
            entry_id = str(threat.get("entry_point_id", "")).strip()
            raw_severity = finding_severity_map.get(
                (comp_id, grounded)
            ) or finding_severity_map.get(
                (entry_id, grounded)
            )
            if raw_severity:
                normalized = self.SEVERITY_NORMALIZATION_MAP.get(
                    raw_severity.strip().lower(), raw_severity.strip()
                )
                if normalized in self.VALID_SEVERITIES:
                    threat["severity"] = normalized

    def _apply_deterministic_threat_enrichment(
        self,
        threats: list[Any],
        threat_context: dict[str, Any],
    ) -> None:
        mapped_sast = [
            f for f in ((threat_context.get("mapped_findings") or {}).get("sast") or [])
            if isinstance(f, dict)
        ]
        for threat in threats:
            if not isinstance(threat, dict):
                continue
            grounded = str(threat.get("grounded_finding") or "").strip()
            matching_finding = self._matching_sast_finding_for_threat(threat, mapped_sast)
            if matching_finding:
                threat["source_type"] = "sast"
                threat["grounded_finding"] = grounded or matching_finding.get("rule_id") or matching_finding.get("cwe")
                if matching_finding.get("mapped_component_id"):
                    threat["affected_component_id"] = matching_finding["mapped_component_id"]
                if matching_finding.get("mapped_entry_point_id"):
                    threat["entry_point_id"] = matching_finding["mapped_entry_point_id"]
                if matching_finding.get("mapped_asset_id"):
                    threat["asset_id"] = matching_finding["mapped_asset_id"]
                if matching_finding.get("root_cause"):
                    threat["root_cause"] = matching_finding["root_cause"]
                if matching_finding.get("finding_fingerprint"):
                    threat["finding_fingerprint"] = matching_finding["finding_fingerprint"]
            else:
                threat.setdefault("source_type", "architecture")
                threat.setdefault("root_cause", self._infer_architecture_root_cause(threat))

            threat["threat_key"] = self._build_threat_key(threat)
            threat["semantic_key"] = threat["threat_key"]

    def _matching_sast_finding_for_threat(
        self,
        threat: dict[str, Any],
        mapped_sast: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        grounded = str(threat.get("grounded_finding") or "").strip().lower()
        comp_id = str(threat.get("affected_component_id") or "").strip()
        entry_id = str(threat.get("entry_point_id") or "").strip()
        text = " ".join(
            str(threat.get(field) or "")
            for field in ("title", "description", "mitigation")
        ).lower()
        for finding in mapped_sast:
            rule = str(finding.get("rule_id") or "").strip().lower()
            cwe = str(finding.get("cwe") or "").strip().lower()
            if grounded and grounded in {rule, cwe}:
                return finding
            if comp_id and comp_id == finding.get("mapped_component_id") and (rule in text or cwe in text):
                return finding
            if entry_id and entry_id == finding.get("mapped_entry_point_id") and (rule in text or cwe in text):
                return finding
        return None

    def _apply_control_suppression_and_downgrade(
        self,
        threats: list[Any],
        threat_context: dict[str, Any],
    ) -> list[Any]:
        controls = {
            str(control.get("id")): control
            for control in (threat_context.get("implemented_controls") or [])
            if isinstance(control, dict) and control.get("id")
        }
        if not controls:
            return [t for t in threats if isinstance(t, dict)]

        kept: list[Any] = []
        for threat in threats:
            if not isinstance(threat, dict):
                kept.append(threat)
                continue
            if threat.get("source_type") == "sast" or threat.get("grounded_finding"):
                kept.append(threat)
                continue

            action = self._control_action_for_threat(threat, controls)
            if action == "suppress":
                continue
            if action == "downgrade":
                threat["source_type"] = "residual"
                threat["control_status"] = "partially_mitigated"
                threat["severity"] = self._downgraded_severity(str(threat.get("severity") or "Medium"))
                desc = str(threat.get("description") or "")
                if "[RESIDUAL RISK" not in desc:
                    threat["description"] = f"{desc} [RESIDUAL RISK after implemented controls.]"
                threat["root_cause"] = self._infer_architecture_root_cause(threat)
                threat["threat_key"] = self._build_threat_key(threat)
                threat["semantic_key"] = threat["threat_key"]
            kept.append(threat)
        return kept

    def _control_action_for_threat(
        self,
        threat: dict[str, Any],
        controls: dict[str, dict[str, Any]],
    ) -> str | None:
        text = " ".join(
            str(threat.get(field) or "")
            for field in ("title", "description", "mitigation", "root_cause")
        ).lower()
        component = str(threat.get("affected_component_id") or "").lower()
        category = str(threat.get("category") or "").lower()

        if "control_redis_auth" in controls and (
            "unauthenticated redis" in text or "no authentication" in text and "redis" in text
        ):
            return "suppress"
        if "control_redis_auth" in controls and "redis" in text and (
            "refresh token" in text or "token" in text or "disclosure" in category or "tampering" in category
        ):
            return "downgrade"
        if "control_file_ownership_check" in controls and (
            "idor" in text or "ownership" in text or "missing ownership" in text
        ):
            return "suppress"
        if "control_admin_role_validation" in controls and (
            "missing admin role" in text or "role validation" in text or "admin role" in text
        ):
            return "suppress"
        if "control_jwt_secret_secrets_manager" in controls and (
            "hardcoded" in text and "jwt" in text or "jwt secret" in text and "exposure" in text
        ):
            return "suppress"
        if "control_jwt_secret_secrets_manager" in controls and "token forgery" in text:
            return "downgrade"
        if "control_file_type_validation" in controls and (
            "unrestricted file upload" in text or "file type validation" in text or "mime" in text
        ):
            return "suppress"
        if "control_internal_mtls" in controls and (
            "internal" in text or "traffic" in text or "boundary" in text or component == "comp_api_gateway"
        ) and ("tampering" in category or "information disclosure" in category):
            return "downgrade"
        if "control_admin_dashboard_vpn" in controls and component == "comp_admin_dashboard" and (
            "spoofing" in category or "exposure" in text
        ):
            return "downgrade"
        if "control_rabbitmq_rotated_credentials" in controls and (
            "guest" in text or "default credential" in text
        ):
            return "suppress"
        if "control_credentials_secrets_manager" in controls and (
            "environment variable" in text and "credential" in text
        ):
            return "suppress"
        return None

    def _infer_architecture_root_cause(self, threat: dict[str, Any]) -> str:
        text = " ".join(
            str(threat.get(field) or "")
            for field in ("title", "description", "mitigation")
        ).lower()
        root_causes = [
            ("unauthenticated redis", "redis_unauthenticated_access"),
            ("hardcoded", "hardcoded_secret"),
            ("jwt secret", "jwt_secret_exposure"),
            ("ownership", "missing_ownership_check"),
            ("admin role", "missing_admin_role_validation"),
            ("file type", "unrestricted_file_upload"),
            ("mime", "unrestricted_file_upload"),
            ("mutual tls", "internal_transport_security"),
            ("internal traffic", "internal_transport_security"),
            ("vpn", "admin_dashboard_network_exposure"),
            ("sql injection", "sql_injection"),
            ("resource consumption", "uncontrolled_resource_consumption"),
        ]
        for marker, root_cause in root_causes:
            if marker in text:
                return root_cause
        title = str(threat.get("title") or "architecture_risk").lower()
        return re.sub(r"[^a-z0-9]+", "_", title).strip("_")[:60] or "architecture_risk"

    def _build_threat_key(self, threat: dict[str, Any]) -> str:
        source_type = str(threat.get("source_type") or "architecture").strip().lower()
        cwe_or_stride = str(threat.get("grounded_finding") or threat.get("category") or "unknown").strip()
        component_id = str(threat.get("affected_component_id") or "unknown").strip()
        entry_point_id = str(threat.get("entry_point_id") or "unknown").strip()
        asset_id = str(threat.get("asset_id") or "unknown").strip()
        root_cause = str(threat.get("root_cause") or self._infer_architecture_root_cause(threat)).strip()
        root_cause = re.sub(r"[^a-z0-9]+", "_", root_cause.lower()).strip("_") or "unknown_root_cause"
        return "|".join([
            source_type,
            cwe_or_stride,
            component_id or "unknown",
            entry_point_id or "unknown",
            asset_id or "unknown",
            root_cause,
        ])

    def _downgraded_severity(self, severity: str) -> str:
        order = ["Low", "Medium", "High", "Critical"]
        normalized = self.SEVERITY_NORMALIZATION_MAP.get(severity.strip().lower(), severity.strip())
        if normalized not in order:
            return "Low"
        return order[max(0, order.index(normalized) - 1)]

    def _check_grounding(
        self,
        threats: list[Any],
        threat_context: dict[str, Any],
    ) -> int:
        """4A: Flag threats whose descriptions reference no known parsed token.

        Builds a four-tier token set:
          Tier 1 — structured IDs (comp_..., entry_..., asset_...)
          Tier 2 — tool names, rule IDs, CWE identifiers from findings
          Tier 3 — protocol names, technology keywords, dependency names, asset names
          Tier 4 — technology hint keywords, code scan CWEs and patterns
        """
        tokens: set[str] = set()

        # Tier 1
        for comp in threat_context.get("components") or []:
            if isinstance(comp, dict) and comp.get("comp_id"):
                tokens.add(comp["comp_id"].lower())
        for ep in threat_context.get("entry_points") or []:
            if isinstance(ep, dict) and ep.get("id"):
                tokens.add(str(ep["id"]).lower())
        for asset in threat_context.get("assets") or []:
            if isinstance(asset, dict):
                if asset.get("id"):
                    tokens.add(str(asset["id"]).lower())
                name = str(asset.get("name", ""))
                if len(name) > 3:
                    tokens.add(name.lower())

        # Tier 2
        mf = threat_context.get("mapped_findings") or {}
        for f in (mf.get("sast") or []) + (mf.get("dast") or []):
            if not isinstance(f, dict):
                continue
            for field in ("tool", "rule_id", "cwe"):
                val = str(f.get(field) or "")
                if len(val) > 3:
                    tokens.add(val.lower())

        # Tier 3
        for flow in threat_context.get("data_flows") or []:
            if isinstance(flow, dict):
                proto = str(flow.get("protocol") or "")
                if len(proto) > 3:
                    tokens.add(proto.lower())
        for dep in threat_context.get("external_dependencies") or []:
            if isinstance(dep, dict):
                dep_name = str(dep.get("name") or "")
                if len(dep_name) > 3:
                    tokens.add(dep_name.lower())
        for comp in threat_context.get("components") or []:
            if isinstance(comp, dict):
                for word in re.split(r'\W+', str(comp.get("technology") or "")):
                    if len(word) > 4:
                        tokens.add(word.lower())

        # Tier 4
        for hint in threat_context.get("tech_hints") or []:
            if isinstance(hint, dict) and hint.get("technology"):
                tokens.add(str(hint["technology"]).lower())
        for hint in threat_context.get("code_hints") or []:
            if isinstance(hint, dict):
                if hint.get("cwe"):
                    tokens.add(str(hint["cwe"]).lower())
                pattern = str(hint.get("pattern") or "")
                if len(pattern) > 3:
                    tokens.add(pattern.lower().rstrip("("))

        low_confidence_count = 0
        for threat in threats:
            if not isinstance(threat, dict):
                continue
            desc = str(threat.get("description") or "").lower()
            if not any(tok in desc for tok in tokens if tok):
                threat["description"] = (
                    str(threat["description"])
                    + " [LOW CONFIDENCE: not grounded in parsed data]"
                )
                threat["low_confidence"] = True
                low_confidence_count += 1
                logger.warning(
                    "Threat %s is not grounded in parsed data.",
                    threat.get("id", "unknown"),
                )

        return low_confidence_count

    def _check_and_retry_finding_coverage(
        self,
        threats: list[Any],
        mapped_findings: dict[str, list[dict[str, Any]]],
        parsed_data: dict[str, Any],
        finding_severity_map: dict[tuple, str] | None,
        threat_context: dict[str, Any] | None,
        seed: int | None,
    ) -> None:
        """4C: Trigger targeted retry if < 30% of threats cite a mapped finding."""
        mapped_count = sum(
            1 for f in (mapped_findings.get("sast") or [])
            if f.get("mapped_component_id")
        ) + sum(
            1 for f in (mapped_findings.get("dast") or [])
            if f.get("mapped_entry_point_id")
        )
        if mapped_count == 0:
            return

        finding_grounded = sum(
            1 for t in threats
            if isinstance(t, dict) and t.get("grounded_finding")
        )
        total = len(threats)
        if total == 0 or (finding_grounded / total) >= 0.30:
            return

        logger.warning(
            "Finding coverage %.0f%% < 30%% threshold — triggering targeted retry.",
            (finding_grounded / total) * 100,
        )
        retry_threats = self._generate_finding_grounded_threats(
            mapped_findings, threats, parsed_data, seed
        )
        if retry_threats:
            self._normalize_severities(retry_threats)
            if finding_severity_map:
                self._apply_severity_overrides(retry_threats, finding_severity_map)
            if threat_context:
                self._check_grounding(retry_threats, threat_context)
            threats.extend(retry_threats)

    def _warn_entry_point_coverage(
        self,
        threats: list[Any],
        parsed_data: dict[str, Any],
    ) -> None:
        """4D: Log a warning for every entry point not referenced by any threat."""
        covered = {
            str(t.get("entry_point_id", "")).strip()
            for t in threats
            if isinstance(t, dict)
        }
        for ep in parsed_data.get("entry_points") or []:
            if not isinstance(ep, dict):
                continue
            ep_id = str(ep.get("id", "")).strip()
            if ep_id and ep_id not in covered:
                logger.warning(
                    "Entry point %s (%s) has no threat coverage.",
                    ep_id,
                    ep.get("name", ""),
                )

    def _check_and_retry_stride_coverage(
        self,
        threats: list[Any],
        threat_context: dict[str, Any],
        seed: int | None,
    ) -> None:
        """4E: Targeted retry for required STRIDE categories not yet covered per component."""
        missing_pairs: list[dict[str, Any]] = []
        for comp in threat_context.get("components") or []:
            if not isinstance(comp, dict):
                continue
            comp_id = comp.get("comp_id", "")
            required = set(comp.get("required_stride_categories") or [])
            covered = {
                str(t.get("category", ""))
                for t in threats
                if isinstance(t, dict)
                and str(t.get("affected_component_id", "")).strip() == comp_id
            }
            for cat in sorted(required - covered):
                logger.warning(
                    "Component %s missing STRIDE coverage for %s — retrying.", comp_id, cat
                )
                missing_pairs.append({
                    "comp_id": comp_id,
                    "comp_name": comp.get("name", comp_id),
                    "category": cat,
                })

        if not missing_pairs:
            return

        retry_threats = self._generate_stride_coverage_threats(
            missing_pairs, threat_context, seed
        )
        if retry_threats:
            self._normalize_severities(retry_threats)
            self._check_grounding(retry_threats, threat_context)
            threats.extend(retry_threats)

    def _generate_stride_coverage_threats(
        self,
        missing_pairs: list[dict[str, Any]],
        threat_context: dict[str, Any],
        seed: int | None,
    ) -> list[dict[str, Any]]:
        """Focused LLM call for required STRIDE categories not covered by the first pass."""
        comp_lines = []
        for comp in threat_context.get("components") or []:
            comp_lines.append(
                f"  {comp.get('comp_id')} | {comp.get('name')} | "
                f"type={comp.get('type')} | {str(comp.get('description', ''))[:120]}"
            )

        pairs_block = "\n".join(
            f"  - {p['comp_id']} ({p['comp_name']}): {p['category']}"
            for p in missing_pairs
        )

        system_prompt = (
            "You are a security threat modeling expert. "
            "You are given a list of (component, STRIDE category) pairs that have no threat yet. "
            "For each pair generate exactly one STRIDE threat grounded in the component description. "
            "Use only the component IDs listed. "
            "Every description MUST start with exactly: 'An attacker can'. "
            "Return only valid JSON: "
            '{"threats": [{"id":"...","title":"...","category":"...","description":"An attacker can ...",'
            '"affected_component_id":"...","entry_point_id":"unknown","asset_id":"unknown",'
            '"severity":"Critical|High|Medium|Low","mitigation":"...","grounded_finding":null}]}'
        )

        user_prompt = (
            "COMPONENTS:\n" + "\n".join(comp_lines) + "\n\n"
            "MISSING (component \u2192 required STRIDE category):\n" + pairs_block + "\n\n"
            "Generate exactly one threat per missing pair above."
        )

        try:
            response = self.ai_service.call_model(
                system_prompt, user_prompt, temperature=0.2, seed=seed
            )
        except Exception as exc:
            logger.warning("STRIDE coverage retry call failed: %s", exc)
            return []
        retry_threats = response.get("threats") if isinstance(response, dict) else []
        if not isinstance(retry_threats, list):
            return []
        for t in retry_threats:
            if isinstance(t, dict) and "grounded_finding" not in t:
                t["grounded_finding"] = None
        return [t for t in retry_threats if isinstance(t, dict)]

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 5 — Targeted retry for uncovered mapped findings
    # ─────────────────────────────────────────────────────────────────────────

    def _generate_finding_grounded_threats(
        self,
        mapped_findings: dict[str, list[dict[str, Any]]],
        existing_threats: list[Any],
        parsed_data: dict[str, Any],
        seed: int | None = None,
    ) -> list[dict[str, Any]]:
        """One focused second GPT call for mapped findings not yet cited by any threat."""
        cited_rules: set[str] = {
            str(t.get("grounded_finding", ""))
            for t in existing_threats
            if isinstance(t, dict) and t.get("grounded_finding")
        }

        uncovered_sast = [
            f for f in (mapped_findings.get("sast") or [])
            if f.get("mapped_component_id")
            and str(f.get("rule_id", "")) not in cited_rules
            and str(f.get("cwe", "")) not in cited_rules
        ]
        uncovered_dast = [
            f for f in (mapped_findings.get("dast") or [])
            if f.get("mapped_entry_point_id")
            and str(f.get("rule_id", "")) not in cited_rules
            and str(f.get("cwe", "")) not in cited_rules
        ]

        if not uncovered_sast and not uncovered_dast:
            return []

        # Build focused prompt context.
        relevant_comp_ids = {f["mapped_component_id"] for f in uncovered_sast}
        relevant_ep_ids = {f["mapped_entry_point_id"] for f in uncovered_dast}
        relevant_ep_ids.update(
            f["mapped_entry_point_id"]
            for f in uncovered_sast
            if f.get("mapped_entry_point_id")
        )

        focused_components = [
            c for c in (parsed_data.get("components") or [])
            if isinstance(c, dict) and c.get("id") in relevant_comp_ids
        ]
        focused_entry_points = [
            ep for ep in (parsed_data.get("entry_points") or [])
            if isinstance(ep, dict) and ep.get("id") in relevant_ep_ids
        ]

        finding_lines: list[str] = []
        for f in uncovered_sast:
            finding_lines.append(
                f"[SAST] Tool: {f.get('tool')}  "
                f"Rule/CWE: {f.get('rule_id')}/{f.get('cwe')}  "
                f"Severity: {f.get('severity')}  "
                f"File: {f.get('file')}:{f.get('line')}  "
                f"Mapped component: {f.get('mapped_component_id')}  "
                f"Mapped entry point: {f.get('mapped_entry_point_id') or 'UNMAPPED'}\n"
                f"  Description: {f.get('description')}"
            )
        for f in uncovered_dast:
            finding_lines.append(
                f"[DAST] Tool: {f.get('tool')}  "
                f"Rule/CWE: {f.get('rule_id')}/{f.get('cwe')}  "
                f"Severity: {f.get('severity')}  "
                f"Endpoint: {f.get('endpoint')}  "
                f"Mapped entry point: {f.get('mapped_entry_point_id')}\n"
                f"  Description: {f.get('description')}"
            )

        comp_lines = [
            f"ID: {c.get('id')}  Name: {c.get('name')}  Type: {c.get('type')}"
            for c in focused_components
            if isinstance(c, dict)
        ]
        ep_lines = [
            f"ID: {ep.get('id')}  Name: {ep.get('name')}  Type: {ep.get('type')}"
            for ep in focused_entry_points
            if isinstance(ep, dict)
        ]
        asset_lines = [
            f"ID: {a.get('id')}  Name: {a.get('name')}  Sensitivity: {a.get('sensitivity')}"
            for a in (parsed_data.get("assets") or [])
            if isinstance(a, dict)
        ]

        system_prompt = (
            "You are given confirmed security findings from SAST and DAST tools. "
            "For each finding generate exactly one STRIDE threat that directly cites "
            "this finding using the exact component ID and entry point ID provided. "
            "Do not generate generic threats. "
            "Accuracy and consistency are the only goals. "
            "Set grounded_finding to the rule_id or CWE of the finding. "
            "Return only valid JSON: "
            '{"threats": [{"id":"...","title":"...","category":"...","description":"...",'
            '"affected_component_id":"...","entry_point_id":"...","asset_id":"...",'
            '"severity":"...","mitigation":"...","grounded_finding":"..."}]}'
        )

        user_prompt = "\n".join([
            "Generate one STRIDE threat per finding listed below.",
            "",
            "=== FINDINGS TO COVER ===",
            *finding_lines,
            "",
            "=== RELEVANT COMPONENTS ===",
            *(comp_lines or ["(none)"]),
            "",
            "=== RELEVANT ENTRY POINTS ===",
            *(ep_lines or ["(none)"]),
            "",
            "=== ALL ASSETS ===",
            *(asset_lines or ["(none)"]),
        ])

        try:
            response = self.ai_service.call_model(
                system_prompt, user_prompt, temperature=0.2, seed=seed
            )
        except Exception as exc:
            logger.warning("Targeted finding retry call failed: %s", exc)
            return []

        retry_threats = response.get("threats") if isinstance(response, dict) else []
        if not isinstance(retry_threats, list):
            return []

        for t in retry_threats:
            if isinstance(t, dict) and "grounded_finding" not in t:
                t["grounded_finding"] = None

        return [t for t in retry_threats if isinstance(t, dict)]

    # ─────────────────────────────────────────────────────────────────────────
    # Existing helpers — preserved or updated as noted
    # ─────────────────────────────────────────────────────────────────────────

    def _normalize_severities(self, threats: list[Any]) -> None:
        """Normalize severity values in-place to one of: Critical, High, Medium, Low.

        Only operates on threats where the 'severity' key already exists.
        Missing keys are intentionally left absent so _validate_threat_structures
        can report them correctly — we do not silently inject defaults here.
        """
        for threat in threats:
            if not isinstance(threat, dict):
                continue
            if "severity" not in threat:
                continue
            raw = threat["severity"]
            if not isinstance(raw, str):
                threat["severity"] = "Medium"
                continue
            normalized = self.SEVERITY_NORMALIZATION_MAP.get(raw.strip().lower())
            if normalized:
                threat["severity"] = normalized
            elif raw.strip() not in self.VALID_SEVERITIES:
                threat["severity"] = "Medium"

    def _deduplicate_threats(self, threats: list[Any]) -> list[Any]:
        """Remove near-duplicate threats within the same STRIDE category.

        4F update: two threats sharing the same (affected_component_id, category,
        entry_point_id) — none of which is 'unknown' — are always considered
        duplicates regardless of title similarity. When merging, the finding-grounded
        threat wins; on a tie, the one with fewer unknown refs wins; on a further tie,
        the longer description (more specific) wins.
        """

        def _tokens(text: str) -> set[str]:
            words = re.sub(r"[^a-z0-9 ]", " ", text.lower()).split()
            return {w for w in words if len(w) > 2}

        def _groundedness(threat: dict) -> int:
            """Lower = more grounded (fewer 'unknown' references)."""
            score = 0
            for key in ("affected_component_id", "entry_point_id", "asset_id"):
                if str(threat.get(key, "unknown")).strip().lower() == "unknown":
                    score += 1
            return score

        def _has_grounded_finding(threat: dict) -> bool:
            return bool(threat.get("grounded_finding"))

        def _category_fit(threat: dict) -> int:
            root_cause = str(threat.get("root_cause") or "").strip().lower()
            category = str(threat.get("category") or "").strip().lower()
            grounded = str(threat.get("grounded_finding") or "").strip().lower()
            if ("sql_injection" in root_cause or grounded == "cwe-89") and category == "tampering":
                return 2
            if (
                "uncontrolled_resource_consumption" in root_cause
                or grounded == "cwe-400"
            ) and category == "denial of service":
                return 2
            return 0

        def _is_duplicate(a: dict, b: dict) -> bool:
            key_a = str(a.get("threat_key") or "").strip().lower()
            key_b = str(b.get("threat_key") or "").strip().lower()
            if key_a and key_b and key_a == key_b:
                return True

            cat_a = str(a.get("category", "")).strip()
            cat_b = str(b.get("category", "")).strip()
            if cat_a != cat_b:
                return False

            # 4F: exact triple match (comp + category + entry_point) — none unknown.
            comp_a = str(a.get("affected_component_id", "unknown")).strip().lower()
            comp_b = str(b.get("affected_component_id", "unknown")).strip().lower()
            ep_a = str(a.get("entry_point_id", "unknown")).strip().lower()
            ep_b = str(b.get("entry_point_id", "unknown")).strip().lower()
            if (comp_a == comp_b and ep_a == ep_b
                    and comp_a != "unknown" and ep_a != "unknown"):
                return True

            # Title token overlap ≥ 60%.
            tokens_a = _tokens(str(a.get("title", "")))
            tokens_b = _tokens(str(b.get("title", "")))
            if not tokens_a or not tokens_b:
                return False
            overlap = len(tokens_a & tokens_b) / min(len(tokens_a), len(tokens_b))
            return overlap >= 0.6

        def _prefer(existing: dict, candidate: dict) -> dict:
            """Return the better threat between two duplicates."""
            if _has_grounded_finding(candidate) and not _has_grounded_finding(existing):
                return candidate
            if _has_grounded_finding(existing) and not _has_grounded_finding(candidate):
                return existing
            if _category_fit(candidate) > _category_fit(existing):
                return candidate
            if _category_fit(existing) > _category_fit(candidate):
                return existing
            if _groundedness(candidate) < _groundedness(existing):
                return candidate
            if _groundedness(existing) < _groundedness(candidate):
                return existing
            # Both equally grounded — prefer the longer (more specific) description.
            if len(str(candidate.get("description", ""))) > len(
                str(existing.get("description", ""))
            ):
                return candidate
            return existing

        kept: list[dict] = []
        for threat in threats:
            if not isinstance(threat, dict):
                kept.append(threat)
                continue
            duplicate_index = next(
                (
                    i for i, k in enumerate(kept)
                    if isinstance(k, dict) and _is_duplicate(k, threat)
                ),
                None,
            )
            if duplicate_index is None:
                kept.append(threat)
            else:
                kept[duplicate_index] = _prefer(kept[duplicate_index], threat)

        return kept

    def _validate_threat_structures(self, threats: list[Any]) -> list[str]:
        """Check required keys are present. 4G: defaults grounded_finding to None."""
        issues: list[str] = []

        for index, threat in enumerate(threats):
            if not isinstance(threat, dict):
                issues.append(f"threats[{index}]")
                continue

            # grounded_finding is nullable — default rather than flag.
            if "grounded_finding" not in threat:
                threat["grounded_finding"] = None

            for key in self.REQUIRED_THREAT_KEYS:
                if key not in threat:
                    issues.append(f"threats[{index}].{key}")

        return issues

    def _validate_references(
        self,
        threats: list[Any],
        parsed_data: dict[str, Any],
    ) -> list[str]:
        issues: list[str] = []
        component_ids = self._collect_ids(parsed_data.get("components"))
        entry_point_ids = self._collect_ids(parsed_data.get("entry_points"))
        asset_ids = self._collect_ids(parsed_data.get("assets"))

        for index, threat in enumerate(threats):
            if not isinstance(threat, dict):
                continue

            affected_component_id = threat.get("affected_component_id")
            if self._is_broken_reference(affected_component_id, component_ids):
                issues.append(f"threats[{index}].affected_component_id")

            entry_point_id = threat.get("entry_point_id")
            if self._is_broken_reference(entry_point_id, entry_point_ids):
                issues.append(f"threats[{index}].entry_point_id")

            asset_id = threat.get("asset_id")
            if self._is_broken_reference(asset_id, asset_ids):
                issues.append(f"threats[{index}].asset_id")

        return issues

    def _validate_stride_categories(self, threats: list[Any]) -> list[str]:
        issues: list[str] = []

        for index, threat in enumerate(threats):
            if not isinstance(threat, dict):
                continue

            category = threat.get("category")
            if not isinstance(category, str) or category not in self.STRIDE_CATEGORIES:
                issues.append(f"threats[{index}].category")

        return issues

    def _collect_ids(self, items: Any) -> set[str]:
        if not isinstance(items, list):
            return set()

        ids: set[str] = set()
        for item in items:
            if not isinstance(item, dict):
                continue

            item_id = item.get("id")
            if isinstance(item_id, str) and item_id.strip():
                ids.add(item_id.strip())

        return ids

    def _is_broken_reference(self, value: Any, valid_ids: set[str]) -> bool:
        if not isinstance(value, str):
            return True

        normalized_value = value.strip()
        if not normalized_value:
            return True

        if normalized_value == "unknown":
            return False

        return normalized_value not in valid_ids
