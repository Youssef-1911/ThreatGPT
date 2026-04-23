import hashlib
import json
import logging
import re
from typing import Any

from .ai_service import AIService

logger = logging.getLogger(__name__)


class ParsingEngine:
    # ---------------------------------------------------------------------------
    # Controlled vocabularies — the AI must use ONLY these values.
    # Post-processing normalizes any deviation deterministically.
    # ---------------------------------------------------------------------------
    COMPONENT_TYPES = {
        "service", "database", "queue", "cache", "gateway", "frontend",
        "backend", "external", "storage", "worker", "auth", "proxy",
    }
    ACTOR_TYPES = {
        "user", "admin", "external_system", "internal_service", "cicd",
        "attacker", "device",
    }
    ASSET_TYPES = {
        "data", "secret", "credential", "config", "token", "file",
        "database_record", "api_key", "certificate",
    }
    ASSET_SENSITIVITIES = {"Critical", "High", "Medium", "Low"}
    ENTRY_POINT_TYPES = {
        "api", "web_ui", "cli", "webhook", "queue", "database",
        "file_system", "grpc", "sdk",
    }
    ENTRY_POINT_EXPOSURES = {
        "public", "public_authenticated", "public_unauthenticated",
        "internal", "partner", "admin",
    }
    TRUST_ZONES = {"public", "internal", "trusted", "dmz", "restricted", "external"}
    EXTERNAL_TRUST_LEVELS = {"trusted", "untrusted", "conditional"}

    # Fuzzy alias maps for post-processing — maps common AI-invented values to canonical ones
    _COMPONENT_TYPE_ALIASES = {
        "api": "service", "api_service": "service", "microservice": "service",
        "web_service": "service", "rest": "service", "grpc_service": "service",
        "db": "database", "datastore": "database", "rds": "database",
        "sql": "database", "nosql": "database", "postgres": "database",
        "mysql": "database", "mongo": "database",
        "message_queue": "queue", "broker": "queue", "kafka": "queue",
        "rabbitmq": "queue", "sqs": "queue", "pubsub": "queue",
        "redis": "cache", "memcached": "cache",
        "load_balancer": "gateway", "api_gateway": "gateway", "ingress": "gateway",
        "nginx": "proxy", "reverse_proxy": "proxy",
        "ui": "frontend", "spa": "frontend", "web_app": "frontend",
        "webapp": "frontend", "web": "frontend",
        "server": "backend", "application": "backend", "app": "backend",
        "third_party": "external", "saas": "external", "vendor": "external",
        "blob": "storage", "s3": "storage", "filesystem": "storage",
        "lambda": "worker", "function": "worker", "job": "worker",
        "identity": "auth", "iam": "auth", "oauth": "auth", "sso": "auth",
    }
    _ACTOR_TYPE_ALIASES = {
        "end_user": "user", "customer": "user", "visitor": "user", "client": "user",
        "operator": "admin", "superuser": "admin", "root": "admin",
        "third_party": "external_system", "partner": "external_system",
        "service": "internal_service", "daemon": "internal_service",
        "pipeline": "cicd", "ci": "cicd", "cd": "cicd", "github_actions": "cicd",
        "threat_actor": "attacker", "hacker": "attacker", "malicious": "attacker",
        "iot": "device", "sensor": "device", "mobile": "device",
    }
    _TRUST_ZONE_ALIASES = {
        "untrusted": "public", "internet": "public", "outside": "public",
        "private": "internal", "intranet": "internal", "backend": "internal",
        "inside": "internal",
        "secure": "trusted", "trusted_zone": "trusted",
        "perimeter": "dmz", "semi_trusted": "dmz",
        "highly_sensitive": "restricted", "pci": "restricted", "regulated": "restricted",
        "protected": "restricted",
        "third_party": "external", "vendor": "external",
    }
    _ENTRY_POINT_TYPE_ALIASES = {
        "rest_api": "api", "http": "api", "https": "api", "graphql": "api",
        "rest": "api", "soap": "api", "rpc": "api",
        "ui": "web_ui", "browser": "web_ui", "portal": "web_ui", "dashboard": "web_ui",
        "command_line": "cli", "terminal": "cli", "shell": "cli",
        "event": "queue", "topic": "queue", "stream": "queue",
        "s3": "file_system", "blob": "file_system", "nfs": "file_system",
    }

    # Deterministic technology-name → component type overrides.
    # Applied after GPT type normalization — these wins are unconditional.
    # Full-word boundary matching prevents "credentials" from matching "redis".
    # Longest-keyword match wins when multiple keywords match a single component.
    NAME_TYPE_LOCKS: dict[str, str] = {
        "nginx":      "gateway",
        "apache":     "gateway",
        "kong":       "gateway",
        "traefik":    "gateway",
        "flask":      "backend",
        "django":     "backend",
        "fastapi":    "backend",
        "express":    "backend",
        "spring":     "backend",
        "rails":      "backend",
        "postgresql": "database",
        "postgres":   "database",
        "mysql":      "database",
        "mongodb":    "database",
        "sqlite":     "database",
        "redis":      "cache",
        "memcached":  "cache",
        "rabbitmq":   "queue",
        "kafka":      "queue",
        "celery":     "worker",
        "keycloak":   "auth",
        "s3":         "storage",
        "minio":      "storage",
        # Service-role keywords — lower priority than technology names above.
        # Longest-match logic ensures tech keywords always win (e.g. "redis" len=5 > "auth" len=4).
        "auth":         "backend",
        "account":      "backend",
        "transfer":     "backend",
        "notification": "backend",
        "admin":        "backend",
    }

    NESTED_REQUIRED_KEYS = {
        "actors": ["id", "name", "type", "description"],
        "components": ["id", "name", "type", "description", "trust_zone"],
        "data_flows": [
            "id",
            "source_component_id",
            "destination_component_id",
            "protocol",
            "description",
        ],
        "trust_boundaries": ["id", "name", "description", "crossing_component_ids"],
        "assets": ["id", "name", "type", "location", "sensitivity"],
        "entry_points": [
            "id",
            "name",
            "type",
            "exposure",
            "description",
            "target_component_id",
        ],
    }

    REQUIRED_KEYS = [
        "architecture_summary",
        "actors",
        "components",
        "data_flows",
        "trust_boundaries",
        "assets",
        "entry_points",
        "authn_authz",
        "external_dependencies",
        "security_findings",
        "assumptions",
        "open_questions",
        "source_map",
    ]

    REQUIRED_TYPES = {
        "architecture_summary": str,
        "actors": list,
        "components": list,
        "data_flows": list,
        "trust_boundaries": list,
        "assets": list,
        "entry_points": list,
        "external_dependencies": list,
        "assumptions": list,
        "open_questions": list,
        "source_map": list,
    }

    EXPECTED_SCHEMA = {
        "architecture_summary": "string",
        "actors": [
            {
                "id": "string",
                "name": "string",
                "type": "string",
                "description": "string",
            }
        ],
        "components": [
            {
                "id": "string",
                "name": "string",
                "type": "string",
                "description": "string",
                "trust_zone": "string",
            }
        ],
        "data_flows": [
            {
                "id": "string",
                "source_component_id": "string",
                "destination_component_id": "string",
                "protocol": "string",
                "description": "string",
            }
        ],
        "trust_boundaries": [
            {
                "id": "string",
                "name": "string",
                "description": "string",
                "crossing_component_ids": ["string"],
            }
        ],
        "assets": [
            {
                "id": "string",
                "name": "string",
                "type": "string",
                "location": "string",
                "sensitivity": "string",
            }
        ],
        "entry_points": [
            {
                "id": "string",
                "name": "string",
                "type": "string",
                "exposure": "string",
                "description": "string",
                "target_component_id": "string",
            }
        ],
        "authn_authz": {
            "authentication_methods": ["string"],
            "authorization_model": "string",
            "privileged_interfaces": ["string"],
        },
        "external_dependencies": [
            {
                "name": "string",
                "type": "string",
                "purpose": "string",
                "trust_level": "string",
            }
        ],
        "security_findings": {
            "sast": ["string"],
            "dast": ["string"],
            "sca": ["string"],
            "infrastructure": ["string"],
            "manual_review": ["string"],
        },
        "assumptions": ["string"],
        "open_questions": ["string"],
        "source_map": [
            {
                "section": "string",
                "evidence": ["string"],
            }
        ],
    }

    def __init__(self, ai_service: AIService | None = None) -> None:
        self.ai_service = ai_service or AIService()

    def parse_evidence(
        self,
        raw_text: str,
        phase: str,
        security_findings: dict[str, Any] | None = None,
        evidence_by_category: dict[str, Any] | None = None,
        source_map: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        evidence_package = self._build_evidence_package(
            phase=phase,
            raw_text=raw_text,
            security_findings=security_findings,
            evidence_by_category=evidence_by_category,
            source_map=source_map,
        )

        # TODO: Add deterministic evidence enrichment and de-duplication here.
        system_prompt = self._build_system_prompt()
        user_prompt = self._build_user_prompt(evidence_package)
        parse_seed = int(
            hashlib.md5(
                evidence_package.get("raw_text", "").encode()
            ).hexdigest(),
            16,
        ) % (2**31)
        parsed_data = self.ai_service.call_model(
            system_prompt, user_prompt, temperature=0.1, seed=parse_seed
        )
        parsed_data = self._preserve_structured_security_findings(
            parsed_data, evidence_package["security_findings"]
        )

        # TODO: Add deterministic post-processing and field merging here.
        return self.validate_parsed_output(parsed_data, phase)

    def compute_evidence_hash(self, evidence_package: dict[str, Any]) -> str:
        """Stable MD5 hash of the content-bearing parts of an evidence package.

        Used by the orchestrator for parse caching: if the hash matches a prior
        version's stored hash, the previous parsed_data is reused and the GPT
        call is skipped entirely.  raw_text + security_findings + source_map are
        included because any of them can change what the parser would output.
        """
        stable = {
            "raw_text": evidence_package.get("raw_text", ""),
            "security_findings": evidence_package.get("security_findings", {}),
            "source_map": evidence_package.get("source_map", []),
        }
        return hashlib.md5(
            json.dumps(stable, sort_keys=True).encode()
        ).hexdigest()

    def parse_evidence_package(
        self,
        evidence_package: dict[str, Any],
        existing_components: list[dict[str, Any]] | None = None,
        existing_entry_points: list[dict[str, Any]] | None = None,
        existing_assets: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        phase = str(evidence_package.get("phase", "")).strip()
        normalized_package = self._build_evidence_package(
            phase=phase,
            raw_text=str(evidence_package.get("raw_text", "")),
            security_findings=evidence_package.get("security_findings"),
            evidence_by_category=evidence_package.get("evidence_by_category"),
            source_map=evidence_package.get("source_map"),
        )

        # Build normalized-name → stable-id maps from the previous version's entities.
        existing_component_ids: dict[str, str] | None = None
        if existing_components:
            existing_component_ids = {}
            for comp in existing_components:
                if isinstance(comp, dict):
                    name = comp.get("name", "")
                    comp_id = comp.get("id", "")
                    if name and comp_id:
                        norm = self._normalize_component_name(name)
                        existing_component_ids[norm] = comp_id

        existing_entry_point_ids: dict[str, str] | None = None
        if existing_entry_points:
            existing_entry_point_ids = {}
            for ep in existing_entry_points:
                if isinstance(ep, dict):
                    name = ep.get("name", "")
                    ep_id = ep.get("id", "")
                    if name and ep_id:
                        norm = self._normalize_entity_name(name)
                        existing_entry_point_ids[norm] = ep_id

        existing_asset_ids: dict[str, str] | None = None
        if existing_assets:
            existing_asset_ids = {}
            for asset in existing_assets:
                if isinstance(asset, dict):
                    name = asset.get("name", "")
                    asset_id = asset.get("id", "")
                    if name and asset_id:
                        norm = self._normalize_entity_name(name)
                        existing_asset_ids[norm] = asset_id

        system_prompt = self._build_system_prompt()
        user_prompt = self._build_user_prompt(
            normalized_package,
            existing_component_ids,
            existing_entry_point_ids,
            existing_asset_ids,
        )

        # Stable seed: hashlib.md5 is process-invariant (unlike Python hash()).
        # Temperature 0.1 < generation 0.2 — parsing needs structured consistency
        # more than creative narrative.
        raw_text = normalized_package.get("raw_text", "")
        parse_seed = int(
            hashlib.md5(raw_text.encode()).hexdigest(), 16
        ) % (2**31)

        parsed_data = self.ai_service.call_model(
            system_prompt, user_prompt, temperature=0.1, seed=parse_seed
        )
        parsed_data = self._preserve_structured_security_findings(
            parsed_data, normalized_package["security_findings"]
        )

        # Post-parse stability fixes applied before schema validation.
        if existing_component_ids:
            parsed_data = self._reconcile_component_ids(parsed_data, existing_component_ids)
        if existing_entry_point_ids:
            parsed_data = self._reconcile_entry_point_ids(parsed_data, existing_entry_point_ids)
        if existing_asset_ids:
            parsed_data = self._reconcile_asset_ids(parsed_data, existing_asset_ids)
        parsed_data = self._remove_ghost_components(parsed_data, raw_text)
        parsed_data = self._extract_implemented_controls(parsed_data, raw_text)

        return self.validate_parsed_output(parsed_data, phase)

    def validate_parsed_output(self, data: dict[str, Any], phase: str) -> dict[str, Any]:
        # Normalize enums and ID prefixes before validation so issues are caught
        # against canonical values, not whatever the AI returned.
        data = self._post_process_parsed_data(data)

        missing_fields = [key for key in self.REQUIRED_KEYS if key not in data]
        invalid_type_fields = [
            key
            for key, expected_type in self.REQUIRED_TYPES.items()
            if key in data and not isinstance(data[key], expected_type)
        ]
        nested_validation_issues = self._validate_nested_structures(data)
        broken_references = self._validate_cross_references(data)

        # TODO: Add deeper nested validation for scalar value types and enum-like constraints.
        # TODO: Add field-level source_map validation so each generated section can be traced to evidence.
        # TODO: Add multi-document merge logic before prompt construction for overlapping evidence packages.
        # TODO: Add question generation for missing evidence when validation detects weak or unknown coverage.
        if self._is_planning_phase(phase):
            if not self._has_non_empty_string(data.get("architecture_summary")):
                missing_fields.append("architecture_summary")
            if not self._has_non_empty_list(data.get("actors")):
                missing_fields.append("actors")
            if not self._has_non_empty_list(data.get("components")):
                missing_fields.append("components")
            if not self._has_non_empty_list(data.get("data_flows")):
                missing_fields.append("data_flows")
            if not self._has_non_empty_list(data.get("assets")):
                missing_fields.append("assets")

        if self._is_development_phase(phase):
            if not (
                self._has_non_empty_list(data.get("components"))
                or self._has_non_empty_list(self._get_security_findings_list(data, "sast"))
            ):
                missing_fields.extend(["components", "security_findings.sast"])

        if self._is_pre_release_phase(phase):
            if not (
                self._has_non_empty_list(self._get_security_findings_list(data, "dast"))
                or self._has_non_empty_list(self._get_security_findings_list(data, "sast"))
                or self._has_non_empty_list(data.get("data_flows"))
            ):
                missing_fields.extend(
                    ["security_findings.dast", "security_findings.sast", "data_flows"]
                )

        combined_missing_fields = list(
            dict.fromkeys(
                missing_fields
                + invalid_type_fields
                + nested_validation_issues
                + broken_references
            )
        )

        return {
            "status": "ready" if not combined_missing_fields else "missing_fields",
            "missing_fields": combined_missing_fields,
            "parsed_data": data,
        }

    def _build_system_prompt(self) -> str:
        component_types = " | ".join(sorted(self.COMPONENT_TYPES))
        actor_types = " | ".join(sorted(self.ACTOR_TYPES))
        asset_types = " | ".join(sorted(self.ASSET_TYPES))
        asset_sensitivities = " | ".join(sorted(self.ASSET_SENSITIVITIES))
        ep_types = " | ".join(sorted(self.ENTRY_POINT_TYPES))
        ep_exposures = " | ".join(sorted(self.ENTRY_POINT_EXPOSURES))
        trust_zones = " | ".join(sorted(self.TRUST_ZONES))
        trust_levels = " | ".join(sorted(self.EXTERNAL_TRUST_LEVELS))

        return (
            "You are a security architecture structuring engine. "
            "Your output is consumed by automated threat modeling pipelines — precision and consistency matter more than coverage.\n\n"

            "DETERMINISM REQUIREMENT — identical input must produce identical output:\n"
            "  Use the exact entity names from the evidence as component names — do not paraphrase or rename them.\n"
            "  Sort all components alphabetically by name.\n"
            "  Sort all entry points alphabetically by name.\n"
            "  Sort all assets alphabetically by name.\n"
            "  Sort all actors alphabetically by name.\n"
            "  Use the minimum number of components necessary to represent the architecture — "
            "do not split one logical component into two.\n\n"

            "OUTPUT FORMAT\n"
            "Return only a single valid JSON object. "
            "No markdown, no code fences, no explanations before or after the JSON. "
            "Use these exact top-level keys: architecture_summary, actors, components, data_flows, "
            "trust_boundaries, assets, entry_points, authn_authz, external_dependencies, "
            "security_findings, assumptions, open_questions, source_map.\n\n"

            "ID NAMING RULES — follow exactly, every run must produce the same ID for the same entity\n"
            "  component ids: comp_<snake_case_name>  (e.g. comp_auth_service, comp_user_db, comp_api_gateway)\n"
            "  actor ids:     actor_<snake_case_name> (e.g. actor_end_user, actor_admin, actor_cicd_pipeline)\n"
            "  data flow ids: flow_<source_id>_to_<dest_id> trimmed to 60 chars\n"
            "  trust boundary ids: boundary_<snake_case_name> (e.g. boundary_public_internal, boundary_db_tier)\n"
            "  asset ids:     asset_<snake_case_name> (e.g. asset_user_credentials, asset_session_tokens)\n"
            "  entry point ids: entry_<snake_case_name> (e.g. entry_login_api, entry_admin_console)\n"
            "  Never use spaces, hyphens, or uppercase in ids. Never use generic ids like 'id1' or 'component1'.\n"
            "  If a reference id is not known, use the literal string 'unknown'.\n\n"

            "ENUM CONSTRAINTS — use ONLY the listed values for these fields (lowercase unless stated)\n"
            f"  component.type:              {component_types}\n"
            "    Component type selection rules:\n"
            "    - Reverse proxy or load balancer → gateway or proxy\n"
            "    - Handles business logic → backend\n"
            "    - Stores persistent data → database or storage\n"
            "    - Caches data in memory → cache\n"
            "    - Handles authentication or identity → auth\n"
            "    - If unsure between two types, pick the first alphabetically from the valid list\n"
            "    No other component.type values are accepted.\n"
            f"  actor.type:                  {actor_types}\n"
            f"  asset.type:                  {asset_types}\n"
            f"  asset.sensitivity:           {asset_sensitivities}\n"
            f"  entry_point.type:            {ep_types}\n"
            f"  entry_point.exposure:        {ep_exposures}\n"
            f"  component.trust_zone:        {trust_zones}\n"
            "    trust_zone must be exactly one of the listed values — no other values accepted.\n"
            f"  external_dependency.trust_level: {trust_levels}\n\n"

            "CROSS-REFERENCE RULES\n"
            "  data_flows[].source_component_id and destination_component_id MUST be ids that appear "
            "in the actors or components arrays, or 'unknown'.\n"
            "  trust_boundaries[].crossing_component_ids MUST be ids that appear in actors or components.\n"
            "  entry_points[].target_component_id MUST be a component id, or 'unknown'.\n"
            "  Never invent a reference id that does not exist in actors or components.\n\n"

            "CLASSIFICATION RULES\n"
            "  External users, admins, CI/CD pipelines, and third-party integrations belong in actors.\n"
            "  Deployable units (services, databases, queues, gateways) belong in components.\n"
            "  HTTP methods, API route verbs, actors, and product/system names are not components unless "
            "the evidence describes them as independently deployed services.\n"
            "  A trust boundary represents a zone crossing — list the component or actor ids that cross it.\n"
            "  An entry point is the attack surface — set exposure=public for internet-facing, "
            "exposure=internal for intranet-only, exposure=admin for management interfaces.\n\n"

            "SAST COMPONENT MAPPING\n"
            "  For each SAST finding, inspect the file path and infer which component owns it "
            "(e.g. src/auth/ → comp_auth_service, src/api/ → comp_api_service). "
            "Annotate the finding description with [component: <comp_id>] so threat generation "
            "can link the vulnerability to the correct component. "
            "Use the same comp_id that appears in the components array.\n\n"

            "MISSING EVIDENCE\n"
            "  If a field cannot be determined from the evidence, use 'unknown' for strings, "
            "[] for arrays, and {} for objects. "
            "Do not fabricate components, threats, or relationships not supported by evidence. "
            "Record gaps in open_questions."
        )

    def _build_user_prompt(
        self,
        evidence_package: dict[str, Any],
        existing_component_ids: dict[str, str] | None = None,
        existing_entry_point_ids: dict[str, str] | None = None,
        existing_asset_ids: dict[str, str] | None = None,
    ) -> str:
        source_map = evidence_package["source_map"]
        evidence_by_category = evidence_package["evidence_by_category"]
        security_findings = evidence_package["security_findings"]

        existing_normalized_names: set[str] | None = (
            set(existing_component_ids.keys()) if existing_component_ids else None
        )

        # Pre-extract component seeds from architecture docs and SAST paths.
        arch_seeds, sast_only_seeds = self._extract_component_seeds(
            evidence_by_category, security_findings, existing_normalized_names
        )

        seed_block_parts: list[str] = []

        # Existing IDs from previous version — highest priority anchor.
        if existing_component_ids:
            existing_lines = "\n".join(
                f"  - id: {cid}  (normalized name: {nname})"
                for nname, cid in sorted(existing_component_ids.items())
            )
            seed_block_parts.append(
                "EXISTING COMPONENT IDs FROM PREVIOUS VERSION "
                "(reuse these exact IDs when the component clearly matches — same role, same function):\n"
                f"{existing_lines}\n"
                "Only mint a new ID for a component genuinely absent from the previous version."
            )

        # Architecture-derived seeds.
        if arch_seeds:
            seed_lines = "\n".join(
                f"  - id: {s['id']}  name: {s['name']}  hint: {s['hint']}"
                for s in arch_seeds
            )
            seed_block_parts.append(
                "ARCHITECTURE COMPONENT SEEDS (use these exact ids — do not rename):\n"
                f"{seed_lines}\n"
                "You may add more components if the evidence supports them. "
                "Do NOT invent new ids for the components listed above."
            )

        # SAST-only seeds — softer instruction: create only if no existing component absorbs it.
        if sast_only_seeds:
            sast_lines = "\n".join(
                f"  - id: {s['id']}  name: {s['name']}  hint: {s['hint']}"
                for s in sast_only_seeds
            )
            seed_block_parts.append(
                "SAST-ONLY COMPONENT SEEDS (found in SAST file paths, no matching architecture component):\n"
                f"{sast_lines}\n"
                "Create a new component for these ONLY if the SAST finding cannot be mapped to any "
                "existing or architecture-defined component. Do not create a component if the finding "
                "can be attributed to an already-listed component or actor."
            )

        # Stable entry point IDs from previous version — prevents endpoint ID drift across runs.
        if existing_entry_point_ids:
            ep_lines = "\n".join(
                f"  - id: {eid}  (normalized name: {nname})"
                for nname, eid in sorted(existing_entry_point_ids.items())
            )
            seed_block_parts.append(
                "EXISTING ENTRY POINT IDs FROM PREVIOUS VERSION "
                "(reuse these exact IDs when the entry point clearly matches — same HTTP method, same path, same target):\n"
                f"{ep_lines}\n"
                "Only mint a new entry point ID for an entry point genuinely absent from the previous version."
            )

        # Stable asset IDs from previous version — prevents asset ID drift across runs.
        if existing_asset_ids:
            asset_lines = "\n".join(
                f"  - id: {aid}  (normalized name: {nname})"
                for nname, aid in sorted(existing_asset_ids.items())
            )
            seed_block_parts.append(
                "EXISTING ASSET IDs FROM PREVIOUS VERSION "
                "(reuse these exact IDs when the asset clearly matches — same data type, same location):\n"
                f"{asset_lines}\n"
                "Only mint a new asset ID for an asset genuinely absent from the previous version."
            )

        seed_block = ("\n\n".join(seed_block_parts) + "\n") if seed_block_parts else ""

        phase_priority = {
            "planning": "architecture and data_flows evidence",
            "in_development": "architecture, source_code, infrastructure, sast, sca, and manual_review evidence",
            "pre_release": "dast, infrastructure, data_flows, and manual_review evidence",
        }.get(evidence_package["phase"], "all evidence equally")

        return (
            "Convert the following extracted architecture and security evidence into structured JSON "
            "that exactly matches the schema below.\n\n"
            f"PHASE: {evidence_package['phase']}\n"
            f"For this phase, prioritize: {phase_priority}\n"
            f"{seed_block}\n"
            "--- EVIDENCE: Merged raw text ---\n"
            f"{evidence_package['raw_text']}\n\n"
            "--- EVIDENCE: Security findings (structured) ---\n"
            f"{json.dumps(security_findings, indent=2)}\n\n"
            "--- EVIDENCE: Grouped by category ---\n"
            f"{json.dumps(evidence_by_category, indent=2)}\n\n"
            "--- SOURCE METADATA ---\n"
            f"{json.dumps(source_map, indent=2)}\n\n"
            "--- EXPECTED OUTPUT SCHEMA ---\n"
            f"{json.dumps(self.EXPECTED_SCHEMA, indent=2)}\n\n"
            "REMINDERS before you output:\n"
            "1. Every id must follow the prefix convention: comp_ / actor_ / flow_ / boundary_ / asset_ / entry_\n"
            "2. All type, sensitivity, exposure, trust_zone, trust_level values must be from the enum lists in the system prompt.\n"
            "3. Every source_component_id, destination_component_id, target_component_id, and "
            "crossing_component_ids entry must reference an id that exists in your actors or components arrays.\n"
            "4. Annotate every SAST finding description with [component: <comp_id>].\n"
            "Use source_code files to infer application components, entry points, assets, and data flows.\n"
            "Use git_metadata only for commit/change context; do not infer application architecture from git_metadata alone.\n"
            "5. Use open_questions for anything the evidence does not clearly answer.\n"
            "6. Return only the JSON object — no markdown, no commentary."
        )

    def _extract_component_seeds(
        self,
        evidence_by_category: dict[str, Any],
        security_findings: dict[str, Any],
        existing_normalized_names: set[str] | None = None,
    ) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
        """Extract likely component IDs from SAST paths and architecture docs.

        Returns (arch_seeds, sast_only_seeds).
        sast_only_seeds are SAST-derived names that don't match any existing or
        architecture-defined component — injected with a softer prompt instruction.
        """
        arch_seeds: list[dict[str, str]] = []
        sast_only_seeds: list[dict[str, str]] = []
        seen: set[str] = set()

        def _add_seed(target: list[dict[str, str]], name: str, hint: str) -> None:
            key = name.lower().strip()
            if not key or key in seen or len(key) < 3:
                return
            seen.add(key)
            comp_id = "comp_" + key.replace("-", "_").replace(" ", "_").replace(".", "_")
            target.append({"id": comp_id, "name": name, "hint": hint})

        # 1. Architecture docs — build arch seeds first so seen set is populated.
        _COMPONENT_KEYWORDS = {
            "service", "api", "database", "db", "cache", "queue", "gateway",
            "proxy", "frontend", "backend", "worker", "storage", "broker",
        }
        arch_docs = (evidence_by_category or {}).get("architecture", [])
        _HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
        _SECTION_HEADERS = {
            "components",
            "actors",
            "entry points",
            "entry_points",
            "data flows",
            "data_flows",
            "assets",
            "authentication",
            "known weaknesses",
        }
        for doc in arch_docs[:3]:
            if not isinstance(doc, dict):
                continue
            in_components_section = False
            for line in str(doc.get("raw_text", ""))[:3000].splitlines():
                line = line.strip(":#-* \t")
                if not line or len(line) > 80:
                    continue
                section_name = line.rstrip(":").strip().lower()
                if section_name in _SECTION_HEADERS:
                    in_components_section = section_name == "components"
                    continue
                if not in_components_section:
                    continue
                if ":" not in line:
                    continue
                first_word = line.split()[0].strip("()[],'\"").upper()
                if first_word in _HTTP_METHODS or line.startswith("/"):
                    continue
                lower = line.lower()
                if any(kw in lower for kw in _COMPONENT_KEYWORDS):
                    # Component bullets usually look like "Name: description".
                    candidate = line.split(":", 1)[0]
                    candidate = re.sub(r"\s*\([^)]*\)", "", candidate).strip()
                    candidate = candidate.strip("[],'\"")
                    if candidate and len(candidate) > 2:
                        _add_seed(arch_seeds, candidate, "inferred from architecture doc")

        # Build a combined set of normalized names the arch + existing IDs already cover,
        # so SAST seeds that duplicate them are silently discarded.
        covered_normalized: set[str] = {self._normalize_component_name(s["name"]) for s in arch_seeds}
        if existing_normalized_names:
            covered_normalized.update(existing_normalized_names)

        # 2. SAST finding file paths → top-level directory = likely component.
        # Only added as sast_only when not already covered by arch or existing IDs.
        sast = security_findings.get("sast", []) if isinstance(security_findings, dict) else []
        for finding in sast[:30]:
            if not isinstance(finding, dict):
                continue
            for loc in finding.get("locations", []):
                if not isinstance(loc, dict):
                    continue
                physical = loc.get("physicalLocation") or {}
                artifact = physical.get("artifactLocation") or {} if isinstance(physical, dict) else {}
                uri = artifact.get("uri", "") if isinstance(artifact, dict) else ""
                if uri and "/" in uri:
                    top_dir = uri.split("/")[0]
                    norm = self._normalize_component_name(top_dir)
                    if norm not in covered_normalized:
                        _add_seed(sast_only_seeds, top_dir, "inferred from SAST file path")

        total_cap = 15
        return arch_seeds[:total_cap], sast_only_seeds[:max(0, total_cap - len(arch_seeds))]

    def _post_process_parsed_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Normalize enum values and ID prefixes deterministically.

        This runs after the AI call to fix any deviation from the controlled
        vocabularies — so downstream consumers always see canonical values.
        """
        # Components
        for item in data.get("components", []):
            if not isinstance(item, dict):
                continue
            item["type"] = self._normalize_enum(
                item.get("type"), self.COMPONENT_TYPES, self._COMPONENT_TYPE_ALIASES, "service"
            )
            # Name-type lock applied after alias normalization — always wins.
            self._apply_name_type_lock(item)
            if "trust_zone" in item:
                item["trust_zone"] = self._normalize_enum(
                    item.get("trust_zone"), self.TRUST_ZONES, self._TRUST_ZONE_ALIASES, "internal"
                )
            item["id"] = self._ensure_prefix(item.get("id", ""), "comp_")

        # Actors
        for item in data.get("actors", []):
            if not isinstance(item, dict):
                continue
            item["type"] = self._normalize_enum(
                item.get("type"), self.ACTOR_TYPES, self._ACTOR_TYPE_ALIASES, "user"
            )
            item["id"] = self._ensure_prefix(item.get("id", ""), "actor_")

        # Assets
        for item in data.get("assets", []):
            if not isinstance(item, dict):
                continue
            item["type"] = self._normalize_enum(
                item.get("type"), self.ASSET_TYPES, {}, "data"
            )
            item["sensitivity"] = self._normalize_sensitivity(item.get("sensitivity"))
            item["id"] = self._ensure_prefix(item.get("id", ""), "asset_")

        # Entry points
        for item in data.get("entry_points", []):
            if not isinstance(item, dict):
                continue
            item["type"] = self._normalize_enum(
                item.get("type"), self.ENTRY_POINT_TYPES, self._ENTRY_POINT_TYPE_ALIASES, "api"
            )
            item["exposure"] = self._normalize_enum(
                item.get("exposure"), self.ENTRY_POINT_EXPOSURES, {}, "internal"
            )
            item["id"] = self._ensure_prefix(item.get("id", ""), "entry_")

        # External dependencies
        for item in data.get("external_dependencies", []):
            if not isinstance(item, dict):
                continue
            item["trust_level"] = self._normalize_enum(
                item.get("trust_level"), self.EXTERNAL_TRUST_LEVELS, {}, "conditional"
            )

        # Data flows
        for item in data.get("data_flows", []):
            if not isinstance(item, dict):
                continue
            item["id"] = self._ensure_prefix(item.get("id", ""), "flow_")

        # Trust boundaries
        for item in data.get("trust_boundaries", []):
            if not isinstance(item, dict):
                continue
            item["id"] = self._ensure_prefix(item.get("id", ""), "boundary_")

        self._apply_domain_model_fixes(data)

        return data

    def _apply_domain_model_fixes(self, data: dict[str, Any]) -> None:
        """Apply deterministic cleanup for common parser drift patterns."""

        components = data.setdefault("components", [])
        if not isinstance(components, list):
            return

        component_by_id = {
            str(component.get("id", "")): component
            for component in components
            if isinstance(component, dict)
        }

        for component in components:
            if not isinstance(component, dict):
                continue
            component_id = str(component.get("id", "")).lower()
            component_name = str(component.get("name", "")).lower()
            identity = f"{component_id} {component_name}"

            if "employee_api" in identity or "employee api" in identity:
                component["type"] = "backend"
            elif "file_upload_service" in identity or "file upload service" in identity:
                component["type"] = "backend"
            elif "admin_dashboard" in identity or "admin dashboard" in identity:
                component["type"] = "frontend"
            elif "rabbitmq" in identity or "rabbit mq" in identity:
                component["type"] = "queue"
            elif (
                "twilio" in identity
                or "sendgrid" in identity
                or "send_grid" in identity
                or "send grid" in identity
            ):
                component["type"] = "external"
                component["trust_zone"] = "external"
            elif "database" in identity or "postgres" in identity or "postgresql" in identity:
                component["type"] = "database"
            elif "cache" in identity or "redis" in identity:
                component["type"] = "cache"
            elif any(
                marker in identity
                for marker in (
                    "account_service", "account service",
                    "authentication_service", "authentication service",
                    "auth_service", "auth service",
                    "transfer_service", "transfer service",
                    "notification_service", "notification service",
                    "admin_service", "admin service",
                )
            ):
                component["type"] = "backend"

        self._normalize_entry_point_exposures(data)
        self._ensure_sast_inferred_admin_surface(data, component_by_id)

    def _normalize_entry_point_exposures(self, data: dict[str, Any]) -> None:
        entry_points = data.get("entry_points", [])
        if not isinstance(entry_points, list):
            return

        auth_markers = (
            "jwt required", "requires valid jwt", "authenticated", "token required",
            "access token required", "refresh token required",
        )
        unauth_markers = (
            "no authentication required", "no auth required", "unauthenticated",
            "credential submission",
        )
        for entry in entry_points:
            if not isinstance(entry, dict):
                continue
            exposure = str(entry.get("exposure", "")).strip().lower()
            if exposure != "public":
                continue
            description = str(entry.get("description", "")).lower()
            if any(marker in description for marker in unauth_markers):
                entry["exposure"] = "public_unauthenticated"
            elif any(marker in description for marker in auth_markers):
                entry["exposure"] = "public_authenticated"

    def _extract_implemented_controls(
        self,
        parsed_data: dict[str, Any],
        raw_text: str,
    ) -> dict[str, Any]:
        """Extract a small set of deterministic controls used as negative evidence."""

        combined = " ".join([
            str(raw_text or ""),
            json.dumps(parsed_data, sort_keys=True),
        ]).lower()
        controls: list[dict[str, Any]] = []
        negative_markers = (
            "no authentication",
            "not configured",
            "not enforced",
            "without mutual tls",
            "no mutual tls",
            "missing",
            "does not check",
            "do not re-validate",
            "not re-validate",
            "has not been rotated",
            "have not been rotated",
            "no ownership check",
            "without parameterisation",
            "without parameterization",
        )

        def has_negative_near(*anchors: str) -> bool:
            for anchor in anchors:
                if not anchor:
                    continue
                for match in re.finditer(re.escape(anchor.lower()), combined):
                    start = max(0, match.start() - 160)
                    end = min(len(combined), match.end() + 180)
                    window = combined[start:end]
                    if any(marker in window for marker in negative_markers):
                        return True
            return False

        def add_control(
            control_id: str,
            control_type: str,
            target_component_id: str,
            mitigates: list[str],
            target_asset_id: str | None = None,
        ) -> None:
            if any(c.get("id") == control_id for c in controls):
                return
            controls.append({
                "id": control_id,
                "control_type": control_type,
                "target_component_id": target_component_id,
                "target_asset_id": target_asset_id,
                "status": "implemented",
                "mitigates": mitigates,
            })

        if "redis" in combined and any(
            marker in combined
            for marker in ("authentication now enabled", "requirepass", "auth-protected", "auth password", "redis auth")
        ) and not has_negative_near("redis", "refresh tokens"):
            add_control(
                "control_redis_auth",
                "authentication",
                "comp_cache_redis",
                ["CWE-522", "redis_unauthenticated_access", "redis_token_exposure"],
                "asset_refresh_tokens",
            )

        if (
            "jwt secret" in combined
            and "secrets manager" in combined
            and not has_negative_near("jwt secret", "auth_service/config")
        ):
            add_control(
                "control_jwt_secret_secrets_manager",
                "secret_management",
                "comp_auth_service",
                ["CWE-798", "hardcoded_jwt_secret", "easy_token_forgery"],
                "asset_jwt_secret",
            )

        if ("mutual tls" in combined or "mtls" in combined) and not has_negative_near("mutual tls", "mtls"):
            add_control(
                "control_internal_mtls",
                "transport_security",
                "comp_api_gateway",
                ["internal_http_tampering", "internal_traffic_disclosure", "CWE-319"],
            )

        if "vpn" in combined and "admin dashboard" in combined and not has_negative_near("vpn", "admin dashboard"):
            add_control(
                "control_admin_dashboard_vpn",
                "network_access_control",
                "comp_admin_dashboard",
                ["admin_dashboard_public_exposure", "admin_dashboard_spoofing"],
                "asset_admin_jwt",
            )

        if (
            "ownership check" in combined or "checks that the requesting user is the file owner" in combined
        ) and not has_negative_near("ownership check", "file owner", "download endpoint"):
            add_control(
                "control_file_ownership_check",
                "authorization",
                "comp_file_upload_service",
                ["CWE-639", "idor_file_download", "missing_ownership_check"],
                "asset_uploaded_hr_documents",
            )

        if all(marker in combined for marker in ("file type", "mime", "magic byte")) and not has_negative_near(
            "file type", "mime", "magic byte", "upload"
        ):
            add_control(
                "control_file_type_validation",
                "input_validation",
                "comp_file_upload_service",
                ["CWE-434", "unrestricted_file_upload"],
                "asset_uploaded_hr_documents",
            )

        if "admin role" in combined and "validation" in combined and not has_negative_near("admin role", "admin endpoint"):
            add_control(
                "control_admin_role_validation",
                "authorization",
                "comp_admin_api",
                ["CWE-306", "missing_admin_role_validation"],
                "asset_admin_jwt",
            )

        if "rabbitmq" in combined and "guest" in combined and any(
            marker in combined for marker in ("rotated", "dedicated service credentials", "limited permissions")
        ) and not has_negative_near("rabbitmq", "guest"):
            add_control(
                "control_rabbitmq_rotated_credentials",
                "credential_management",
                "comp_message_queue_rabbitmq",
                ["rabbitmq_default_guest_credentials"],
            )

        if "credentials" in combined and "secrets manager" in combined:
            add_control(
                "control_credentials_secrets_manager",
                "secret_management",
                "comp_secrets_manager_aws",
                ["environment_credential_exposure", "hardcoded_credentials"],
            )

        if controls:
            existing = parsed_data.get("implemented_controls")
            parsed_data["implemented_controls"] = (
                [c for c in existing if isinstance(c, dict)] if isinstance(existing, list) else []
            )
            existing_ids = {c.get("id") for c in parsed_data["implemented_controls"]}
            parsed_data["implemented_controls"].extend(
                control for control in controls if control.get("id") not in existing_ids
            )
        return parsed_data

    def _ensure_sast_inferred_admin_surface(
        self,
        data: dict[str, Any],
        component_by_id: dict[str, dict[str, Any]],
    ) -> None:
        findings = self._get_security_findings_list(data, "sast")
        if not isinstance(findings, list):
            return

        has_admin_service_evidence = False
        has_reverse_endpoint_evidence = False
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            finding_text = json.dumps(finding).lower()
            if "admin_service" in finding_text or "admin service" in finding_text:
                has_admin_service_evidence = True
            if "/admin/transfers/reverse" in finding_text or "transfer reversal" in finding_text:
                has_reverse_endpoint_evidence = True

        if not has_admin_service_evidence:
            return

        components = data.setdefault("components", [])
        if "comp_admin_service" not in component_by_id:
            admin_service = {
                "id": "comp_admin_service",
                "name": "Admin Service",
                "type": "backend",
                "description": "Admin backend service inferred from SAST evidence.",
                "trust_zone": "internal",
            }
            components.append(admin_service)
            component_by_id["comp_admin_service"] = admin_service
        else:
            component_by_id["comp_admin_service"]["type"] = "backend"

        if not has_reverse_endpoint_evidence:
            return

        entry_points = data.setdefault("entry_points", [])
        if isinstance(entry_points, list) and not any(
            isinstance(entry, dict) and entry.get("id") == "entry_admin_transfers_reverse"
            for entry in entry_points
        ):
            entry_points.append(
                {
                    "id": "entry_admin_transfers_reverse",
                    "name": "POST /admin/transfers/reverse",
                    "type": "api",
                    "exposure": "admin",
                    "description": "Admin transfer reversal endpoint inferred from SAST evidence.",
                    "target_component_id": "comp_admin_service",
                }
            )

        data_flows = data.setdefault("data_flows", [])
        if (
            isinstance(data_flows, list)
            and "comp_admin_dashboard" in component_by_id
            and not any(
                isinstance(flow, dict)
                and flow.get("source_component_id") == "comp_admin_dashboard"
                and flow.get("destination_component_id") == "comp_admin_service"
                for flow in data_flows
            )
        ):
            data_flows.append(
                {
                    "id": "flow_comp_admin_dashboard_to_comp_admin_service",
                    "source_component_id": "comp_admin_dashboard",
                    "destination_component_id": "comp_admin_service",
                    "protocol": "HTTP",
                    "description": "Admin dashboard calls the admin backend service.",
                }
            )

    def _normalize_enum(
        self,
        value: Any,
        valid: set[str],
        aliases: dict[str, str],
        default: str,
    ) -> str:
        if not isinstance(value, str):
            return default
        normalized = value.strip().lower().replace(" ", "_").replace("-", "_")
        if normalized in valid:
            return normalized
        if normalized in aliases:
            return aliases[normalized]
        # Substring match as last resort
        for v in valid:
            if v in normalized or normalized in v:
                return v
        return default

    def _apply_name_type_lock(self, component: dict[str, Any]) -> None:
        """Override component type when a known technology keyword is present.

        Scans component name + description for keywords in NAME_TYPE_LOCKS using
        full word-boundary matching so 'credentials' does not match 'redis'.
        Longest keyword wins when multiple keywords match — most specific takes precedence.
        """
        search_text = (
            component.get("name", "").lower()
            + " "
            + component.get("description", "").lower()
        )
        best_keyword: str | None = None
        best_length = 0
        locked_type: str = ""

        for keyword, ktype in self.NAME_TYPE_LOCKS.items():
            pattern = r"\b" + re.escape(keyword) + r"\b"
            if re.search(pattern, search_text) and len(keyword) > best_length:
                best_keyword = keyword
                best_length = len(keyword)
                locked_type = ktype

        if best_keyword:
            logger.debug(
                "Name-type lock: %s → %s (keyword: %s)",
                component.get("id"), locked_type, best_keyword,
            )
            component["type"] = locked_type
        else:
            # Safety net: a component whose name contains "service"/"Service" should not
            # be typed as database/cache/queue unless a tech keyword explicitly caused it.
            name_lower = component.get("name", "").lower()
            desc_lower = component.get("description", "").lower()
            combined = name_lower + " " + desc_lower
            _INFRA_TYPES = {"database", "cache", "queue"}
            _TECH_KEYWORDS = {
                "postgres", "postgresql", "mysql", "mongodb", "sqlite",
                "redis", "memcached", "rabbitmq", "kafka",
            }
            if (
                ("_service" in name_lower or "service" in name_lower)
                and component.get("type") in _INFRA_TYPES
                and not any(tk in combined for tk in _TECH_KEYWORDS)
            ):
                logger.debug(
                    "Service-role override: %s type %s → backend",
                    component.get("id"), component.get("type"),
                )
                component["type"] = "backend"

    def _normalize_sensitivity(self, value: Any) -> str:
        if not isinstance(value, str):
            return "Medium"
        cap = value.strip().capitalize()
        if cap in self.ASSET_SENSITIVITIES:
            return cap
        lower = value.strip().lower()
        mapping = {
            "critical": "Critical", "crit": "Critical", "p0": "Critical",
            "high": "High", "p1": "High",
            "medium": "Medium", "med": "Medium", "moderate": "Medium", "p2": "Medium",
            "low": "Low", "p3": "Low", "informational": "Low", "info": "Low",
        }
        return mapping.get(lower, "Medium")

    def _ensure_prefix(self, value: str, prefix: str) -> str:
        """Add the prefix if the id doesn't already start with it and isn't 'unknown'."""
        if not isinstance(value, str):
            return prefix + "unknown"
        cleaned = value.strip().lower().replace(" ", "_").replace("-", "_")
        if not cleaned or cleaned == "unknown":
            return "unknown"
        if cleaned.startswith(prefix):
            return cleaned
        return prefix + cleaned

    def _build_evidence_package(
        self,
        phase: str,
        raw_text: str,
        security_findings: dict[str, Any] | None,
        evidence_by_category: dict[str, Any] | None,
        source_map: list[dict[str, Any]] | None,
    ) -> dict[str, Any]:
        return {
            "phase": phase,
            "raw_text": raw_text.strip(),
            "security_findings": self._normalize_security_findings(security_findings),
            "evidence_by_category": self._normalize_evidence_by_category(evidence_by_category),
            "source_map": self._normalize_source_map(source_map),
        }

    def _preserve_structured_security_findings(
        self,
        parsed_data: dict[str, Any],
        evidence_findings: dict[str, Any],
    ) -> dict[str, Any]:
        """Keep scanner findings as structured evidence after the AI parse.

        The parser may summarize findings as prose strings, but threat generation
        needs rule IDs, CWE values, severities, files, and lines for deterministic
        SAST/DAST grounding. Non-empty structured input therefore wins.
        """
        if not isinstance(parsed_data, dict):
            parsed_data = {}

        parsed_findings = parsed_data.get("security_findings")
        if not isinstance(parsed_findings, dict):
            parsed_findings = {}

        normalized_evidence = self._normalize_security_findings(evidence_findings)
        for key, values in normalized_evidence.items():
            if values:
                parsed_findings[key] = values
            else:
                parsed_findings.setdefault(key, [])

        parsed_data["security_findings"] = parsed_findings
        return parsed_data

    def _normalize_security_findings(
        self,
        security_findings: dict[str, Any] | None,
    ) -> dict[str, Any]:
        normalized = {
            "sast": [],
            "dast": [],
            "sca": [],
            "infrastructure": [],
            "manual_review": [],
        }
        if security_findings is None:
            return normalized

        if not isinstance(security_findings, dict):
            raise ValueError("security_findings must be a dictionary when provided")

        for key in normalized:
            value = security_findings.get(key)
            if isinstance(value, list):
                normalized[key] = value

        return normalized

    def _get_security_findings_list(self, data: dict[str, Any], key: str) -> Any:
        findings = data.get("security_findings")
        if not isinstance(findings, dict):
            return None

        # TODO: Add nested schema checks for security_findings categories.
        return findings.get(key)

    def _validate_nested_structures(self, data: dict[str, Any]) -> list[str]:
        issues: list[str] = []

        for field_name, required_keys in self.NESTED_REQUIRED_KEYS.items():
            field_value = data.get(field_name)
            if not isinstance(field_value, list):
                continue

            for index, item in enumerate(field_value):
                if not isinstance(item, dict):
                    issues.append(f"{field_name}[{index}]")
                    continue

                for key in required_keys:
                    if key not in item:
                        issues.append(f"{field_name}[{index}].{key}")

        # TODO: Validate cross-references between ids once deterministic graph rules are added.
        return issues

    def _validate_cross_references(self, data: dict[str, Any]) -> list[str]:
        issues: list[str] = []
        actor_ids = self._collect_ids(data.get("actors"))
        component_ids = self._collect_ids(data.get("components"))
        actor_or_component_ids = actor_ids | component_ids

        data_flows = data.get("data_flows")
        if isinstance(data_flows, list):
            for index, item in enumerate(data_flows):
                if not isinstance(item, dict):
                    continue

                source_id = item.get("source_component_id")
                if self._is_broken_reference(source_id, actor_or_component_ids):
                    issues.append(f"data_flows[{index}].source_component_id")

                destination_id = item.get("destination_component_id")
                if self._is_broken_reference(destination_id, actor_or_component_ids):
                    issues.append(f"data_flows[{index}].destination_component_id")

        trust_boundaries = data.get("trust_boundaries")
        if isinstance(trust_boundaries, list):
            for index, item in enumerate(trust_boundaries):
                if not isinstance(item, dict):
                    continue

                crossing_ids = item.get("crossing_component_ids")
                if not isinstance(crossing_ids, list):
                    continue

                for crossing_index, crossing_id in enumerate(crossing_ids):
                    if self._is_broken_reference(crossing_id, actor_or_component_ids):
                        issues.append(
                            f"trust_boundaries[{index}].crossing_component_ids[{crossing_index}]"
                        )

        entry_points = data.get("entry_points")
        if isinstance(entry_points, list):
            for index, item in enumerate(entry_points):
                if not isinstance(item, dict):
                    continue

                target_component_id = item.get("target_component_id")
                if self._is_broken_reference(target_component_id, component_ids):
                    issues.append(f"entry_points[{index}].target_component_id")

        return issues

    def _normalize_evidence_by_category(
        self,
        evidence_by_category: dict[str, Any] | None,
    ) -> dict[str, list[Any]]:
        normalized = {
            "architecture": [],
            "data_flows": [],
            "source_code": [],
            "sast": [],
            "dast": [],
            "sca": [],
            "infrastructure": [],
            "manual_review": [],
            "git_metadata": [],
        }
        if not isinstance(evidence_by_category, dict):
            return normalized

        for key in normalized:
            value = evidence_by_category.get(key)
            if isinstance(value, list):
                normalized[key] = value

        return normalized

    def _normalize_source_map(self, source_map: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
        if not isinstance(source_map, list):
            return []

        return [item for item in source_map if isinstance(item, dict)]

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

    def _has_non_empty_list(self, value: Any) -> bool:
        return isinstance(value, list) and len(value) > 0

    def _has_non_empty_string(self, value: Any) -> bool:
        return isinstance(value, str) and bool(value.strip())

    def _is_planning_phase(self, phase: str) -> bool:
        return self._normalize_phase(phase) == "planning"

    def _is_development_phase(self, phase: str) -> bool:
        return self._normalize_phase(phase) == "in_development"

    def _is_pre_release_phase(self, phase: str) -> bool:
        return self._normalize_phase(phase) == "pre_release"

    @staticmethod
    def _normalize_component_name(name: str) -> str:
        """Collapse a component name to lowercase alphanumerics for fuzzy cross-version matching.

        "Authentication Service" → "authenticationservice"
        "auth_service"          → "authservice"
        Both normalize to the same string, so the stable ID is reused.
        """
        return re.sub(r"[^a-z0-9]", "", name.lower())

    @staticmethod
    def _normalize_entity_name(name: str) -> str:
        """Normalize any entity name (entry point, asset) to lowercase alphanumerics.

        "POST /auth/login" → "postauthlogin"
        "JWT Secret"       → "jwtsecret"
        """
        return re.sub(r"[^a-z0-9]", "", name.lower())

    def _reconcile_component_ids(
        self,
        parsed_data: dict[str, Any],
        existing_component_ids: dict[str, str],
    ) -> dict[str, Any]:
        """Replace AI-invented component IDs with stable IDs from the previous version.

        Safety net in case the AI ignores the prompt instruction to reuse existing IDs.
        Updates all cross-references in data_flows, trust_boundaries, and entry_points.
        """
        id_remap: dict[str, str] = {}
        for component in parsed_data.get("components", []):
            if not isinstance(component, dict):
                continue
            norm = self._normalize_component_name(component.get("name", ""))
            stable_id = existing_component_ids.get(norm)
            if stable_id and component.get("id") != stable_id:
                old_id = component["id"]
                id_remap[old_id] = stable_id
                component["id"] = stable_id
                logger.debug("ID reconciliation: %s → %s (%s)", old_id, stable_id, norm)

        if id_remap:
            self._remap_cross_references(parsed_data, id_remap)
        return parsed_data

    def _reconcile_entry_point_ids(
        self,
        parsed_data: dict[str, Any],
        existing_entry_point_ids: dict[str, str],
    ) -> dict[str, Any]:
        """Replace AI-invented entry point IDs with stable IDs from the previous version."""
        for ep in parsed_data.get("entry_points", []):
            if not isinstance(ep, dict):
                continue
            norm = self._normalize_entity_name(ep.get("name", ""))
            stable_id = existing_entry_point_ids.get(norm)
            if stable_id and ep.get("id") != stable_id:
                logger.debug(
                    "Entry point ID reconciliation: %s → %s (%s)",
                    ep.get("id"), stable_id, norm,
                )
                ep["id"] = stable_id
        return parsed_data

    def _reconcile_asset_ids(
        self,
        parsed_data: dict[str, Any],
        existing_asset_ids: dict[str, str],
    ) -> dict[str, Any]:
        """Replace AI-invented asset IDs with stable IDs from the previous version."""
        for asset in parsed_data.get("assets", []):
            if not isinstance(asset, dict):
                continue
            norm = self._normalize_entity_name(asset.get("name", ""))
            stable_id = existing_asset_ids.get(norm)
            if stable_id and asset.get("id") != stable_id:
                logger.debug(
                    "Asset ID reconciliation: %s → %s (%s)",
                    asset.get("id"), stable_id, norm,
                )
                asset["id"] = stable_id
        return parsed_data

    def _remap_cross_references(
        self,
        data: dict[str, Any],
        remap: dict[str, str],
    ) -> None:
        """Update all foreign-key references in the parsed model after an ID remap."""
        for flow in data.get("data_flows", []):
            if not isinstance(flow, dict):
                continue
            for key in ("source_component_id", "destination_component_id"):
                if flow.get(key) in remap:
                    flow[key] = remap[flow[key]]
            # Rebuild flow ID from the (possibly remapped) source/dest IDs.
            src = flow.get("source_component_id", "")
            dst = flow.get("destination_component_id", "")
            if flow.get("id", "").startswith("flow_") and src and dst:
                flow["id"] = f"flow_{src}_to_{dst}"[:60]

        for boundary in data.get("trust_boundaries", []):
            if not isinstance(boundary, dict):
                continue
            crossing = boundary.get("crossing_component_ids")
            if isinstance(crossing, list):
                boundary["crossing_component_ids"] = [
                    remap.get(cid, cid) for cid in crossing
                ]

        for ep in data.get("entry_points", []):
            if not isinstance(ep, dict):
                continue
            if ep.get("target_component_id") in remap:
                ep["target_component_id"] = remap[ep["target_component_id"]]

    def _remove_ghost_components(
        self,
        parsed_data: dict[str, Any],
        arch_raw_text: str,
    ) -> dict[str, Any]:
        """Remove components that are misclassified assets or SAST-hallucinated entities.

        A component is considered a ghost when ALL four conditions hold:
        - No entry point targets it.
        - No data flow includes it as source or destination.
        - Its normalized name matches a parsed asset name (it's an asset, not a service).
        - Its name does not appear in the raw architecture text.

        RabbitMQ and similar real infrastructure components are protected because they
        appear in architecture text and have data flows.
        """
        components = parsed_data.get("components", [])
        if not isinstance(components, list):
            return parsed_data

        entry_point_target_ids = {
            ep.get("target_component_id")
            for ep in parsed_data.get("entry_points", [])
            if isinstance(ep, dict)
        }
        flow_component_ids: set[str] = set()
        for flow in parsed_data.get("data_flows", []):
            if not isinstance(flow, dict):
                continue
            flow_component_ids.add(flow.get("source_component_id", ""))
            flow_component_ids.add(flow.get("destination_component_id", ""))

        asset_names_normalized = {
            self._normalize_component_name(a.get("name", ""))
            for a in parsed_data.get("assets", [])
            if isinstance(a, dict) and a.get("name")
        }

        arch_text_lower = arch_raw_text.lower()
        to_remove: set[str] = set()

        for component in components:
            if not isinstance(component, dict):
                continue
            comp_id = component.get("id", "")
            comp_name = component.get("name", "")
            norm_name = self._normalize_component_name(comp_name)

            has_entry_point = comp_id in entry_point_target_ids
            has_flow = comp_id in flow_component_ids
            matches_asset = norm_name in asset_names_normalized
            in_arch_text = bool(comp_name) and comp_name.lower() in arch_text_lower

            if not has_entry_point and not has_flow and matches_asset and not in_arch_text:
                logger.warning(
                    "Ghost component removed: %s (%s) — name matches asset, "
                    "not in arch text, no flows or entry points",
                    comp_id,
                    comp_name,
                )
                to_remove.add(comp_id)

        if to_remove:
            parsed_data["components"] = [
                c for c in components
                if not (isinstance(c, dict) and c.get("id") in to_remove)
            ]
            for boundary in parsed_data.get("trust_boundaries", []):
                if isinstance(boundary, dict):
                    crossing = boundary.get("crossing_component_ids")
                    if isinstance(crossing, list):
                        boundary["crossing_component_ids"] = [
                            cid for cid in crossing if cid not in to_remove
                        ]

        return parsed_data

    def _normalize_phase(self, phase: str) -> str:
        normalized_phase = phase.strip().lower().replace(" ", "_").replace("-", "_").replace("/", "_")
        normalized_phase = "_".join(part for part in normalized_phase.split("_") if part)

        if normalized_phase in {"planning", "plan", "pre_development"}:
            return "planning"
        if normalized_phase in {"in_development", "development", "dev"}:
            return "in_development"
        if normalized_phase in {"pre_release", "testing", "pre_release_testing"}:
            return "pre_release"
        return normalized_phase
