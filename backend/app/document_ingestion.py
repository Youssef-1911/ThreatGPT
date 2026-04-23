import json
from pathlib import Path
from typing import Any


DEFAULT_SECURITY_FINDINGS = {
    "sast": [],
    "dast": [],
    "sca": [],
    "infrastructure": [],
    "manual_review": [],
}

TAG_CATEGORY_ALIASES = {
    "architecture": "architecture",
    "design": "architecture",
    "system_design": "architecture",
    "components": "architecture",
    "data_flows": "data_flows",
    "data_flow": "data_flows",
    "dfd": "data_flows",
    "trust_boundaries": "data_flows",
    "trust_boundary": "data_flows",
    "sast": "sast",
    "dast": "dast",
    "pentest": "dast",
    "penetration_test": "dast",
    "sca": "sca",
    "dependency_scan": "sca",
    "infrastructure": "infrastructure",
    "iac": "infrastructure",
    "manual_review": "manual_review",
    "notes": "manual_review",
    "requirements": "manual_review",
    "api_spec": "manual_review",
    "api_specification": "manual_review",
    "source_code": "source_code",
    "source": "source_code",
    "code": "source_code",
    "git_metadata": "git_metadata",
}

FILENAME_CATEGORY_HINTS = {
    "architecture": ["architecture", "design", "overview", "system"],
    "data_flows": ["dataflow", "data_flow", "dfd", "sequence"],
    "sast": ["sast", "sarif", "semgrep", "codeql", "static"],
    "dast": ["dast", "zap", "burp", "dynamic"],
    "sca": ["sca", "dependency", "dependencies", "sbom", "supply_chain"],
    "infrastructure": ["infra", "infrastructure", "terraform", "iac", "k8s", "kubernetes"],
    "manual_review": ["review", "notes", "questionnaire", "checklist"],
    "source_code": ["src", "source", "app"],
}


def extract_txt(file_path: str) -> str:
    return Path(file_path).read_text(encoding="utf-8")


def extract_csv(file_path: str) -> str:
    return Path(file_path).read_text(encoding="utf-8")


def extract_json(file_path: str) -> dict[str, Any]:
    with Path(file_path).open("r", encoding="utf-8") as file_handle:
        data = json.load(file_handle)

    if not isinstance(data, dict):
        raise ValueError("JSON document must contain a top-level object")

    return data


def extract_pdf(file_path: str) -> str:
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        # TODO: Add a preferred PDF extraction library and richer page-level handling.
        raise RuntimeError("PDF extraction requires the 'pypdf' package") from exc

    reader = PdfReader(file_path)
    text_chunks: list[str] = []

    for page in reader.pages:
        text_chunks.append(page.extract_text() or "")

    return "\n".join(text_chunks).strip()


def extract_docx(file_path: str) -> str:
    try:
        from docx import Document
    except ImportError as exc:
        # TODO: Add better DOCX support for tables, headers, and embedded content.
        raise RuntimeError("DOCX extraction requires the 'python-docx' package") from exc

    document = Document(file_path)
    paragraphs = [paragraph.text for paragraph in document.paragraphs]
    return "\n".join(paragraphs).strip()


def normalize_security_findings(
    data: dict[str, Any],
    category: str | None = None,
) -> dict[str, list[Any]]:
    normalized = _empty_security_findings()

    runs = data.get("runs")
    if isinstance(runs, list):
        normalized["sast"] = _extract_sarif_results(runs)
        return normalized

    for key in normalized:
        value = data.get(key)
        if isinstance(value, list):
            normalized[key] = value

    findings = data.get("security_findings")
    if isinstance(findings, dict):
        for key in normalized:
            value = findings.get(key)
            if isinstance(value, list):
                normalized[key] = value

    # Scanner reports often use a generic top-level "findings" array. Route it
    # through the document category so SAST/DAST findings remain structured.
    generic_findings = data.get("findings")
    if isinstance(generic_findings, list) and category in normalized:
        normalized[category] = generic_findings

    # TODO: Add deterministic normalization for more scanner-specific JSON formats.
    return normalized


# File types treated as plain text — includes all source code extensions
# so that code files fetched from git are ingested without errors.
_TEXT_LIKE_TYPES = frozenset(
    {
        "txt", "csv", "md",
        # Backend source
        "py", "go", "java", "cs", "rb", "rs", "php", "swift", "kt",
        # Frontend source
        "ts", "tsx", "js", "jsx", "vue", "svelte",
        # Shell / CI
        "sh", "bash",
        # Infrastructure
        "tf", "tfvars", "toml", "ini", "conf", "sql",
        # Web
        "html", "css", "scss", "xml",
        # Misc text
        "yaml", "yml",  # handled separately for SARIF detection, but also valid as text
    }
)


def ingest_document(
    file_path: str,
    file_type: str,
    phase: str | None = None,
    tag: str | None = None,
) -> dict[str, Any]:
    normalized_type = file_type.strip().lower().lstrip(".")
    raw_text = ""
    security_findings = _empty_security_findings()
    source_path = Path(file_path)
    json_data: dict[str, Any] | None = None

    if normalized_type in _TEXT_LIKE_TYPES:
        raw_text = extract_txt(file_path)
    elif normalized_type == "json":
        json_data = extract_json(file_path)
        raw_text = json.dumps(json_data, indent=2)
    elif normalized_type == "sarif":
        json_data = extract_json(file_path)
        raw_text = json.dumps(json_data, indent=2)
    elif normalized_type == "pdf":
        raw_text = extract_pdf(file_path)
    elif normalized_type == "docx":
        raw_text = extract_docx(file_path)
    else:
        raise ValueError(f"Unsupported file type: {file_type}")

    category = categorize_document(
        file_path=file_path,
        file_type=normalized_type,
        phase=phase,
        tag=tag,
        json_data=json_data,
    )
    phase_bucket = infer_phase_bucket(phase, category)
    if json_data is not None:
        security_findings = normalize_security_findings(json_data, category=category)

    return {
        "file_path": str(source_path),
        "file_name": source_path.name,
        "file_type": normalized_type,
        "phase": phase,
        "phase_bucket": phase_bucket,
        "category": category,
        "tag": tag,
        "raw_text": raw_text,
        "security_findings": security_findings,
        "source_map": [
            {
                "file_name": source_path.name,
                "file_path": str(source_path),
                "category": category,
                "phase_bucket": phase_bucket,
            }
        ],
        "errors": [],
    }


def ingest_documents(documents: list[dict[str, Any]]) -> dict[str, Any]:
    ingested_documents: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []

    for document in documents:
        file_path = str(document["file_path"])
        file_type = str(document.get("file_type") or Path(file_path).suffix.lstrip("."))
        phase = _optional_string(document.get("phase"))
        tag = _optional_string(document.get("tag"))

        try:
            ingested_documents.append(
                ingest_document(
                    file_path=file_path,
                    file_type=file_type,
                    phase=phase,
                    tag=tag,
                )
            )
        except Exception as exc:
            errors.append(
                {
                    "file_path": file_path,
                    "file_type": file_type,
                    "phase": phase or "",
                    "tag": tag or "",
                    "error": str(exc),
                }
            )

    merged_security_findings = _empty_security_findings()
    evidence_by_category = _initialize_evidence_by_category()
    source_map: list[dict[str, Any]] = []
    merged_raw_text_parts: list[str] = []

    for document in ingested_documents:
        merged_raw_text_parts.append(
            _format_document_for_merge(
                file_name=document["file_name"],
                category=document["category"],
                phase_bucket=document["phase_bucket"],
                raw_text=document["raw_text"],
            )
        )
        source_map.extend(document["source_map"])

        category = document["category"]
        if category in evidence_by_category:
            evidence_by_category[category].append(
                {
                    "file_name": document["file_name"],
                    "file_path": document["file_path"],
                    "phase_bucket": document["phase_bucket"],
                    "raw_text": document["raw_text"],
                }
            )

        for key, values in document["security_findings"].items():
            if isinstance(values, list):
                merged_security_findings[key].extend(values)
                if key in evidence_by_category and values:
                    evidence_by_category[key].append(
                        {
                            "file_name": document["file_name"],
                            "file_path": document["file_path"],
                            "phase_bucket": document["phase_bucket"],
                            "findings": values,
                        }
                    )

    return {
        "documents": ingested_documents,
        "errors": errors,
        "raw_text": "\n\n".join(part for part in merged_raw_text_parts if part).strip(),
        "security_findings": merged_security_findings,
        "evidence_by_category": evidence_by_category,
        "source_map": source_map,
    }


def _extract_sarif_results(runs: list[Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    for run in runs:
        if not isinstance(run, dict):
            continue

        tool = run.get("tool") or {}
        driver = tool.get("driver") if isinstance(tool, dict) else {}
        tool_name = driver.get("name", "") if isinstance(driver, dict) else ""

        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue

            message = result.get("message") or {}
            locations = result.get("locations") or []
            results.append(
                {
                    "rule_id": result.get("ruleId", ""),
                    "level": result.get("level", ""),
                    "message": message.get("text", "") if isinstance(message, dict) else "",
                    "tool": tool_name,
                    "locations": locations if isinstance(locations, list) else [],
                }
            )

    return results


def categorize_document(
    file_path: str,
    file_type: str,
    phase: str | None = None,
    tag: str | None = None,
    json_data: dict[str, Any] | None = None,
) -> str:
    normalized_tag = _normalize_alias(tag)
    if normalized_tag:
        return normalized_tag

    normalized_phase = _normalize_phase_bucket(phase)
    normalized_type = file_type.strip().lower().lstrip(".")
    lower_name = Path(file_path).name.lower()

    if normalized_type == "sarif":
        return "sast"

    if normalized_type == "json" and isinstance(json_data, dict):
        if isinstance(json_data.get("runs"), list):
            return "sast"
        if any(isinstance(json_data.get(key), list) for key in ("alerts", "vulnerabilities", "findings")):
            if normalized_phase == "pre_release":
                return "dast"
            if normalized_phase == "in_development":
                return "sast"

    for category, hints in FILENAME_CATEGORY_HINTS.items():
        if any(hint in lower_name for hint in hints):
            return category

    if normalized_phase == "planning":
        return "architecture"
    if normalized_phase == "in_development":
        return "source_code"
    if normalized_phase == "pre_release":
        return "dast"

    return "manual_review"


def infer_phase_bucket(phase: str | None, category: str) -> str:
    normalized_phase = _normalize_phase_bucket(phase)
    if normalized_phase:
        return normalized_phase

    if category in {"architecture", "data_flows"}:
        return "planning"
    if category in {"sast", "sca", "infrastructure"}:
        return "in_development"
    if category == "dast":
        return "pre_release"
    return "general"


def _empty_security_findings() -> dict[str, list[Any]]:
    return {key: [] for key in DEFAULT_SECURITY_FINDINGS}


def _initialize_evidence_by_category() -> dict[str, list[dict[str, Any]]]:
    return {
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


def _format_document_for_merge(
    file_name: str,
    category: str,
    phase_bucket: str,
    raw_text: str,
) -> str:
    cleaned_text = raw_text.strip()
    if not cleaned_text:
        return ""

    return (
        f"[Source: {file_name}]\n"
        f"[Category: {category}]\n"
        f"[Phase: {phase_bucket}]\n"
        f"{cleaned_text}"
    )


def _normalize_alias(value: str | None) -> str | None:
    if not value:
        return None

    normalized_value = value.strip().lower().replace(" ", "_").replace("-", "_")
    return TAG_CATEGORY_ALIASES.get(normalized_value)


def _normalize_phase_bucket(phase: str | None) -> str | None:
    if not phase:
        return None

    normalized_phase = phase.strip().lower().replace(" ", "_").replace("-", "_").replace("/", "_")
    normalized_phase = "_".join(part for part in normalized_phase.split("_") if part)

    if normalized_phase in {"planning", "plan", "pre_development"}:
        return "planning"
    if normalized_phase in {"in_development", "development", "dev"}:
        return "in_development"
    if normalized_phase in {"pre_release", "testing", "pre_release_testing"}:
        return "pre_release"
    return "general"


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return str(value)
