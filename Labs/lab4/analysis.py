"""Validation of NVD API payloads and variant-based vulnerability analysis."""

from __future__ import annotations

import math
from typing import Any, NoReturn

ALLOWED_FIELD_VALUES: dict[str, set[str]] = {
    "attackVector": {"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"},
    "attackComplexity": {"LOW", "HIGH"},
    "privilegesRequired": {"NONE", "LOW", "HIGH"},
    "userInteraction": {"NONE", "REQUIRED"},
    "scope": {"UNCHANGED", "CHANGED"},
    "confidentialityImpact": {"NONE", "LOW", "HIGH"},
    "integrityImpact": {"NONE", "LOW", "HIGH"},
    "availabilityImpact": {"NONE", "LOW", "HIGH"},
}

VARIANT_RULES: dict[int, dict[str, Any]] = {
    1: {"threshold": 7.0, "field": "attackVector", "expected": "NETWORK"},
    2: {"threshold": 8.0, "field": "attackComplexity", "expected": "LOW"},
    3: {"threshold": 7.0, "field": "privilegesRequired", "expected": "NONE"},
    4: {"threshold": 8.0, "field": "userInteraction", "expected": "NONE"},
    5: {"threshold": 7.0, "field": "confidentialityImpact", "expected": "HIGH"},
    6: {"threshold": 7.0, "field": "integrityImpact", "expected": "HIGH"},
    7: {"threshold": 7.0, "field": "availabilityImpact", "expected": "HIGH"},
    8: {"threshold": 9.0, "field": "scope", "expected": "CHANGED"},
    9: {"threshold": 5.0, "field": "attackVector", "expected": "LOCAL"},
    10: {"threshold": 6.0, "field": "privilegesRequired", "expected": "LOW"},
    11: {"threshold": 6.0, "field": "userInteraction", "expected": "REQUIRED"},
    12: {"threshold": 6.0, "field": "confidentialityImpact", "expected": "LOW"},
    13: {"threshold": 6.0, "field": "integrityImpact", "expected": "LOW"},
    14: {"threshold": 6.0, "field": "availabilityImpact", "expected": "LOW"},
    15: {"threshold": 8.0, "field": "attackComplexity", "expected": "HIGH"},
}


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _validate_optional_non_empty_str(container: dict[str, Any], key: str) -> str | None:
    if key not in container:
        return None
    value = container[key]
    if not isinstance(value, str) or not value.strip():
        _fail(f"Field '{key}' must be a non-empty string.")
    return value


def _extract_english_description(cve: dict[str, Any]) -> str | None:
    if "descriptions" not in cve:
        return None
    descriptions = cve["descriptions"]
    if not isinstance(descriptions, list):
        _fail("Field 'descriptions' must be a list.")

    english_description: str | None = None
    for item in descriptions:
        if not isinstance(item, dict):
            _fail("Each description entry must be a dict.")
        lang = item.get("lang")
        value = item.get("value")
        if not isinstance(lang, str) or not isinstance(value, str):
            _fail("Description 'lang' and 'value' must be strings.")
        if english_description is None and lang == "en" and value.strip():
            english_description = value
    return english_description


def _extract_cvss_v31(cve: dict[str, Any]) -> dict[str, Any] | None:
    if "metrics" not in cve:
        return None
    metrics = cve["metrics"]
    if not isinstance(metrics, dict):
        _fail("Field 'metrics' must be a dict.")

    if "cvssMetricV31" not in metrics:
        return None
    cvss_list = metrics["cvssMetricV31"]
    if not isinstance(cvss_list, list):
        _fail("Field 'cvssMetricV31' must be a list.")
    if not cvss_list:
        return None

    for entry in cvss_list:
        if not isinstance(entry, dict):
            _fail("Each entry in 'cvssMetricV31' must be a dict.")

    selected = next(
        (entry for entry in cvss_list if entry.get("type") == "Primary"),
        cvss_list[0],
    )

    cvss_data = selected.get("cvssData")
    if not isinstance(cvss_data, dict):
        _fail("Selected CVSS entry must contain a 'cvssData' dict.")

    score = cvss_data.get("baseScore")
    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(score)
        or not (0.0 <= float(score) <= 10.0)
    ):
        _fail("Field 'baseScore' must be a finite number between 0 and 10.")

    version = _validate_optional_non_empty_str(cvss_data, "version")
    if version is not None and version != "3.1":
        _fail("Field 'cvssData.version' must equal '3.1' when present.")

    vector = _validate_optional_non_empty_str(cvss_data, "vectorString")
    source = _validate_optional_non_empty_str(selected, "source")

    return {
        "cvss_version": version,
        "score": float(score),
        "score_source": source,
        "vector": vector,
        "cvss_data": dict(cvss_data),
    }


def extract_record(payload: Any, cve_id: str) -> dict[str, Any] | None:
    """Validate an NVD API payload and extract an internal vulnerability record.

    Returns None when 'vulnerabilities' is empty. Otherwise returns a dict:
        {
            "cve_id": str,
            "description": str | None,
            "vuln_status": str | None,
            "cvss": {
                "cvss_version": str | None,
                "score": float,
                "score_source": str | None,
                "vector": str | None,
                "cvss_data": dict[str, Any],
            } | None,
        }
    """
    if not isinstance(payload, dict):
        _fail("Payload must be a JSON object.")

    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or len(vulnerabilities) > 1:
        _fail("Field 'vulnerabilities' must be a list of 0 or 1 item.")

    if not vulnerabilities:
        return None

    item = vulnerabilities[0]
    if not isinstance(item, dict):
        _fail("Vulnerability item must be a dict.")

    cve = item.get("cve")
    if not isinstance(cve, dict):
        _fail("Vulnerability item must contain a 'cve' dict.")

    if cve.get("id") != cve_id:
        _fail("Returned CVE ID does not match the requested CVE ID.")

    vuln_status = _validate_optional_non_empty_str(cve, "vulnStatus")
    description = _extract_english_description(cve)

    if vuln_status is None or vuln_status == "Rejected":
        return {
            "cve_id": cve_id,
            "description": description,
            "vuln_status": vuln_status,
            "cvss": None,
        }

    cvss = _extract_cvss_v31(cve)
    return {
        "cve_id": cve_id,
        "description": description,
        "vuln_status": vuln_status,
        "cvss": cvss,
    }


def build_report(
    record: dict[str, Any] | None,
    cve_id: str,
    variant: int,
) -> dict[str, Any]:
    """Apply the variant rule to an extracted record and build the report dict."""
    if (
        isinstance(variant, bool)
        or not isinstance(variant, int)
        or variant not in VARIANT_RULES
    ):
        _fail("Variant must be an integer between 1 and 15.")

    rule = dict(VARIANT_RULES[variant])
    report: dict[str, Any] = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": rule,
        "observed": None,
        "decision": "not_found",
    }

    if record is None:
        return report

    vuln_status = record.get("vuln_status")
    report["description"] = record.get("description")
    report["vuln_status"] = vuln_status

    if vuln_status == "Rejected":
        report["decision"] = "rejected"
        return report

    if vuln_status is None:
        report["decision"] = "insufficient_data"
        return report

    cvss = record.get("cvss")
    if cvss is None:
        report["decision"] = "insufficient_data"
        return report

    report["cvss_version"] = cvss["cvss_version"]
    report["score"] = cvss["score"]
    report["score_source"] = cvss["score_source"]
    report["vector"] = cvss["vector"]

    field = rule["field"]
    cvss_data = cvss["cvss_data"]
    if field not in cvss_data:
        report["decision"] = "insufficient_data"
        return report

    observed = cvss_data[field]
    allowed = ALLOWED_FIELD_VALUES[field]
    if not isinstance(observed, str) or observed not in allowed:
        _fail(f"Invalid value for CVSS field '{field}'.")

    report["observed"] = observed
    if cvss["score"] >= rule["threshold"] and observed == rule["expected"]:
        report["decision"] = "review"
    else:
        report["decision"] = "other"

    return report
