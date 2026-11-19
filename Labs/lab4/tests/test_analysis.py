"""Unit tests for NVD payload validation and variant 11 analysis rules."""

from __future__ import annotations

from typing import Any

import pytest

from Labs.lab4.analysis import build_report, extract_record

CVE_ID = "CVE-2099-10001"
VARIANT = 11


@pytest.mark.parametrize(
    ("score", "user_interaction", "expected_decision"),
    [
        (5.9, "REQUIRED", "other"),
        (6.0, "REQUIRED", "review"),
        (6.1, "REQUIRED", "review"),
        (9.8, "NONE", "other"),
    ],
)
def test_variant_11_threshold_and_feature(
    sample_payload: dict[str, Any],
    score: float,
    user_interaction: str,
    expected_decision: str,
) -> None:
    cvss_data = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][
        0
    ]["cvssData"]
    cvss_data["baseScore"] = score
    cvss_data["userInteraction"] = user_interaction

    record = extract_record(sample_payload, CVE_ID)
    report = build_report(record, CVE_ID, VARIANT)

    assert report["decision"] == expected_decision
    assert report["score"] == score
    assert report["observed"] == user_interaction


def test_not_found() -> None:
    payload = {"vulnerabilities": []}
    record = extract_record(payload, CVE_ID)
    report = build_report(record, CVE_ID, VARIANT)

    assert record is None
    assert report["decision"] == "not_found"
    assert report["description"] is None
    assert report["score"] is None
    assert report["observed"] is None


def test_rejected_ignores_score(sample_payload: dict[str, Any]) -> None:
    sample_payload["vulnerabilities"][0]["cve"]["vulnStatus"] = "Rejected"
    record = extract_record(sample_payload, CVE_ID)
    report = build_report(record, CVE_ID, VARIANT)

    assert report["decision"] == "rejected"
    assert report["vuln_status"] == "Rejected"
    assert report["score"] is None
    assert report["observed"] is None


def test_missing_metrics_gives_insufficient_data(
    sample_payload: dict[str, Any],
) -> None:
    del sample_payload["vulnerabilities"][0]["cve"]["metrics"]
    record = extract_record(sample_payload, CVE_ID)
    report = build_report(record, CVE_ID, VARIANT)

    assert report["decision"] == "insufficient_data"
    assert report["score"] is None


def test_missing_variant_field_gives_insufficient_data(
    sample_payload: dict[str, Any],
) -> None:
    cvss_data = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][
        0
    ]["cvssData"]
    del cvss_data["userInteraction"]

    record = extract_record(sample_payload, CVE_ID)
    report = build_report(record, CVE_ID, VARIANT)

    assert report["decision"] == "insufficient_data"
    assert report["observed"] is None


@pytest.mark.parametrize("bad_value", [None, "MAYBE", 123])
def test_invalid_variant_field_raises_value_error(
    sample_payload: dict[str, Any],
    bad_value: Any,
) -> None:
    cvss_data = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][
        0
    ]["cvssData"]
    cvss_data["userInteraction"] = bad_value

    record = extract_record(sample_payload, CVE_ID)
    with pytest.raises(ValueError):
        build_report(record, CVE_ID, VARIANT)


def test_primary_priority_over_secondary(sample_payload: dict[str, Any]) -> None:
    primary = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]
    secondary = {
        "source": "secondary@example.invalid",
        "type": "Secondary",
        "cvssData": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
            "userInteraction": "REQUIRED",
            "baseScore": 4.2,
        },
    }
    sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"] = [
        secondary,
        primary,
    ]

    record = extract_record(sample_payload, CVE_ID)
    report = build_report(record, CVE_ID, VARIANT)

    assert report["score"] == 9.8
    assert report["score_source"] == "nvd@nist.gov"


def test_fallback_to_first_when_no_primary(sample_payload: dict[str, Any]) -> None:
    first = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]
    first["type"] = "Secondary"
    first["source"] = "first-secondary@example.invalid"

    record = extract_record(sample_payload, CVE_ID)
    report = build_report(record, CVE_ID, VARIANT)

    assert report["score_source"] == "first-secondary@example.invalid"
