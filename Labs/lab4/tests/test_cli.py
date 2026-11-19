"""Integration tests for the Lab 04 CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from Labs.lab4 import main as cli_main


def test_cli_local_input_success(
    tmp_path: Path,
    sample_payload: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_main, "VARIANT_NUMBER", 11)
    input_file = tmp_path / "sample.json"
    input_file.write_text(json.dumps(sample_payload), encoding="utf-8")

    exit_code = cli_main.main(["--cve", "CVE-2099-10001", "--input", str(input_file)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["cve_id"] == "CVE-2099-10001"
    assert report["variant"] == 11
    assert report["decision"] == "other"


def test_cli_invalid_json_file(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_main, "VARIANT_NUMBER", 11)
    bad_file = tmp_path / "broken.json"
    bad_file.write_text("{not valid json", encoding="utf-8")

    exit_code = cli_main.main(["--cve", "CVE-2099-10001", "--input", str(bad_file)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "JSON" in captured.err


def test_cli_missing_file(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_main, "VARIANT_NUMBER", 11)
    missing = tmp_path / "does_not_exist.json"

    exit_code = cli_main.main(["--cve", "CVE-2099-10001", "--input", str(missing)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "Error" in captured.err


def test_cli_invalid_cve_format(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_main, "VARIANT_NUMBER", 11)

    exit_code = cli_main.main(["--cve", "cve-2099-10001"])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "Error" in captured.err


def test_cli_invalid_variant(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_main, "VARIANT_NUMBER", 99)

    exit_code = cli_main.main(["--cve", "CVE-2099-10001"])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "VARIANT_NUMBER" in captured.err
