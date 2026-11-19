"""Unit tests for the NVD API HTTP client."""

from __future__ import annotations

from unittest.mock import Mock

import pytest
import requests

from Labs.lab4 import api_client


def test_build_headers_without_key() -> None:
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_build_headers_with_key_trimmed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NVD_API_KEY", "  fake-test-key  ")
    assert api_client.build_headers() == {
        "Accept": "application/json",
        "apiKey": "fake-test-key",
    }


def test_build_headers_ignores_blank_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NVD_API_KEY", "   ")
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_fetch_uses_expected_request(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.headers = {"Content-Type": "application/json; charset=utf-8"}
    response.json.return_value = payload

    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    assert api_client.fetch_response("CVE-2099-10001") == payload
    fake_get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": "CVE-2099-10001"},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_fetch_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    response = Mock(spec=requests.Response)
    response.status_code = 500
    response.raise_for_status.side_effect = requests.HTTPError(
        "500 Server Error", response=response
    )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))

    with pytest.raises(requests.HTTPError):
        api_client.fetch_response("CVE-2099-10001")


def test_fetch_timeout_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        api_client.requests,
        "get",
        Mock(side_effect=requests.Timeout("timed out")),
    )
    with pytest.raises(requests.Timeout):
        api_client.fetch_response("CVE-2099-10001")


def test_fetch_invalid_json(monkeypatch: pytest.MonkeyPatch) -> None:
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))

    with pytest.raises(requests.exceptions.JSONDecodeError):
        api_client.fetch_response("CVE-2099-10001")
