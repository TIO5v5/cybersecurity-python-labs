"""HTTP client for querying the NVD CVE API 2.0."""

from __future__ import annotations

import os
from typing import Any

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT: tuple[float, int] = (3.05, 10)


def build_headers() -> dict[str, str]:
    """Build HTTP headers for NVD API requests, including optional apiKey."""
    headers = {"Accept": "application/json"}
    raw_key = os.getenv("NVD_API_KEY")
    if raw_key is not None:
        api_key = raw_key.strip()
        if api_key:
            headers["apiKey"] = api_key
    return headers


def fetch_response(cve_id: str) -> Any:
    """Fetch a single CVE response payload from the NVD API."""
    response = requests.get(
        NVD_API_URL,
        params={"cveId": cve_id},
        headers=build_headers(),
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,
    )
    response.raise_for_status()
    if response.status_code != 200:
        raise requests.HTTPError(
            f"Unexpected HTTP status code: {response.status_code}",
            response=response,
        )
    return response.json()
