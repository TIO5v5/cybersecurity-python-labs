"""CLI entry point for Lab 04 NVD CVE analyzer."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import requests

from Labs.lab4 import analysis, api_client
from shared.student import VARIANT_NUMBER

CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")


def load_response(path: Path | str) -> Any:
    """Read and parse a UTF-8 JSON file containing an NVD API response."""
    file_path = Path(path)
    content = file_path.read_text(encoding="utf-8")
    return json.loads(content)


def _is_valid_variant(variant: Any) -> bool:
    return (
        not isinstance(variant, bool)
        and isinstance(variant, int)
        and 1 <= variant <= 15
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze an NVD CVE record according to the variant rule."
    )
    parser.add_argument(
        "--cve",
        required=True,
        help="CVE identifier in the format CVE-YYYY-NNNN.",
    )
    parser.add_argument(
        "--input",
        dest="input_path",
        default=None,
        help="Optional path to a local UTF-8 JSON NVD response file.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI utility and return the process exit code."""
    if not _is_valid_variant(VARIANT_NUMBER):
        print(
            "Error: VARIANT_NUMBER must be an integer between 1 and 15.",
            file=sys.stderr,
        )
        return 2

    parser = _build_parser()
    args = parser.parse_args(argv)

    cve_id: str = args.cve
    if not CVE_PATTERN.fullmatch(cve_id):
        print(
            "Error: --cve must match the format CVE-YYYY-NNNN (uppercase).",
            file=sys.stderr,
        )
        return 2

    try:
        if args.input_path is not None:
            payload = load_response(args.input_path)
        else:
            payload = api_client.fetch_response(cve_id)
    except (OSError, UnicodeDecodeError):
        print("Error: failed to read the input file.", file=sys.stderr)
        return 1
    except (json.JSONDecodeError, requests.exceptions.JSONDecodeError):
        print("Error: response body is not valid JSON.", file=sys.stderr)
        return 1
    except requests.exceptions.Timeout:
        print("Error: network request timed out.", file=sys.stderr)
        return 1
    except requests.exceptions.ConnectionError:
        print("Error: failed to connect to the NVD API.", file=sys.stderr)
        return 1
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        print(f"Error: NVD API returned HTTP status {status}.", file=sys.stderr)
        return 1
    except requests.exceptions.RequestException:
        print(
            "Error: unexpected network error while querying the NVD API.",
            file=sys.stderr,
        )
        return 1

    try:
        record = analysis.extract_record(payload, cve_id)
        report = analysis.build_report(record, cve_id, VARIANT_NUMBER)
    except ValueError as exc:
        print(f"Error: invalid response data ({exc}).", file=sys.stderr)
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
