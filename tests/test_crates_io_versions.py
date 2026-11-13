#!/usr/bin/env python3
"""Behavioral tests for strict crates.io release-version verification."""

from __future__ import annotations

import json
import io
import sys
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from check_crates_io_versions import (  # noqa: E402
    RegistryCheckError,
    main,
    verify_crate_versions,
)


class RegistryResponse:
    def __init__(self, status: int, payload: object) -> None:
        self.status = status
        self.payload = payload

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")

    def __enter__(self) -> RegistryResponse:
        return self

    def __exit__(self, *_: object) -> None:
        return None


class CratesIoVersionTests(unittest.TestCase):
    def test_accepts_the_exact_published_package_version(self) -> None:
        requests = []

        def open_url(request: object, *, timeout: float) -> RegistryResponse:
            requests.append((request, timeout))
            return RegistryResponse(
                200,
                {"version": {"crate": "do-context-shield", "num": "0.1.0"}},
            )

        verify_crate_versions(
            [("do-context-shield", "0.1.0")], opener=open_url
        )

        self.assertEqual(1, len(requests))
        request, timeout = requests[0]
        self.assertEqual(
            "https://crates.io/api/v1/crates/do-context-shield/0.1.0",
            request.full_url,
        )
        self.assertEqual(
            "do-context-shield-release-preflight/1.0",
            request.get_header("User-agent"),
        )
        self.assertGreater(timeout, 0)

    def test_missing_version_is_reported_as_missing(self) -> None:
        output = io.StringIO()
        with patch(
            "check_crates_io_versions.urlopen",
            side_effect=lambda request, timeout: HTTPError(
                request.full_url, 404, "Not Found", None, None
            ),
        ):
            with redirect_stderr(output):
                exit_code = main(["do-context-shield@9.9.9"])

        self.assertEqual(1, exit_code)
        self.assertIn(
            "FAIL: do-context-shield@9.9.9 is not published on crates.io",
            output.getvalue(),
        )

    def test_network_error_fails_closed_instead_of_treating_version_as_missing(self) -> None:
        output = io.StringIO()
        with patch(
            "check_crates_io_versions.urlopen",
            side_effect=URLError("temporary DNS failure"),
        ):
            with redirect_stderr(output):
                exit_code = main(["do-context-shield@0.1.0"])

        self.assertEqual(1, exit_code)
        self.assertIn("crates.io request failed", output.getvalue())
        self.assertIn("temporary DNS failure", output.getvalue())
        self.assertNotIn("is not published", output.getvalue())

    def test_mismatched_registry_response_fails_closed(self) -> None:
        def open_url(request: object, *, timeout: float) -> RegistryResponse:
            return RegistryResponse(
                200,
                {"version": {"crate": "do-context-shield", "num": "0.2.0"}},
            )

        with self.assertRaises(RegistryCheckError):
            verify_crate_versions(
                [("do-context-shield", "0.1.0")], opener=open_url
            )


if __name__ == "__main__":
    unittest.main()
