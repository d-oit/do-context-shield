#!/usr/bin/env python3
"""Strict crates.io version verification used by the release preflight."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Iterable
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

PackageVersion = tuple[str, str]
USER_AGENT = "do-context-shield-release-preflight/1.0"
CRATES_IO_API = "https://crates.io/api/v1/crates"


class MissingCrateVersionsError(Exception):
    """Raised when one or more expected package versions are absent."""

    def __init__(self, missing: list[PackageVersion]) -> None:
        self.missing = missing
        super().__init__(", ".join(f"{name}@{version}" for name, version in missing))


class RegistryCheckError(Exception):
    """Raised when registry state cannot be validated reliably."""


def verify_crate_versions(
    package_versions: Iterable[PackageVersion],
    *,
    opener: Callable[..., object] | None = None,
    timeout: float = 15.0,
) -> None:
    """Require every requested crates.io package version to be present.

    A 404 is a missing package/version. Network failures, unexpected HTTP
    statuses, and malformed responses are errors rather than missing results.
    """
    packages = list(package_versions)
    if not packages:
        raise RegistryCheckError("no package versions were supplied")

    open_url = opener or urlopen
    missing: list[PackageVersion] = []
    for crate, version in packages:
        if not crate or not version:
            raise RegistryCheckError("package names and versions must be non-empty")

        url = f"{CRATES_IO_API}/{quote(crate, safe='')}/{quote(version, safe='')}"
        request = Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with open_url(request, timeout=timeout) as response:
                status = response.status
                body = response.read()
        except HTTPError as error:
            if error.code == 404:
                missing.append((crate, version))
                continue
            raise RegistryCheckError(
                f"{crate}@{version}: crates.io returned HTTP {error.code}"
            ) from None
        except (URLError, TimeoutError, OSError, HTTPException) as error:
            reason = error.reason if isinstance(error, URLError) else error
            raise RegistryCheckError(
                f"{crate}@{version}: crates.io request failed: {reason}"
            ) from None

        if status == 404:
            missing.append((crate, version))
            continue
        if status != 200:
            raise RegistryCheckError(
                f"{crate}@{version}: crates.io returned HTTP {status}"
            )

        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError) as error:
            raise RegistryCheckError(
                f"{crate}@{version}: crates.io returned invalid JSON: {error}"
            ) from None

        published = payload.get("version") if isinstance(payload, dict) else None
        if (
            not isinstance(published, dict)
            or published.get("crate") != crate
            or published.get("num") != version
        ):
            raise RegistryCheckError(
                f"{crate}@{version}: crates.io response did not match the requested package version"
            )

    if missing:
        raise MissingCrateVersionsError(missing)


def main(arguments: list[str] | None = None) -> int:
    """Check package specifications passed as ``crate@version`` arguments."""
    specifications = sys.argv[1:] if arguments is None else arguments
    if not specifications:
        print("usage: check_crates_io_versions.py crate@version [...]", file=sys.stderr)
        return 2

    package_versions: list[PackageVersion] = []
    for specification in specifications:
        crate, separator, version = specification.partition("@")
        if not separator or not crate or not version:
            print(
                f"FAIL: invalid package version specification: {specification!r}",
                file=sys.stderr,
            )
            return 2
        package_versions.append((crate, version))

    try:
        verify_crate_versions(package_versions)
    except MissingCrateVersionsError as error:
        for crate, version in error.missing:
            print(
                f"FAIL: {crate}@{version} is not published on crates.io",
                file=sys.stderr,
            )
        return 1
    except RegistryCheckError as error:
        print(f"FAIL: crates.io verification failed: {error}", file=sys.stderr)
        return 1

    print(
        f"crates.io: verified {len(package_versions)} release package versions."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
