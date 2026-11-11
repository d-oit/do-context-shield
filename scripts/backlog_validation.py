#!/usr/bin/env python3
"""Validate active backlog status metadata and local Markdown references."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
BACKLOG_PATH = Path("plans/backlog.md")
DECISIONS_PATH = Path("docs/decisions")
EVIDENCE_PATH = Path("docs/test-evidence")
SECTION_STATUSES = {
    "Active work": "active",
    "External blockers": "blocked",
    "Residual risks": "residual-risk",
}
# Remove a required item only after its blocker or residual is explicitly resolved.
REQUIRED_ITEMS = {
    "Issue #188: approval to rerun the release workflow": "blocked",
    "Claude Code end-to-end client probe": "blocked",
    "Glued-only secret occurrences can evade detection": "residual-risk",
}
ALLOWED_STATUSES = set(SECTION_STATUSES.values())
SECTION_RE = re.compile(r"^##\s+(.+?)\s*$")
ENTRY_RE = re.compile(r"^###\s+(.+?)\s*$")
STATUS_RE = re.compile(r"^\s*-\s+\*\*Status\*\*:\s*(.*?)\s*$")
LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]*)\)")
HEADING_RE = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$")


def validate_backlog(text: str) -> list[str]:
    """Validate heading categories and exactly one matching status per item."""
    errors: list[str] = []
    first_content = next((line for line in text.splitlines() if line.strip()), "")
    if first_content != "# Backlog":
        errors.append("backlog must begin with '# Backlog'")

    current_section: str | None = None
    current_entry: tuple[str, str | None, list[str]] | None = None
    entries: list[tuple[str, str | None, list[str]]] = []
    seen_sections: set[str] = set()

    def finish_entry() -> None:
        nonlocal current_entry
        if current_entry is not None:
            entries.append(current_entry)
            current_entry = None

    for line in text.splitlines():
        section_match = SECTION_RE.match(line)
        if section_match:
            finish_entry()
            section = section_match.group(1)
            if section not in SECTION_STATUSES:
                errors.append(f"unsupported backlog section '{section}'")
                current_section = None
            else:
                if section in seen_sections:
                    errors.append(f"duplicate backlog section '{section}'")
                seen_sections.add(section)
                current_section = section
            continue

        entry_match = ENTRY_RE.match(line)
        if entry_match:
            finish_entry()
            title = entry_match.group(1)
            if current_section is None:
                errors.append(f"entry '{title}' is outside a supported backlog section")
            current_entry = (title, current_section, [])
            continue

        status_match = STATUS_RE.match(line)
        if status_match:
            if current_entry is None:
                errors.append("status metadata appears outside a backlog entry")
            else:
                current_entry[2].append(status_match.group(1))

    finish_entry()
    if not entries:
        errors.append("backlog must contain at least one categorized entry")

    for title, section, statuses in entries:
        if len(statuses) != 1:
            errors.append(f"entry '{title}' must declare exactly one status")
            continue
        status = statuses[0]
        if status not in ALLOWED_STATUSES:
            errors.append(f"entry '{title}' has unsupported status '{status}'")
            continue
        expected = SECTION_STATUSES.get(section or "")
        if expected is None:
            continue
        if status != expected:
            errors.append(f"entry '{title}' is under '{section}' but requires status '{expected}'")
    observed = {title: statuses[0] for title, _, statuses in entries if len(statuses) == 1}
    for title, expected in REQUIRED_ITEMS.items():
        actual = observed.get(title)
        if actual is None:
            errors.append(f"required open item '{title}' is missing or has invalid status metadata")
        elif actual != expected:
            errors.append(f"required open item '{title}' must remain status '{expected}'")
    return errors


def _heading_anchors(text: str) -> set[str]:
    anchors: set[str] = set()
    counts: dict[str, int] = {}
    for line in text.splitlines():
        match = HEADING_RE.match(line)
        if not match:
            continue
        slug = re.sub(r"[^\w -]", "", match.group(1).lower()).strip()
        slug = re.sub(r"\s+", "-", slug)
        count = counts.get(slug, 0)
        counts[slug] = count + 1
        anchors.add(slug if count == 0 else f"{slug}-{count}")
    return anchors


def _markdown_sources(root: Path) -> list[Path]:
    sources = [root / BACKLOG_PATH]
    for directory in (DECISIONS_PATH, EVIDENCE_PATH):
        path = root / directory
        if path.is_dir():
            sources.extend(sorted(path.rglob("*.md")))
    return sources


def _validate_links(root: Path, sources: list[Path]) -> list[str]:
    errors: list[str] = []
    root = root.resolve()
    for source in sources:
        if not source.is_file():
            errors.append(f"missing Markdown source '{source.relative_to(root)}'")
            continue
        try:
            text = source.read_text(encoding="utf-8")
        except OSError as error:
            errors.append(f"cannot read Markdown source '{source.relative_to(root)}': {error}")
            continue
        for raw_target in LINK_RE.findall(text):
            target_text = raw_target.strip()
            if target_text.startswith("<") and ">" in target_text:
                target_text = target_text[1 : target_text.index(">")].strip()
            elif target_text:
                target_text = target_text.split(maxsplit=1)[0]
            if not target_text:
                errors.append(f"empty local link target in '{source.relative_to(root)}'")
                continue
            try:
                parsed = urlsplit(target_text)
            except ValueError:
                errors.append(f"invalid link target in '{source.relative_to(root)}': {raw_target}")
                continue
            if parsed.scheme or parsed.netloc:
                continue
            target_name = unquote(parsed.path)
            if target_name.startswith("/"):
                target = (root / target_name.lstrip("/")).resolve()
            elif target_name:
                target = (source.parent / target_name).resolve()
            else:
                target = source.resolve()
            if not target.is_relative_to(root):
                errors.append(f"link escapes repository in '{source.relative_to(root)}': {raw_target}")
                continue
            if not target.is_file():
                errors.append(f"missing local link target in '{source.relative_to(root)}': {raw_target}")
                continue
            if parsed.fragment and target.suffix.lower() == ".md":
                try:
                    anchors = _heading_anchors(target.read_text(encoding="utf-8"))
                except OSError as error:
                    errors.append(f"cannot read link target '{target.relative_to(root)}': {error}")
                    continue
                fragment = unquote(parsed.fragment).lower()
                if fragment not in anchors:
                    errors.append(
                        f"missing heading anchor '{fragment}' in '{target.relative_to(root)}'"
                    )
    return errors


def validate_repository(root: Path) -> list[str]:
    """Validate the active backlog and links in its historical records."""
    root = root.resolve()
    backlog = root / BACKLOG_PATH
    if not backlog.is_file():
        return [f"missing active backlog '{BACKLOG_PATH}'"]
    try:
        text = backlog.read_text(encoding="utf-8")
    except OSError as error:
        return [f"cannot read active backlog '{BACKLOG_PATH}': {error}"]
    return validate_backlog(text) + _validate_links(root, _markdown_sources(root))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root to validate")
    args = parser.parse_args()
    errors = validate_repository(args.root)
    if errors:
        for error in errors:
            print(f"backlog validation: ERROR: {error}", file=sys.stderr)
        return 1
    print("backlog validation: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
