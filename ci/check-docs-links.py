#!/usr/bin/env python3
"""Relative link checker for the Markdown documentation.

Checks every `[text](target)` link, reference-style definition and HTML `src` / `srcset` /
`href` attribute in the repository's Markdown files. A relative target must exist; a target
with a `#fragment` that points at a Markdown file must match one of that file's headings
(GitHub slug rules). External links (`http:`, `https:`, `mailto:`) are not fetched. Code
fences and inline code are ignored.

Usage: ci/check-docs-links.py [PATH ...]   (default: every Markdown file git lists)
Exit status: 0 clean, 1 on any broken link. Output: `file:line: broken link: target`.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

INLINE = re.compile(r"(?<!\\)!?\[(?:[^\[\]]|\[[^\]]*\])*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
REFDEF = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+.*)?$")
HTML_ATTR = re.compile(r"""\b(?:src|srcset|href)\s*=\s*["']([^"']+)["']""")
FENCE = re.compile(r"^\s*(```|~~~)")
CODE_SPAN = re.compile(r"`[^`]*`")
HEADING = re.compile(r"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$")
EXTERNAL = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*:|//)")


def markdown_files(args: list[str]) -> list[Path]:
    if args:
        return [Path(a) for a in args]
    out = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "*.md"],
        check=True,
        capture_output=True,
    ).stdout
    return [Path(p) for p in out.decode().split("\0") if p]


def slug(heading: str) -> str:
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    text = re.sub(r"[`*~]", "", text).strip().lower()
    text = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
    return text.replace(" ", "-")


_anchor_cache: dict[Path, set[str]] = {}


def anchors(path: Path) -> set[str]:
    if path in _anchor_cache:
        return _anchor_cache[path]
    found: set[str] = set()
    seen: dict[str, int] = {}
    in_fence = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = HEADING.match(line)
        if not m:
            continue
        base = slug(m.group(2))
        count = seen.get(base, 0)
        seen[base] = count + 1
        found.add(base if count == 0 else f"{base}-{count}")
    _anchor_cache[path] = found
    return found


def targets(line: str):
    stripped = CODE_SPAN.sub("", line)
    for m in INLINE.finditer(stripped):
        yield m.group(1)
    m = REFDEF.match(stripped)
    if m:
        yield m.group(1)
    for m in HTML_ATTR.finditer(stripped):
        for part in m.group(1).split(","):
            candidate = part.strip().split(" ")[0]
            if candidate:
                yield candidate


def check(path: Path) -> list[str]:
    problems: list[str] = []
    in_fence = False
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for target in targets(line):
            if EXTERNAL.match(target):
                continue
            base, _, fragment = target.partition("#")
            resolved = path if not base else (path.parent / base.split("?")[0])
            if base.startswith("/"):
                resolved = Path(base.lstrip("/"))
            if not resolved.exists():
                problems.append(f"{path.as_posix()}:{number}: broken link: {target}")
                continue
            if fragment and resolved.is_file() and resolved.suffix == ".md":
                if fragment.lower() not in anchors(resolved):
                    problems.append(f"{path.as_posix()}:{number}: broken anchor: {target}")
    return problems


def main(argv: list[str]) -> int:
    problems: list[str] = []
    for path in markdown_files(argv):
        if path.is_file():
            problems.extend(check(path))
    for problem in problems:
        print(problem)
    if problems:
        print(f"check-docs-links: {len(problems)} problem(s)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
