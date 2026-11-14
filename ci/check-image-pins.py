#!/usr/bin/env python3
"""Container image pin checker.

Every container image the repository pulls must be pinned by digest (`name:tag@sha256:...`,
the tag stays for humans), so that a moved or compromised tag cannot change what a CI runner
or a released image executes. Checked:

* `FROM` lines of every Dockerfile (a stage name from an earlier `FROM ... AS name` and
  `scratch` are fine);
* every fully qualified registry reference (`docker.io/`, `docker.elastic.co/`, `ghcr.io/`,
  `quay.io/`, `gcr.io/`, `mcr.microsoft.com/`, `public.ecr.aws/`) in scripts, workflows,
  Rust sources and YAML.

Usage: ci/check-image-pins.py
Exit status: 0 clean, 1 on any unpinned image. Output: `file:line: image is not pinned by digest: ref`.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGISTRY_REF = re.compile(
    r"\b((?:docker\.io|docker\.elastic\.co|ghcr\.io|quay\.io|gcr\.io|mcr\.microsoft\.com|public\.ecr\.aws)/[\w./-]+(?::[\w.-]+)?(?:@sha256:[0-9a-f]{64})?)"
)
FROM_LINE = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", re.IGNORECASE)
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
TEXT_SUFFIXES = {".sh", ".rs", ".yml", ".yaml", ".toml", ".py", ".json"}


def tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout.decode()
    return [ROOT / p for p in out.split("\0") if p]


def main() -> int:
    problems: list[str] = []
    for path in tracked_files():
        if not path.is_file() or path == Path(__file__).resolve():
            continue
        is_dockerfile = path.name == "Dockerfile" or path.name.startswith("Dockerfile.")
        if not is_dockerfile and path.suffix not in TEXT_SUFFIXES:
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        rel = path.relative_to(ROOT)
        stages: set[str] = set()
        for number, line in enumerate(lines, 1):
            if is_dockerfile:
                m = FROM_LINE.match(line)
                if m:
                    ref, alias = m.group(1), m.group(2)
                    if ref != "scratch" and ref not in stages and not DIGEST.search(ref):
                        problems.append(f"{rel}:{number}: image is not pinned by digest: {ref}")
                    if alias:
                        stages.add(alias)
                    continue
            for m in REGISTRY_REF.finditer(line):
                ref = m.group(1)
                if not DIGEST.search(ref):
                    problems.append(f"{rel}:{number}: image is not pinned by digest: {ref}")
    for problem in problems:
        print(problem)
    if problems:
        print(f"check-image-pins: {len(problems)} problem(s)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
