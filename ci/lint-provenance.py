#!/usr/bin/env python3
"""Public-tree hygiene gate: fail when a file carries a reference that must not be public.

The names this repository must not contain cannot be listed here without defeating the rule,
so ci/provenance-hashes.txt stores only SHA-256 hashes of lowercase terms:

    word<TAB><sha256>            a whole word or one camelCase segment
    substr<TAB><len><TAB><sha256>   any window of <len> characters of the lowercased text

Words are split on non-alphanumerics and on lower-to-upper camel-case boundaries, so `foo_bar`,
`FooBar`, `foo-bar` and `FOO_BAR` are all checked. Substring rules slide a window of the stored
length over every lowercased line and path.

Further rules:

* `host-path`: absolute paths of a developer machine (workspace, home and user-profile roots);
* `privileged-pr-trigger`: the privileged fork-PR workflow trigger, which this repository does
  not use;
* `internal-citation`: citations of internal design records or plan directories
  (numbered decision records, plan or decision-record directories);
* `maintainer-handle`: the maintainer's account name may appear only in `.github/CODEOWNERS`;
* `email-address`: e-mail addresses other than clearly synthetic ones (`example.*`, `*.test`,
  `*.invalid`, `localhost`).

Usage: ci/lint-provenance.py [PATH ...]
Default: every file `git ls-files` lists plus untracked files that are not ignored.
Exit status: 0 clean, 1 on any hit, 2 when the hash file is missing or malformed. Hits print as
`file:line: [rule]` without the matched text, so CI logs never spell a retired name.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
from pathlib import Path

HASH_FILE = Path(__file__).with_name("provenance-hashes.txt")

WORD = re.compile(r"[A-Za-z0-9]+")
CAMEL = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
SKIP_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".gz", ".zip", ".tar", ".der",
    ".pdf", ".db", ".snap",
}
SKIP_NAMES = {"Cargo.lock", "package-lock.json", "uv.lock", "LICENSE"}
MAX_BYTES = 4 * 1024 * 1024

# Absolute developer-machine paths. The look-behind keeps relative paths and URL segments out.
HOST_PATH = re.compile(r"(?<![A-Za-z0-9_.~:@-])/(?:data|home|Users)/")
PRIVILEGED_TRIGGER = re.compile(r"pull_request_targe[t]")
CITATION = re.compile(r"\bAD[R]-\d+\b|docs/plan[s]/|docs/ad[r]/")
HANDLE = re.compile(r"kaan-zero" + r"day", re.IGNORECASE)
HANDLE_ALLOWED = {".github/CODEOWNERS"}
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b")
EMAIL_OK_DOMAIN = re.compile(r"(?:^|\.)example(?:\.[a-z]+)?$|\.test$|\.invalid$|^localhost$", re.IGNORECASE)


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def load_rules() -> tuple[set[str], dict[int, set[str]]]:
    words: set[str] = set()
    substrings: dict[int, set[str]] = {}
    try:
        raw = HASH_FILE.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        print(f"lint-provenance: cannot read {HASH_FILE.name}: {exc}", file=sys.stderr)
        raise SystemExit(2)
    for number, line in enumerate(raw, 1):
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        digest = parts[-1]
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            bad(number)
        if parts[0] == "word" and len(parts) == 2:
            words.add(digest)
        elif parts[0] == "substr" and len(parts) == 3 and parts[1].isdigit() and int(parts[1]) > 0:
            substrings.setdefault(int(parts[1]), set()).add(digest)
        else:
            bad(number)
    return words, substrings


def bad(number: int) -> None:
    print(f"lint-provenance: {HASH_FILE.name}:{number}: malformed rule", file=sys.stderr)
    raise SystemExit(2)


def tokens(text: str):
    for word in WORD.findall(text):
        yield word.lower()
        parts = CAMEL.findall(word)
        if len(parts) > 1:
            for part in parts:
                yield part.lower()


class Rules:
    def __init__(self) -> None:
        self.words, self.substrings = load_rules()

    def matches(self, text: str) -> bool:
        """True when `text` carries a hashed word or substring term."""
        if any(sha(t) in self.words for t in tokens(text)):
            return True
        lowered = text.lower()
        for length, digests in self.substrings.items():
            for start in range(len(lowered) - length + 1):
                if sha(lowered[start : start + length]) in digests:
                    return True
        return False


def files(args: list[str]) -> list[Path]:
    if args:
        return [Path(a) for a in args]
    out = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        check=True,
        capture_output=True,
    ).stdout
    return [Path(p) for p in out.decode().split("\0") if p]


def main(argv: list[str]) -> int:
    rules = Rules()
    hits = 0

    def report(label: str, number: int | None, rule: str) -> None:
        nonlocal hits
        where = label if number is None else f"{label}:{number}"
        print(f"{where}: [{rule}]")
        hits += 1

    for path in files(argv):
        label = path.as_posix()
        if not path.is_file() or path.is_symlink():
            continue
        if path.suffix in SKIP_SUFFIXES or path.name in SKIP_NAMES or path.name == HASH_FILE.name:
            continue
        if rules.matches(label):
            report(label, None, "retired-name in path")
        if path.stat().st_size > MAX_BYTES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        handle_ok = label in HANDLE_ALLOWED
        for number, line in enumerate(text.splitlines(), 1):
            if rules.matches(line):
                report(label, number, "retired-name")
            if HOST_PATH.search(line):
                report(label, number, "host-path")
            if PRIVILEGED_TRIGGER.search(line):
                report(label, number, "privileged-pr-trigger")
            if CITATION.search(line):
                report(label, number, "internal-citation")
            if HANDLE.search(line) and not handle_ok:
                report(label, number, "maintainer-handle")
            if any(not EMAIL_OK_DOMAIN.search(m.group(1)) for m in EMAIL.finditer(line)):
                report(label, number, "email-address")
    if hits:
        print(f"lint-provenance: {hits} hit(s)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
