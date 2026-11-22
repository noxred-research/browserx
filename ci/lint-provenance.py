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

History mode (`--history`) applies the same rules to everything a clone can fetch: every ref
name (branches, tags, `refs/pull/*`), every commit message, every tag annotation and every
blob of every commit reachable from any ref, including its paths. It adds one rule,
`identity`: an author, committer, tagger or trailer identity must carry a GitHub noreply address and an
account handle (letters, digits, `.`, `_`, `-`, optional `[bot]`) or a plain display name (GitHub writes a
squash merge's author from the account's profile name); a private mail address always fails, and no
identity may carry a hashed retired term (`retired-name in identity`). Trailers of commits that were
already published with a private address are listed one by one in
`ci/provenance-history-exceptions.txt` (full commit id and message line): such a trailer line is exempt from
the identity checks, and from nothing else about its commit. Earlier
versions of the hash file must hold only
well-formed rules (`hash-file`).

Usage: ci/lint-provenance.py [PATH ...]
       ci/lint-provenance.py --history
Default: every file `git ls-files` lists plus untracked files that are not ignored.
Exit status: 0 clean, 1 on any hit, 2 when the hash file is missing or malformed. Hits print as
`file:line: [rule]` without the matched text, so CI logs never spell a retired name. History
hits print as `blob <oid>:<path>:<line>`, `commit <oid>:<line>` or `ref <name>`.
"""

from __future__ import annotations

import functools
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
# History identities: an account handle (or bot) and a GitHub noreply address.
IDENTITY_NAME = re.compile(r"^[A-Za-z0-9._-]+(?:\[bot\])?$")
# A display name: letters and digits (any script), single inner spaces, dots, underscores, apostrophes and hyphens.
DISPLAY_NAME = re.compile(r"^[^\W_](?:[^\W_]|[._'-]| (?! ))*(?:[^\W_]|\.)$")
IDENTITY_MAIL = re.compile(r"^(?:[0-9]+\+)?[A-Za-z0-9._-]+(?:\[bot\])?@users\.noreply\.github\.com$|^(?:noreply|support)@github\.com$")
TRAILER = re.compile(r"^(?:Signed-off-by|Co-authored-by|Reviewed-by|Acked-by|Tested-by|Reported-by|Suggested-by|Helped-by):\s*(.*?)\s*<([^<>]*)>\s*$", re.IGNORECASE)


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


def well_formed_hash_file(text: str) -> bool:
    """True when every line of a hash-file version is blank, a comment or a hash-only rule."""
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        digest = parts[-1]
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            return False
        if not (
            (parts[0] == "word" and len(parts) == 2)
            or (parts[0] == "substr" and len(parts) == 3 and parts[1].isdigit() and int(parts[1]) > 0)
        ):
            return False
    return True


class Rules:
    def __init__(self) -> None:
        self.words, self.substrings = load_rules()
        self.matches = functools.lru_cache(maxsize=1 << 16)(self._matches)

    def _matches(self, text: str) -> bool:
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




def check_text(rules: Rules, report, label: str, text: str, handle_ok: bool, emails: bool = True) -> None:
    """Apply the per-line rules to `text`; `report(label, line, rule)` records a hit."""
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
        if emails and any(not EMAIL_OK_DOMAIN.search(m.group(1)) for m in EMAIL.finditer(line)):
            report(label, number, "email-address")


def main(argv: list[str]) -> int:
    if any(a.startswith("--") for a in argv) and argv != ["--history"]:
        print("usage: lint-provenance.py [PATH ...] | --history", file=sys.stderr)
        return 2
    rules = Rules()
    hits = 0

    def report(label: str, number: int | None, rule: str) -> None:
        nonlocal hits
        where = label if number is None else f"{label}:{number}"
        print(f"{where}: [{rule}]")
        hits += 1

    if argv == ["--history"]:
        history(rules, report)
    else:
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
            check_text(rules, report, label, text, label in HANDLE_ALLOWED)
    if hits:
        print(f"lint-provenance: {hits} hit(s)", file=sys.stderr)
        return 1
    return 0


def git_bytes(*args: str, stdin: bytes | None = None) -> bytes:
    return subprocess.run(["git", *args], check=True, capture_output=True, input=stdin).stdout


def identity_ok(name: str, mail: str) -> bool:
    """The mail must be a GitHub noreply address; the name an account handle or a plain display name.

    GitHub writes the author of a squash or web merge from the account's profile name, so a display name
    is accepted when, and only when, the mail is a noreply address. A private mail address fails whatever
    the name is.
    """
    return bool(IDENTITY_MAIL.fullmatch(mail) and (IDENTITY_NAME.fullmatch(name) or DISPLAY_NAME.fullmatch(name)))


def identity_names_retired_term(rules: Rules, name: str, mail: str) -> bool:
    """A name or mail that carries a hashed term. A display name may hold several words, so it is checked like text."""
    return rules.matches(name) or rules.matches(mail)


def _history_exceptions() -> frozenset[tuple[str, int]]:
    """`<40 hex digits of a commit id> <message line>` pairs of already published trailers, one per line.

    A malformed line stops the lint with status 2 and a one-line message, like a malformed hash file.
    """
    path = Path(__file__).with_name("provenance-history-exceptions.txt")
    pairs: set[tuple[str, int]] = set()
    if path.is_file():
        for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{40}", parts[0]) or not parts[1].isdigit():
                print(f"lint-provenance: {path.name}:{number}: expected `<40 hex digits> <line number>`", file=sys.stderr)
                raise SystemExit(2)
            pairs.add((parts[0], int(parts[1])))
    return frozenset(pairs)


HISTORY_EXCEPTIONS = _history_exceptions()


def history(rules: Rules, report, exceptions: frozenset[tuple[str, int]] | None = None) -> None:
    """Scan every ref name, commit, tag annotation and blob reachable from any ref."""
    if exceptions is None:
        exceptions = HISTORY_EXCEPTIONS
    # Ref names (a fetchable `refs/pull/*` counts as much as a branch).
    for ref in git_bytes("for-each-ref", "--format=%(refname)").decode().split():
        if rules.matches(ref):
            report(f"ref {ref}", None, "retired-name in ref name")

    # Commits: identities and messages. 0x1e starts a record, 0x1f separates fields.
    fmt = "%x1e%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%B"
    log = git_bytes("log", "--all", f"--format={fmt}").decode("utf-8", "replace")
    for record in log.split("\x1e")[1:]:
        oid, an, ae, cn, ce, body = record.split("\x1f", 5)
        label = f"commit {oid[:12]}"
        for name, mail in ((an, ae), (cn, ce)):
            if not identity_ok(name, mail):
                report(label, None, "identity")
            if identity_names_retired_term(rules, name, mail):
                report(label, None, "retired-name in identity")
        trailers: set[int] = set()
        for number, line in enumerate(body.splitlines(), 1):
            m = TRAILER.match(line)
            if m:
                trailers.add(number)
                if (oid, number) in exceptions:
                    continue
                if not identity_ok(m.group(1), m.group(2)):
                    report(label, number, "identity")
                if identity_names_retired_term(rules, m.group(1), m.group(2)):
                    report(label, number, "retired-name in identity")
        kept = "\n".join("" if n in trailers else line for n, line in enumerate(body.splitlines(), 1))
        check_text(rules, report, label, kept, handle_ok=True)

    # Annotated tags.
    tags = git_bytes(
        "for-each-ref", "refs/tags", "--format=%(refname)%1f%(taggername)%1f%(taggeremail:trim)%1f%(contents)%1e"
    ).decode("utf-8", "replace")
    for record in tags.split("\x1e"):
        record = record.strip("\n")
        if not record:
            continue
        ref, tname, tmail, contents = record.split("\x1f", 3)
        if tname:
            if not identity_ok(tname, tmail):
                report(f"tag {ref}", None, "identity")
            if identity_names_retired_term(rules, tname, tmail):
                report(f"tag {ref}", None, "retired-name in identity")
        check_text(rules, report, f"tag {ref}", contents, handle_ok=True)

    # Blobs: every distinct object of every reachable tree, with every path it ever had.
    paths: dict[str, set[str]] = {}
    for line in git_bytes("rev-list", "--objects", "--all").decode("utf-8", "replace").splitlines():
        oid, _, path = line.partition(" ")
        if path:
            paths.setdefault(oid, set()).add(path)
    oids = sorted(paths)
    batch = git_bytes("cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)", stdin="".join(f"{o}\n" for o in oids).encode())
    blobs = [line.split() for line in batch.decode().splitlines()]
    blobs = [(o, int(size)) for o, kind, size in blobs if kind == "blob"]
    reported_paths: set[str] = set()
    for oid, size in blobs:
        names = sorted(paths[oid])
        for path in names:
            if path not in reported_paths and rules.matches(path):
                reported_paths.add(path)
                report(f"blob {oid[:12]}:{path}", None, "retired-name in path")
        label = f"blob {oid[:12]}:{names[0]}" + (f" (+{len(names) - 1} more paths)" if len(names) > 1 else "")
        if all(Path(n).suffix in SKIP_SUFFIXES or Path(n).name in SKIP_NAMES for n in names) or size > MAX_BYTES:
            continue
        data = git_bytes("cat-file", "blob", oid)
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if all(Path(n).name == HASH_FILE.name for n in names):
            if not well_formed_hash_file(text):
                report(label, None, "hash-file")
            continue
        check_text(rules, report, label, text, handle_ok=all(n in HANDLE_ALLOWED for n in names))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
