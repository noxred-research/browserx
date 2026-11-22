#!/usr/bin/env python3
"""Tests of the `identity` rules of ci/lint-provenance.py (history mode).

Run: python3 -B -m unittest discover -s ci -p 'test_lint_provenance.py'
"""

import contextlib
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("lint-provenance.py")
HASHES = SCRIPT.with_name("provenance-hashes.txt")
spec = importlib.util.spec_from_file_location("lint_provenance", SCRIPT)
lint = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lint)

# Addresses are built from parts: the tree lint rejects a literal e-mail address in a file.
AT = "@"
NOREPLY = "190931966+someone" + AT + "users.noreply.github.com"
GITHUB = "noreply" + AT + "github.com"
PRIVATE = "given" + AT + "private.example.org"

# git picks its repository and identity from these; a test must not inherit any of them (a git hook sets GIT_DIR).
CLEAN_ENV = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
CLEAN_ENV.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull})


@contextlib.contextmanager
def throwaway_repo(commits):
    """A temporary repository built from (author, author_mail, committer, committer_mail, message)."""
    with tempfile.TemporaryDirectory() as tmp:
        def git(*args, **env):
            return subprocess.run(
                ["git", *args], cwd=tmp, check=True, capture_output=True, text=True, env={**CLEAN_ENV, **env}
            ).stdout.strip()

        git("init", "-q", "-b", "main")
        oids = []
        for index, (an, ae, cn, ce, message) in enumerate(commits):
            (Path(tmp) / "file.txt").write_text(f"{index}\n", encoding="utf-8")
            git("add", "file.txt")
            git(
                "commit", "-q", "-m", message,
                GIT_AUTHOR_NAME=an, GIT_AUTHOR_EMAIL=ae, GIT_COMMITTER_NAME=cn, GIT_COMMITTER_EMAIL=ce,
            )
            oids.append(git("rev-parse", "HEAD"))
        yield tmp, oids


def run_script(tmp, script=SCRIPT):
    done = subprocess.run(
        [sys.executable, str(script), "--history"], cwd=tmp, capture_output=True, text=True, env=CLEAN_ENV, check=False
    )
    return done.returncode, done.stdout, done.stderr


def run_in_process(tmp, exceptions, rules=None):
    """Call history() directly, so the exception list can be chosen; returns the (label, line, rule) hits."""
    hits = []
    previous = os.getcwd()
    os.chdir(tmp)
    try:
        lint.history(rules or lint.Rules(), lambda label, number, rule: hits.append((label, number, rule)), exceptions)
    finally:
        os.chdir(previous)
    return hits


class IdentityOk(unittest.TestCase):
    def test_handles_and_bots_with_noreply_mail(self):
        self.assertTrue(lint.identity_ok("someone", NOREPLY))
        self.assertTrue(lint.identity_ok("dependabot[bot]", "49699333+dependabot[bot]" + AT + "users.noreply.github.com"))
        self.assertTrue(lint.identity_ok("GitHub", GITHUB))

    def test_display_name_needs_a_noreply_mail(self):
        self.assertTrue(lint.identity_ok("Given Family", NOREPLY))
        self.assertTrue(lint.identity_ok("Given M. O'Family-Name", NOREPLY))
        self.assertTrue(lint.identity_ok("Zoë Faßbinder", NOREPLY))
        self.assertFalse(lint.identity_ok("Given Family", PRIVATE))
        self.assertFalse(lint.identity_ok("Given Family", "given.family" + AT + "users.noreply.github.com.evil.example"))
        self.assertFalse(lint.identity_ok("Given Family", ""))

    def test_private_mail_fails_whatever_the_name(self):
        self.assertFalse(lint.identity_ok("someone", PRIVATE))
        self.assertFalse(lint.identity_ok("someone", "someone" + AT + "noreply.github.com"))

    def test_malformed_names_and_mails_fail(self):
        for name in ("", " ", "Given  Family", " Given", "Given ", "Given<Family", "Given\tFamily", "Given@Family", "Given Family\n"):
            self.assertFalse(lint.identity_ok(name, NOREPLY), repr(name))
        self.assertFalse(lint.identity_ok("Given Family", NOREPLY + "\n"))


class History(unittest.TestCase):
    def test_squash_merge_by_a_display_name_with_a_noreply_mail_passes(self):
        with throwaway_repo([("Given Family", NOREPLY, "GitHub", GITHUB, "fix: a change (#1)")]) as (tmp, _):
            self.assertEqual(run_script(tmp), (0, "", ""))

    def test_display_name_with_a_private_mail_fails(self):
        with throwaway_repo([("Given Family", PRIVATE, "GitHub", GITHUB, "fix: x")]) as (tmp, _):
            code, out, _ = run_script(tmp)
        self.assertEqual(code, 1)
        self.assertIn("[identity]", out)

    def test_private_committer_mail_fails(self):
        with throwaway_repo([("someone", NOREPLY, "Given Family", PRIVATE, "fix: x")]) as (tmp, _):
            code, out, _ = run_script(tmp)
        self.assertEqual(code, 1)
        self.assertIn("[identity]", out)

    def test_trailer_identity_follows_the_same_rule(self):
        ok = f"fix: x\n\nCo-authored-by: Given Family <{NOREPLY}>"
        bad = f"fix: x\n\nCo-authored-by: Given Family <{PRIVATE}>"
        with throwaway_repo([("someone", NOREPLY, "GitHub", GITHUB, ok)]) as (tmp, _):
            self.assertEqual(run_script(tmp)[0], 0)
        with throwaway_repo([("someone", NOREPLY, "GitHub", GITHUB, bad)]) as (tmp, _):
            code, out, _ = run_script(tmp)
        self.assertEqual(code, 1)
        self.assertRegex(out, r"commit [0-9a-f]{12}:3: \[identity\]")


class Exceptions(unittest.TestCase):
    BAD_TRAILER = f"fix: x\n\nCo-authored-by: Given Family <{PRIVATE}>"

    def test_an_exception_exempts_that_trailer_line_only(self):
        # The listed commit also has a private author: that hit must stay.
        with throwaway_repo([("Given Family", PRIVATE, "GitHub", GITHUB, self.BAD_TRAILER)]) as (tmp, (oid,)):
            label = f"commit {oid[:12]}"
            self.assertEqual(run_in_process(tmp, frozenset()), [(label, None, "identity"), (label, 3, "identity")])
            self.assertEqual(run_in_process(tmp, frozenset({(oid, 3)})), [(label, None, "identity")])

    def test_the_line_number_and_the_full_id_must_match(self):
        with throwaway_repo([("someone", NOREPLY, "GitHub", GITHUB, self.BAD_TRAILER)]) as (tmp, (oid,)):
            label = f"commit {oid[:12]}"
            self.assertEqual(run_in_process(tmp, frozenset({(oid, 4)})), [(label, 3, "identity")])
            self.assertEqual(run_in_process(tmp, frozenset({(oid[:12], 3)})), [(label, 3, "identity")])
            self.assertEqual(run_in_process(tmp, frozenset({("0" * 40, 3)})), [(label, 3, "identity")])
            self.assertEqual(run_in_process(tmp, frozenset({(oid, 3)})), [])

    def test_the_published_exceptions_are_well_formed(self):
        pairs = lint._history_exceptions()
        self.assertEqual(len(pairs), 3)
        for oid, number in pairs:
            self.assertRegex(oid, r"^[0-9a-f]{40}$")
            self.assertGreater(number, 0)

    def test_a_malformed_exceptions_file_stops_the_lint_with_status_2(self):
        with tempfile.TemporaryDirectory() as scripts:
            shutil.copy(SCRIPT, scripts)
            shutil.copy(HASHES, scripts)
            Path(scripts, "provenance-history-exceptions.txt").write_text("5b478c98205c 60\n", encoding="utf-8")
            with throwaway_repo([("someone", NOREPLY, "GitHub", GITHUB, "fix: x")]) as (tmp, _):
                code, out, err = run_script(tmp, Path(scripts, SCRIPT.name))
        self.assertEqual((code, out), (2, ""))
        self.assertEqual(len(err.strip().splitlines()), 1)
        self.assertIn("provenance-history-exceptions.txt:1", err)


class RetiredTermsInIdentities(unittest.TestCase):
    """A display name may hold several words, so it is checked like text. The hashed terms cannot be spelled
    here: a stand-in rule set that matches the word `retired` exercises the same code path."""

    class Stub:
        @staticmethod
        def matches(text):
            return "retired" in text.lower()

    def test_author_committer_trailer_and_tagger_are_checked(self):
        trailer = f"fix: x\n\nCo-authored-by: Retired Word <{NOREPLY}>"
        with throwaway_repo([("Retired Word", NOREPLY, "GitHub", GITHUB, "fix: x")]) as (tmp, (oid,)):
            self.assertEqual(
                run_in_process(tmp, frozenset(), self.Stub()), [(f"commit {oid[:12]}", None, "retired-name in identity")]
            )
        with throwaway_repo([("someone", NOREPLY, "Retired Word", GITHUB, "fix: x")]) as (tmp, (oid,)):
            self.assertEqual(
                run_in_process(tmp, frozenset(), self.Stub()), [(f"commit {oid[:12]}", None, "retired-name in identity")]
            )
        with throwaway_repo([("someone", NOREPLY, "GitHub", GITHUB, trailer)]) as (tmp, (oid,)):
            label = f"commit {oid[:12]}"
            self.assertEqual(run_in_process(tmp, frozenset(), self.Stub()), [(label, 3, "retired-name in identity")])
            self.assertEqual(run_in_process(tmp, frozenset({(oid, 3)}), self.Stub()), [])
        with throwaway_repo([("someone", NOREPLY, "GitHub", GITHUB, "fix: x")]) as (tmp, _):
            subprocess.run(
                ["git", "tag", "-a", "v1", "-m", "release"],
                cwd=tmp, check=True, capture_output=True,
                env={**CLEAN_ENV, "GIT_COMMITTER_NAME": "Retired Word", "GIT_COMMITTER_EMAIL": NOREPLY},
            )
            self.assertEqual(run_in_process(tmp, frozenset(), self.Stub()), [("tag refs/tags/v1", None, "retired-name in identity")])


if __name__ == "__main__":
    unittest.main()
