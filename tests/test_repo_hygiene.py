#!/usr/bin/env python3
"""Tests for how repo-hygiene composes enforcement mode with commit scope.

The rule that matters both ways: an unconfigured filter must BLOCK when the
commit stages a file that filter covers (that is the 2026-08-14 incident --
plaintext secrets into a public repo) and must NOT block otherwise, because
the fix it names needs sops, age and the age key, which a contributor or a
fresh checkout does not have.

    blocking = bool(hits) or enforcement is strict

An AND of two axes, not an OR. Composed as OR, contributor mode would
swallow a staged plaintext secret. Three tests below pin the AND.

These assert exit conditions and severity, never message wording. Two
earlier versions asserted on phrasing and broke the moment the shared
formatter landed; they were change-detectors, and they tested nothing the
formatter's own parity suite doesn't already cover.

Run: python3 tests/test_repo_hygiene.py
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hooks"))

import lint_repo_hygiene as lint  # noqa: E402
import secretguard  # noqa: E402


class RuleTestCase(unittest.TestCase):
    """Pins every input the rule reads, so nothing here passes vacuously.

    Notably `filter_is_configured`: on a maintainer's clone the filters ARE
    configured, the rule would return early, and every assertion below would
    pass while testing nothing.

    Every seam a test here patches is saved and restored from this one
    place, `staged_blob` included -- a test that patches a module attribute
    the base class does not restore leaks it into whatever runs next, and
    the symptom is a failure in an unrelated test.
    """

    MODE = "contributor"

    def setUp(self):
        self._saved = (lint.staged_paths, lint.filter_is_configured,
                       lint.gitattributes_filters, lint.staged_blob,
                       lint.SCOPE_ALL, lint.CI, secretguard._resolved)
        lint.failures.clear()
        lint.warnings.clear()
        lint.SCOPE_ALL = False
        lint.CI = False
        lint.filter_is_configured = lambda name: False
        secretguard._resolved = (self.MODE, "pinned by test")

        # One filter, so a test about how THIS filter is treated can't be
        # muddied by another declared filter reporting on its own account.
        name, pattern = self.a_real_filter()
        self.covered = pattern
        lint.gitattributes_filters = lambda: {name: [pattern]}

        # The rule returns early without a .gitattributes at the root, and
        # this hook repo has none; give it a throwaway root that does.
        self._root_saved = lint.ROOT
        self._tmp = tempfile.TemporaryDirectory()
        lint.ROOT = Path(self._tmp.name)
        (lint.ROOT / ".gitattributes").write_text(
            f"{pattern} filter={name}\n", encoding="utf-8")

    def tearDown(self):
        (lint.staged_paths, lint.filter_is_configured,
         lint.gitattributes_filters, lint.staged_blob, lint.SCOPE_ALL,
         lint.CI, secretguard._resolved) = self._saved
        lint.ROOT = self._root_saved
        self._tmp.cleanup()
        lint.failures.clear()
        lint.warnings.clear()

    def run_rule(self, staged):
        lint.staged_paths = lambda: staged
        lint.rule_declared_filters_are_configured()
        return lint.failures, lint.warnings

    def a_real_filter(self):
        """(filter name, a path it covers).

        A fixed fixture: this hook repo has no filtered paths of its own, and
        gitattributes_filters is patched in setUp, so the rule never reads a
        real .gitattributes here.
        """
        return "sops", "secrets/example.sops.yaml"

class ContributorScopingTest(RuleTestCase):
    """Contributor mode: the case that used to trap people."""

    MODE = "contributor"

    def test_unrelated_commit_warns_but_does_not_block(self):
        """Environment, not content -- a typo fix must still commit."""
        fails, warns = self.run_rule({"maintenance/log.md"})
        self.assertEqual(fails, [])
        self.assertTrue(warns, "a missing filter must still be reported")

    def test_staging_a_covered_file_blocks(self):
        """Content -- blocks even in contributor mode. This is the AND.

        Composed as OR this returns a warning and a plaintext secret goes
        into a public repo.
        """
        fails, warns = self.run_rule({self.covered})
        self.assertTrue(fails, "a staged covered path must block in any mode")
        self.assertEqual(warns, [], "content must not be downgraded to a warning")

    def test_block_message_carries_every_field(self):
        """The five elements, plus an exit that needs no age key.

        Fields, not phrasing: someone who is blocked must be told what
        broke, which file, what is missing, who stopped them, how to fix
        it, and a way out they can take with no sops and no key.
        """
        fails, _ = self.run_rule({self.covered})
        text = "\n".join(fails)
        for label in ("problem:", "file:", "needs:", "blocked by:",
                      "fix:", "if stuck:", "mode:"):
            self.assertIn(label, text, f"blocked message is missing {label}")

    def test_all_mode_blocks_regardless_of_staging(self):
        """CI runs --all; without it enforcement passes vacuously there."""
        lint.SCOPE_ALL = True
        fails, _ = self.run_rule({"maintenance/log.md"})
        self.assertTrue(fails, "--all must enforce repo-wide")

    def test_unknown_scope_falls_back_to_blocking(self):
        """A broken `git diff` must widen the rule, never disable it."""
        fails, _ = self.run_rule(None)
        self.assertTrue(fails)

    def test_ci_skips_the_rule_entirely(self):
        """CI legitimately has no filters and never commits."""
        lint.CI = True
        fails, warns = self.run_rule({self.covered})
        self.assertEqual((fails, warns), ([], []))

    def test_configured_filter_is_silent(self):
        lint.filter_is_configured = lambda name: True
        fails, warns = self.run_rule({self.covered})
        self.assertEqual((fails, warns), ([], []))


class StrictScopingTest(RuleTestCase):
    """Strict mode: the other half of the AND."""

    MODE = "strict"

    def test_unrelated_commit_blocks(self):
        """Environment IS enforced in strict -- scope alone would let this by."""
        fails, _ = self.run_rule({"maintenance/log.md"})
        self.assertTrue(fails, "strict must block on an unwired clone")

    def test_staging_a_covered_file_blocks(self):
        fails, _ = self.run_rule({self.covered})
        self.assertTrue(fails)


if __name__ == "__main__":
    unittest.main()
