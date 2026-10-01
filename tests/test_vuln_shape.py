#!/usr/bin/env python3
"""Tests for hooks/check_vuln_shape.py.

Every fixture is invented: the hosts are made-up names under an internal
suffix or private addresses nobody owns in public, and the findings are
generic categories. This file is listed in .vuln-shape-allow, because its
job is to hold exactly the text the hook blocks.
"""
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
HOOKS = os.path.join(os.path.dirname(HERE), "hooks")
SCRIPT = os.path.join(HOOKS, "check_vuln_shape.py")
sys.path.insert(0, HOOKS)

import check_vuln_shape as vs  # noqa: E402

# Should block: each one is a finding about a specific (fake) machine.
FINDINGS = [
    "The admin API on fakebox-07.lan:8081 is reachable unauthenticated.",
    "curl http://10.250.3.4:9000/api/config returns the full config, no auth required",
    "Firewall is disabled on zz-test-node.internal, every port is open.",
    "nas-fixture.local still has the default password set on its web UI.",
    "CVE-2099-00001 applies to the router at 172.31.250.9",
    "ssh admin@fakegw  # works without a password\n",
    "Service listens on 0.0.0.0:7777\nso testpi-99.local is open to the LAN",
    "The proxy can be skipped: hitting dummyhost:5555 directly bypasses the auth layer",
]

# Should pass: legitimate security writing, placeholders, or unrelated text.
CLEAN = [
    # design prose about posture, no specific machine
    "The API is unauthenticated on the LAN by design; see the threat model.",
    "We accept that anyone on the LAN can read telemetry. Writes need a token.",
    "If the firewall is disabled, the service is exposed to every peer.",
    # placeholders are the right way to write an example
    "Example: curl http://192.0.2.10:8080/ answers without auth if misconfigured.",
    "e.g. host.example.com:8080 would be unauthenticated in that setup",
    "Bind to 127.0.0.1:8080, never 0.0.0.0:8080.",
    # a public advisory link is not a host
    "Bumped the library for a vulnerability: https://github.com/advisories/GHSA-xxxx",
    # "bypass" about something other than access control; a file:line
    "Go binaries bypass NSS and ask the resolver at fakebox-07.lan directly.",
    "the server closes the unauthenticated socket; see handshake.js:67",
    # hosts with no exposure claim
    "Deploy target is fakebox-07.lan:8081; restart with systemctl.",
    "The UUID column is 3f2b8c1e-0000-4000-8000-000000000000 in the fixture table.",
]

ACCESS_IDS = [
    "Pending access request id: 7a1c9e2b-1111-4222-8333-944455556666",
    "device token request ab12CD34ef56GH78ij90KL still awaiting approval",
]


def hits(text):
    return vs.scan_text(text.splitlines())


class ScanTest(unittest.TestCase):
    def test_findings_block(self):
        for text in FINDINGS:
            with self.subTest(text=text):
                self.assertTrue(hits(text), "missed: %r" % text)

    def test_clean_passes(self):
        for text in CLEAN:
            with self.subTest(text=text):
                self.assertEqual(hits(text), [], "false positive: %r" % text)

    def test_access_ids_block(self):
        for text in ACCESS_IDS:
            with self.subTest(text=text):
                h = hits(text)
                self.assertTrue(h)
                self.assertIn("access", h[0][1])

    def test_window_joins_claim_and_host_across_lines(self):
        text = "Notes for fakebox-07.lan\n\nIts dashboard is unauthenticated."
        self.assertTrue(hits(text))

    def test_far_apart_does_not_join(self):
        text = "fakebox-07.lan\n" + "filler\n" * 10 + "unauthenticated by design"
        self.assertEqual(hits(text), [])

    def test_inline_marker_allows_but_reports(self):
        text = ("<!-- vuln-shape: allow -->\n"
                "fakebox-07.lan answers unauthenticated (disclosed upstream)")
        h = hits(text)
        self.assertTrue(h)
        self.assertTrue(all(allowed for _, _, allowed in h))

    def test_only_added_lines_count(self):
        lines = ["fakebox-07.lan is unauthenticated", "a typo fix"]
        self.assertEqual(vs.scan_text(lines, added={2}), [])
        self.assertTrue(vs.scan_text(lines, added={1}))


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


class HookTest(unittest.TestCase):
    """The script end to end, in a throwaway repo."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = self.tmp.name
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.email", "t@example.com")
        _git(self.repo, "config", "user.name", "t")
        self.write("README.md", "hello\n")
        _git(self.repo, "add", "README.md")
        _git(self.repo, "commit", "-qm", "init")

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        with open(os.path.join(self.repo, name), "w", encoding="utf-8") as fh:
            fh.write(text)

    def run_hook(self, *args):
        env = dict(os.environ)
        for k in ("CI", "GITHUB_ACTIONS", "SECRETGUARD_MODE"):
            env.pop(k, None)
        return subprocess.run([sys.executable, SCRIPT, *args], cwd=self.repo,
                              env=env, capture_output=True, text=True,
                              start_new_session=True)

    def test_staged_finding_blocks_without_echoing_it(self):
        self.write("notes.md", FINDINGS[0] + "\n")
        _git(self.repo, "add", "notes.md")
        r = self.run_hook()
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("notes.md:1", r.stderr)
        self.assertIn("BLOCKED", r.stderr)
        self.assertNotIn("fakebox-07", r.stderr)

    def test_contributor_mode_still_blocks(self):
        self.write(".secretguard-mode", "contributor\n")
        self.write("notes.md", FINDINGS[2] + "\n")
        _git(self.repo, "add", "notes.md")
        self.assertEqual(self.run_hook().returncode, 1)

    def test_clean_commit_passes(self):
        # spaced past the window, so lines are judged one at a time
        self.write("notes.md", ("\n" * 5).join(CLEAN) + "\n")
        _git(self.repo, "add", "notes.md")
        r = self.run_hook()
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_existing_content_does_not_block_unrelated_edit(self):
        self.write("old.md", FINDINGS[0] + "\nline two\n")
        _git(self.repo, "add", "old.md")
        _git(self.repo, "commit", "-qm", "old", "--no-verify")
        self.write("old.md", FINDINGS[0] + "\nline two, fixed\n")
        _git(self.repo, "add", "old.md")
        self.assertEqual(self.run_hook().returncode, 0)

    def test_allowlist_file_lets_through_loudly(self):
        self.write(".vuln-shape-allow", "# fixtures\nfixtures/*\n")
        os.mkdir(os.path.join(self.repo, "fixtures"))
        self.write("fixtures/f.md", FINDINGS[1] + "\n")
        _git(self.repo, "add", "fixtures/f.md")
        r = self.run_hook()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("fixtures/f.md:1", r.stderr)
        self.assertIn(".vuln-shape-allow", r.stderr)

    def test_all_mode_scans_tracked_files(self):
        self.write("old.md", FINDINGS[3] + "\n")
        _git(self.repo, "add", "old.md")
        _git(self.repo, "commit", "-qm", "old", "--no-verify")
        self.assertEqual(self.run_hook("--all").returncode, 1)

    def test_unreadable_index_blocks(self):
        env = dict(os.environ, GIT_INDEX_FILE=os.path.join(self.repo, "nope", "idx"))
        env.pop("CI", None)
        os.makedirs(os.path.join(self.repo, "nope", "idx"))  # a dir, not a file
        r = subprocess.run([sys.executable, SCRIPT], cwd=self.repo, env=env,
                           capture_output=True, text=True, start_new_session=True)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("could not read", r.stderr)


if __name__ == "__main__":
    unittest.main()
