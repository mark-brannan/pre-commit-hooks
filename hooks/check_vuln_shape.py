#!/usr/bin/env python3
"""Block vulnerability-shaped content before it lands in a public repo.

gitleaks catches credentials. It does not catch a finding: a sentence that
says a named machine is reachable without authentication, a firewall that is
off, a default password that was never changed, a CVE next to a host. Those
carry no secret, so every credential scanner waves them through, and once
pushed to a public repo they are in history for good. Undoing that is a
history rewrite, so the check belongs before the commit, not after.

What it looks for
-----------------

Security *writing* is legitimate. A design doc may say "the API is
unauthenticated on the LAN by design" and that is not a leak. What turns it
into a finding is specificity: a particular machine. So the main rule is a
conjunction, judged over a small window of lines:

  exposure   an exposure claim (unauthenticated, auth bypass, firewall
             disabled, default password, CVE id, listening on 0.0.0.0, ...)
  host       a specific host identifier near it (an IPv4 address, a name
             under an internal suffix such as .lan or .local, a host:port,
             a URL, user@host)

Placeholders are not specific. Documentation address ranges (RFC 5737),
example.* and the reserved .test/.example/.invalid suffixes, localhost and
loopback never count as a host, so prose written with placeholders -- the
way it should be -- passes.

One rule needs no host:

  access-id  a pending access-request or device-token identifier (a UUID or
             long token) next to words like "access request" or "request id".
             An outstanding approval ID is a handle someone else can use.

Scope: only lines this commit adds (pre-commit), or every line of every
tracked text file (--all, for CI). Existing content never blocks an
unrelated edit.

When it is wrong
----------------

A false positive is never a dead end:

  - inline: put `vuln-shape: allow` on any line within the window of the
    hit (a comment, an HTML comment in markdown). Use it for a deliberate,
    public, already-disclosed example.
  - per file: list a path glob in `.vuln-shape-allow` at the repo root, one
    per line, `#` comments. For files whose job is to hold such text, such
    as this hook's own test fixtures.

Neither is silent. Every allowed hit is still printed as a note, with its
location, so an allow is a visible decision rather than a hole.

Content guard: it blocks in every secretguard mode, and if it cannot read
what is staged it blocks rather than pass. Messages give path, line and
rule name only, never the matched text, so a CI log on a public repo does
not republish what the hook just caught.
"""
import argparse
import fnmatch
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secretguard  # noqa: E402  -- needs the sys.path line above

ROOT = secretguard.REPO
ALLOW_MARKER = "vuln-shape: allow"
ALLOW_FILE = ".vuln-shape-allow"
WINDOW = 3  # lines either side of a hit that count as "near"
HOOK = "pre-commit hook vuln-shape"

# --- exposure claims ---------------------------------------------------------
_EXPOSURE = re.compile(
    r"""(
        \bun-?authenticated\b
      | \bunauthori[sz]ed\ access\b
      | \bno\ auth(entication)?\b
      | \bwithout\ (any\ |a\ )?(auth\w*|password|credentials|login|token)\b
      | \bno\ (token|password|login|credentials)\ (needed|required)\b
      | \bbypass(es|ed|ing|able)?\b[^.\n]{0,40}?\b(auth\w*|login|proxy|firewall|sso|security|access\ control)
      | \banyone\ (on|from)\ the\ (lan|network|internet|tailnet|vpn)\b
      | \bopen\ to\ the\ (lan|internet|world|network|public)\b
      | \b0\.0\.0\.0:\d+
      | \bon\ all\ interfaces\b
      | \blistening\ on\ 0\.0\.0\.0\b
      | \bfirewall\ (is\ )?(disabled|off|inactive|down|not\ (enabled|running))\b
      | \bufw\ (disable|inactive)\b
      | \bdefault\ (password|credentials|creds|login)\b
      | \bpassword\ (is\ )?(still\ )?(unchanged|the\ default|blank|empty)\b
      | \bCVE-\d{4}-\d{4,}\b
      | \bvulnerab(le|ility)\b
      | \bexploit(able|ed)?\b
      | \bremote\ code\ execution\b
      | \bRCE\b
      | \bprivilege\ escalation\b
      | \bNOPASSWD\b
    )""",
    re.I | re.X,
)

# --- host identifiers --------------------------------------------------------
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])")
_INTERNAL_NAME = re.compile(
    r"\b[a-z0-9][a-z0-9-]*(\.[a-z0-9-]+)*\.(local|lan|home|internal|intranet|corp|home\.arpa|ts\.net)\b",
    re.I,
)
_HOST_PORT = re.compile(r"\b([a-z][a-z0-9-]*(\.[a-z0-9-]+)*):(\d{2,5})\b", re.I)
_FILE_LINE = re.compile(
    r"\.(py|js|mjs|cjs|ts|tsx|jsx|go|rs|rb|sh|c|h|cc|cpp|hpp|java|kt|swift|md|txt"
    r"|json|ya?ml|toml|ini|cfg|conf|log|html|css|sql|lua|pl|php)$", re.I)
_URL_HOST = re.compile(r"\b[a-z][a-z0-9+.-]*://([^/\s:@'\"<>)]+)", re.I)
_USER_AT_HOST = re.compile(r"\b(?:ssh|scp|rsync|sftp)\b[^\n]*?\b[\w.-]+@([a-z0-9][\w.-]*)", re.I)

_PLACEHOLDER_NAME = re.compile(
    r"(^|\.)(example(\.(com|org|net))?|test|invalid|localhost|localdomain)$", re.I
)
_PLACEHOLDER_HOSTS = {"localhost", "host", "hostname", "your-host", "myhost",
                      "server", "<host>", "box", "machine"}


def _ip_is_placeholder(octets):
    a, b, c, d = octets
    if a == 0 or a == 127 or a >= 224:
        return True                          # unspecified, loopback, multicast/reserved
    if (a, b, c) in ((192, 0, 2), (198, 51, 100), (203, 0, 113)):
        return True                          # RFC 5737 documentation ranges
    if a == 255 or (a, b, c, d) == (255, 255, 255, 0):
        return True                          # netmasks
    return False


def _name_is_placeholder(name):
    name = name.lower().rstrip(".")
    return name in _PLACEHOLDER_HOSTS or bool(_PLACEHOLDER_NAME.search(name))


def has_host(line):
    """True if the line names a specific, non-placeholder machine."""
    for m in _IPV4.finditer(line):
        octets = tuple(int(x) for x in m.groups())
        if all(o <= 255 for o in octets) and not _ip_is_placeholder(octets):
            return True
    for m in _INTERNAL_NAME.finditer(line):
        if not _name_is_placeholder(m.group(0)):
            return True
    for m in _HOST_PORT.finditer(line):
        if _FILE_LINE.search(m.group(1)):
            continue                         # `handshake.js:67` is a file and line
        if not _name_is_placeholder(m.group(1)) and 1 <= int(m.group(3)) <= 65535:
            # `http:80`, `https:443` are scheme:port in config, not a host
            if m.group(1).lower() not in ("http", "https", "tcp", "udp", "port"):
                return True
    # A URL to a public site (a forge, an advisory) is not a host finding;
    # IPs and internal names inside URLs are caught above. What is left is a
    # bare single-label name, which only resolves on someone's own network.
    for m in _URL_HOST.finditer(line):
        host = m.group(1).rstrip(".")
        if "." not in host and not _name_is_placeholder(host):
            return True
    for m in _USER_AT_HOST.finditer(line):
        host = m.group(1).rstrip(".")
        if _IPV4.fullmatch(host):
            continue                         # judged by the IPv4 rule above
        if not _name_is_placeholder(host):
            return True
    return False


# --- pending access identifiers ---------------------------------------------
_ACCESS_WORDS = re.compile(
    r"\b(access[- ]?requests?|device[- ]?(access[- ]?)?tokens?|request[- _]?ids?|requestid"
    r"|pending\ (approval|request)s?)\b",
    re.I | re.X,
)
_ID_VALUE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
    r"|\b(?=[A-Za-z0-9_-]{20,}\b)(?=[A-Za-z0-9_-]*\d)(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_-]+\b",
    re.I,
)


def _near(flags, i):
    lo, hi = max(0, i - WINDOW), min(len(flags), i + WINDOW + 1)
    return any(flags[lo:hi])


def scan_text(lines, added=None):
    """Return [(lineno, rule, allowed)] for hits on added lines (1-based).

    `added` is the set of 1-based line numbers this commit adds; None means
    every line counts (--all).
    """
    exposure = [bool(_EXPOSURE.search(l)) for l in lines]
    host = [has_host(l) for l in lines]
    access = [bool(_ACCESS_WORDS.search(l)) for l in lines]
    ident = [bool(_ID_VALUE.search(l)) for l in lines]
    marker = [ALLOW_MARKER in l for l in lines]
    hits = []
    for i in range(len(lines)):
        if added is not None and (i + 1) not in added:
            continue
        rule = None
        if (exposure[i] and _near(host, i)) or (host[i] and _near(exposure, i)):
            rule = "exposure claim next to a specific host"
        elif (ident[i] and _near(access, i)) or (access[i] and _near(ident, i)):
            rule = "pending access-request or token identifier"
        if rule:
            hits.append((i + 1, rule, _near(marker, i)))
    # One report per run of adjacent lines, not one per line.
    out, last = [], None
    for h in hits:
        if last is not None and h[0] == last[0] + 1 and h[1] == last[1]:
            last = h
            continue
        out.append(h)
        last = h
    return out


# --- git plumbing ------------------------------------------------------------
class GitError(Exception):
    pass


def _git(*args, binary=False):
    r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True)
    if r.returncode != 0:
        raise GitError("git %s: %s" % (" ".join(args),
                                       r.stderr.decode("utf-8", "replace").strip()))
    return r.stdout if binary else r.stdout.decode("utf-8", "surrogateescape")


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", re.M)


def staged_added_lines():
    """{path: set(added line numbers)} for this commit."""
    names = [n for n in _git("diff", "--cached", "--name-only", "-z",
                             "--diff-filter=ACMR").split("\0") if n]
    result = {}
    for name in names:
        diff = _git("diff", "--cached", "-U0", "--no-color", "--no-ext-diff",
                    "--", name)
        added = set()
        for m in _HUNK.finditer(diff):
            start, count = int(m.group(1)), int(m.group(2) or 1)
            added.update(range(start, start + count))
        if added:
            result[name] = added
    return result


def _is_binary(raw):
    return b"\0" in raw[:8192]


def load_allowlist():
    path = os.path.join(ROOT, ALLOW_FILE)
    try:
        with open(path, encoding="utf-8") as fh:
            return [l.strip() for l in fh if l.strip() and not l.lstrip().startswith("#")]
    except FileNotFoundError:
        return []


def _allowed_by_file(name, globs):
    return any(fnmatch.fnmatch(name, g) for g in globs)


def run(all_files=False):
    try:
        if all_files:
            names = [n for n in _git("ls-files", "-z").split("\0") if n]
            scope = {n: None for n in names}
        else:
            scope = staged_added_lines()
        globs = load_allowlist()
        blocked, allowed = [], []
        for name, added in sorted(scope.items()):
            if all_files:
                p = os.path.join(ROOT, name)
                if not os.path.isfile(p):
                    continue
                with open(p, "rb") as fh:
                    raw = fh.read()
            else:
                raw = _git("show", ":%s" % name, binary=True)
            if _is_binary(raw):
                continue
            lines = raw.decode("utf-8", "replace").splitlines()
            file_ok = _allowed_by_file(name, globs)
            for lineno, rule, marked in scan_text(lines, added):
                where = "%s:%d  %s" % (name, lineno, rule)
                if marked:
                    allowed.append(where + "  (inline %s)" % ALLOW_MARKER)
                elif file_ok:
                    allowed.append(where + "  (%s)" % ALLOW_FILE)
                else:
                    blocked.append(where)
    except (GitError, OSError) as exc:
        secretguard.block(
            "could not read what this commit stages, so it cannot be judged",
            problem=str(exc),
            blocked_by=HOOK,
            fix="fix the git error above and commit again",
        )
        return 1

    if allowed:
        secretguard.note(
            "vulnerability-shaped lines let through by an explicit allow",
            file=allowed,
            blocked_by=HOOK,
            see="hooks/check_vuln_shape.py docstring, 'When it is wrong'",
        )
    if blocked:
        secretguard.block(
            "this reads like a security finding about a specific machine",
            problem="a public repo keeps it in history for good; credential "
                    "scanners do not catch findings",
            file=blocked,
            blocked_by=HOOK,
            fix="move the detail to a private log or repo and leave a vague "
                "pointer here; or replace the host with a placeholder "
                "(example.com, 192.0.2.x)",
            if_stuck="a deliberate public example: add '%s' on or beside the "
                     "line, or list the path in %s" % (ALLOW_MARKER, ALLOW_FILE),
            see="hooks/check_vuln_shape.py docstring",
        )
        return 1
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--all", action="store_true",
                    help="scan every line of every tracked file (CI)")
    args = ap.parse_args(argv)
    return run(all_files=args.all)


if __name__ == "__main__":
    sys.exit(main())
