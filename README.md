# pre-commit-hooks

Shared [pre-commit](https://pre-commit.com) hooks for secret scanning, repo
hygiene and encoding health. Extracted from `mark-brannan/symphony`, where
each one was written after a real incident; the incident lives in the
script's header.

## Use

```yaml
# .pre-commit-config.yaml
minimum_pre_commit_version: "3.2.0"
default_install_hook_types: [pre-commit, pre-push]
default_stages: [pre-commit]
repos:
  - repo: https://github.com/mark-brannan/pre-commit-hooks
    rev: <commit sha>   # pin a sha; `pre-commit autoupdate --freeze` bumps it
    hooks:
      - id: gitleaks
      - id: prepush-secret-scan
      - id: repo-hygiene
      - id: encoding-health
      - id: vuln-shape
```

Then `pre-commit install` and check it worked:

```sh
pre-commit run --all-files   # every hook prints Passed or Skipped
```

| id | stage | blocks on |
|---|---|---|
| `gitleaks` | pre-commit | credential-shaped strings in the staged diff (pinned image, `--redact`) |
| `prepush-secret-scan` | pre-push | never-tracked files, unencrypted sops files, cleartext credentials in any pushed commit |
| `repo-hygiene` | pre-commit | a `.gitattributes` filter git has no config for |
| `encoding-health` | pre-commit | non-UTF-8 or mojibake in staged files |
| `vuln-shape` | pre-commit | an exposure claim (unauthenticated, firewall off, default password, CVE) next to a specific host, or a pending access-request ID, in added lines |

Every hook judges only what this commit stages (or this push publishes).
Repo-wide state is CI's job: `hooks/lint_repo_hygiene.py --all` and
`hooks/check_encoding_health.py --repo`, or the manual-stage aliases shown
in `.pre-commit-hooks.yaml`.

## Why hooks degrade instead of failing

A hook that needs a tool the machine lacks (docker, sops, an age key) says
so and lets the commit through in *contributor* mode, and blocks in
*strict* mode. Mode comes from `$SECRETGUARD_MODE`, then a
`.secretguard-mode` file at the consuming repo's root, then whether an age
key is present. `hooks/secretguard.sh` has the detail. A local hook is fast
feedback, not the enforcement boundary: `--no-verify` skips it. CI is the
gate.

## Configuration

- **gitleaks image**: `$GITLEAKS_IMAGE`, else the consuming repo's
  `docker/gitleaks/Dockerfile` `FROM` line, else this repo's.
- **gitleaks rules**: a `.gitleaks.toml` at the consuming repo's root is
  passed with `--config`.
- **vuln-shape allows**: `vuln-shape: allow` on or within three lines of a
  hit, or a path glob in `.vuln-shape-allow` at the repo root. Allowed hits
  still print as notes. Placeholders (`example.com`, `192.0.2.x`) never
  count as a host, so writing examples with them needs no allow.

Block messages point at the consuming repo's own docs (`RUNBOOK.md`,
`scripts/setup-git-filters.sh`) for the sops paths; those only fire in
repos that use sops filters.

## Layout, and adding a hook

```
hooks/        one executable per hook, plus secretguard.{sh,py} (shared mode + message format)
tests/        test_<hook>.py, stdlib unittest; CI runs tests/test_*.py
docker/       version pins Dependabot can see
```

A new hook is a script in `hooks/`, its test in `tests/`, and an entry in
`.pre-commit-hooks.yaml`. Rules that only make sense in one repo stay in
that repo as `repo: local` hooks.

Run the suite: `for t in tests/test_*.py; do python3 "$t" -q; done`
