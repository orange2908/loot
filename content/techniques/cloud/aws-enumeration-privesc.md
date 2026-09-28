---
title: "AWS Post-Credential Enumeration and Privilege-Escalation Paths"
category: cloud
subcategory: aws
type: technique
tags: [cloud, aws, iam, enumeration, privilege-escalation, sts, get-caller-identity, iam-policy, pass-role, lambda, assume-role, s3, secrets-manager, pacu, scoutsuite, credentials]
difficulty: medium
summary: "Once you hold AWS keys: identify who you are, enumerate the policy, then look for the known IAM escalation edges (iam:PassRole, policy versions, assume-role)."
when_to_use:
  - "You have AWS credentials (from metadata, a leaked .env, a bucket, or a config file)"
  - "You need to know what the credentials can do"
  - "You are looking for a path from a limited role to a more powerful one"
tools: [awscli, jq, pacu, scoutsuite, enumerate-iam]
related: [cloud-metadata-ssrf, object-storage-misconfig, serverless-attacks, aws-cli-cheatsheet]
---

## TL;DR

The value of AWS credentials is entirely their IAM policy. Establish identity
(`sts get-caller-identity`), enumerate what the policy allows, then check for the well-known IAM
misconfigurations that let a limited principal reach a more powerful one - almost all of them turn
on `iam:PassRole` plus a compute service, or on rewriting your own permissions.

## Recognise it

- You obtained `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (± `AWS_SESSION_TOKEN`).
- The keys start with `AKIA` (long-lived IAM user) or `ASIA` (temporary STS - needs the session
  token).
- The challenge objective is a Secret, an S3 object, or "become admin".

## Theory

### Identity first

```bash
aws sts get-caller-identity
# -> Account, Arn (user or assumed-role), UserId
```

The ARN tells you whether you are an IAM **user** (`arn:aws:iam::123:user/name`) or an
**assumed role** (`arn:aws:sts::123:assumed-role/RoleName/session`). That changes which enumeration
calls exist (users have access keys and inline/attached policies you can sometimes read; roles have
a trust policy).

### Enumerating your own permissions

You cannot always read your own policy (that itself requires `iam:Get*`/`iam:List*`). Two approaches:

1. **Read the policy directly** if allowed:
```bash
aws iam list-attached-user-policies --user-name NAME
aws iam list-user-policies --user-name NAME
aws iam get-user-policy --user-name NAME --policy-name INLINE
aws iam list-attached-role-policies --role-name ROLE
aws iam get-policy-version --policy-arn ARN --version-id v3
```
2. **Brute the API** with a non-destructive enumerator (`enumerate-iam`, or Pacu's
   `iam__enum_permissions`) that calls hundreds of read-only/`List`/`Describe` actions and records
   which return `200` vs `AccessDenied`. This is the practical method when policy-read is denied.

### The canonical IAM privilege-escalation edges

These are the well-documented paths (Rhino Security Labs catalogued the classic set). Each is "if
you hold permission X you can become more powerful":

| Permission(s) held | Escalation |
|---|---|
| `iam:CreatePolicyVersion` | create a new default version of a policy that grants `*:*` |
| `iam:SetDefaultPolicyVersion` | switch the default to an existing over-permissive version |
| `iam:AttachUserPolicy` / `AttachRolePolicy` / `AttachGroupPolicy` | attach `AdministratorAccess` to yourself |
| `iam:PutUserPolicy` / `PutRolePolicy` / `PutGroupPolicy` | inline an admin policy onto yourself |
| `iam:CreateAccessKey` (on another user) | mint keys for a more privileged user |
| `iam:CreateLoginProfile` / `UpdateLoginProfile` | set a console password on a privileged user |
| `iam:PassRole` + `iam:CreateInstanceProfile` + `ec2:RunInstances` | launch an EC2 instance with a powerful role, read its metadata |
| `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | run code as a powerful role |
| `iam:PassRole` + `glue`/`cloudformation`/`datapipeline`/`sagemaker` create | same idea via other compute services |
| `sts:AssumeRole` on a role whose trust policy allows you | assume a more powerful role directly |
| `iam:UpdateAssumeRolePolicy` + `sts:AssumeRole` | rewrite a role's trust policy to allow yourself, then assume it |
| `lambda:UpdateFunctionCode` on a function with a powerful role | overwrite the code, run as that role |
| `ec2-instance-connect:SendSSHPublicKey` + reachable instance | push a key and log in |

The unifying theme: `iam:PassRole` hands another role's permissions to a compute service you can
run code on; and any `iam:Put*/Attach*/Create*PolicyVersion` lets you rewrite your own grants.

### Trust policies and `sts:AssumeRole`

A role can be assumed by whoever its trust policy names. Overly broad trust policies -
`"Principal": {"AWS": "*"}` or a wildcarded account - let an outsider assume the role. Enumerate
roles (`iam:ListRoles`) and read each trust document; a role trusting your account (or `*`) that
also has strong permissions is a direct escalation.

## Procedure

```bash
# 0) identity
aws sts get-caller-identity

# 1) region and account context
aws ec2 describe-regions --query 'Regions[].RegionName' --output text 2>/dev/null

# 2) try to read your own policy
ME=$(aws sts get-caller-identity --query Arn --output text)
# for a user:
aws iam list-attached-user-policies --user-name "${ME##*/}" 2>/dev/null
aws iam list-user-policies --user-name "${ME##*/}" 2>/dev/null

# 3) if that is denied, enumerate by probing (non-destructive read calls)
#    enumerate-iam --access-key ... --secret-key ...
#    or Pacu: run iam__enum_permissions

# 4) look for the objective directly -- often faster than full escalation
aws s3 ls
aws secretsmanager list-secrets 2>/dev/null
aws ssm describe-parameters 2>/dev/null
aws lambda list-functions 2>/dev/null

# 5) enumerate roles and their trust policies for assume-role edges
aws iam list-roles --query 'Roles[].[RoleName,AssumeRolePolicyDocument]' 2>/dev/null
```

## Code - a read-only enumeration reporter

```python
#!/usr/bin/env python3
"""Read-only AWS credential triage: identity, self-permissions, and escalation-edge hints.

Uses boto3 and issues ONLY read/describe/list/simulate calls. It does not create,
modify, or assume anything; the escalation section reports which edges are POSSIBLE
given the enumerated permissions, it does not perform them.

Requires: pip install boto3
Credentials come from the standard boto3 chain (env vars, ~/.aws, or --profile).
"""
from __future__ import annotations

import sys

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    boto3 = None  # allow --self-test without boto3

# Escalation edges keyed by the permissions that enable them (Rhino Security Labs catalogue).
ESCALATION_EDGES = {
    "iam:CreatePolicyVersion": "create a new default policy version granting *:*",
    "iam:SetDefaultPolicyVersion": "revert a policy to an over-permissive existing version",
    "iam:AttachUserPolicy": "attach AdministratorAccess to yourself",
    "iam:AttachRolePolicy": "attach AdministratorAccess to a role you control",
    "iam:PutUserPolicy": "inline an admin policy onto your user",
    "iam:PutRolePolicy": "inline an admin policy onto a role",
    "iam:CreateAccessKey": "mint access keys for a more privileged user",
    "iam:CreateLoginProfile": "set a console password on a privileged user",
    "iam:UpdateLoginProfile": "reset a console password on a privileged user",
    "iam:PassRole": "hand a powerful role to a compute service (needs a run/create verb too)",
    "iam:UpdateAssumeRolePolicy": "rewrite a role's trust policy to allow yourself",
    "lambda:UpdateFunctionCode": "overwrite a function's code to run as its role",
    "sts:AssumeRole": "assume a role whose trust policy permits you",
}

# Actions worth simulating to detect the edges above.
PROBE_ACTIONS = list(ESCALATION_EDGES.keys()) + [
    "s3:ListAllMyBuckets", "s3:GetObject",
    "secretsmanager:GetSecretValue", "secretsmanager:ListSecrets",
    "ssm:GetParameter", "ec2:RunInstances", "lambda:CreateFunction",
    "iam:ListRoles", "iam:ListUsers",
]


def caller_identity(session) -> dict:
    return session.client("sts").get_caller_identity()


def simulate(iam, principal_arn: str, actions: list[str]) -> dict[str, str]:
    """Use IAM policy simulation to learn allow/deny per action, non-destructively."""
    results: dict[str, str] = {}
    # simulate in batches; the API caps at ~100 actions
    for i in range(0, len(actions), 50):
        batch = actions[i : i + 50]
        try:
            resp = iam.simulate_principal_policy(PolicySourceArn=principal_arn, ActionNames=batch)
        except ClientError as e:
            # simulation itself may be denied; fall back to "unknown"
            for a in batch:
                results[a] = f"unknown ({e.response['Error']['Code']})"
            continue
        for r in resp.get("EvaluationResults", []):
            results[r["EvalActionName"]] = r["EvalDecision"]  # allowed / explicitDeny / implicitDeny
    return results


def report_edges(decisions: dict[str, str]) -> list[str]:
    findings = []
    for action, why in ESCALATION_EDGES.items():
        if decisions.get(action) == "allowed":
            findings.append(f"{action}: {why}")
    return findings


def enumerate_light(session) -> None:
    """A few direct read calls that often reach the objective faster than escalation."""
    checks = [
        ("s3", "list_buckets", lambda r: [b["Name"] for b in r.get("Buckets", [])]),
        ("secretsmanager", "list_secrets", lambda r: [s["Name"] for s in r.get("SecretList", [])]),
        ("iam", "list_roles", lambda r: [x["RoleName"] for x in r.get("Roles", [])]),
        ("lambda", "list_functions", lambda r: [f["FunctionName"] for f in r.get("Functions", [])]),
    ]
    for svc, op, extract in checks:
        try:
            client = session.client(svc)
            resp = getattr(client, op)()
            items = extract(resp)
            print(f"  {svc}.{op}: {len(items)} item(s)" + (f" -> {items[:10]}" if items else ""))
        except (ClientError, Exception) as e:
            code = getattr(e, "response", {}).get("Error", {}).get("Code", type(e).__name__)
            print(f"  {svc}.{op}: {code}")


def main() -> int:
    if boto3 is None:
        print("boto3 not installed: pip install boto3")
        return 1
    profile = None
    if "--profile" in sys.argv:
        profile = sys.argv[sys.argv.index("--profile") + 1]
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()

    print("=== identity ===")
    try:
        ident = caller_identity(session)
    except NoCredentialsError:
        print("no credentials found in the boto3 chain")
        return 1
    except ClientError as e:
        print(f"get_caller_identity failed: {e}")
        return 1
    arn = ident["Arn"]
    print(f"account: {ident['Account']}")
    print(f"arn:     {arn}")
    print(f"userid:  {ident['UserId']}")

    print("\n=== permission simulation ===")
    iam = session.client("iam")
    decisions = simulate(iam, arn, PROBE_ACTIONS)
    for action in PROBE_ACTIONS:
        print(f"  {decisions.get(action, 'unknown'):>14}  {action}")

    print("\n=== escalation edges available ===")
    edges = report_edges(decisions)
    if edges:
        for e in edges:
            print(f"  [!] {e}")
        if decisions.get("iam:PassRole") == "allowed":
            print("      note: PassRole needs a paired compute verb "
                  "(ec2:RunInstances / lambda:CreateFunction / etc.)")
    else:
        print("  none detectable via simulation (simulation may itself be denied)")

    print("\n=== quick objective sweep ===")
    enumerate_light(session)
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        decisions = {"iam:AttachUserPolicy": "allowed", "iam:PassRole": "allowed",
                     "s3:GetObject": "implicitDeny"}
        edges = report_edges(decisions)
        assert any("AttachUserPolicy" in e for e in edges)
        assert any("PassRole" in e for e in edges)
        assert not any("GetObject" in e for e in edges)
        assert "iam:CreatePolicyVersion" in ESCALATION_EDGES
        print("[+] self-test ok")
        sys.exit(0)
    sys.exit(main())
```

## Variants & pitfalls

- **Temporary vs long-lived keys**: `ASIA...` keys require `AWS_SESSION_TOKEN`; without it every
  call fails with a signature error. `AKIA...` keys do not use a session token.
- **Policy simulation may be denied**: `iam:SimulatePrincipalPolicy` is itself a permission. When
  denied, fall back to `enumerate-iam` (probes real calls) or Pacu.
- **Region matters**: many services are regional; enumerate in the instance's region first
  (`AWS_DEFAULT_REGION`), then others.
- **CloudTrail**: enumeration and especially escalation attempts are logged. In an authorised
  assessment note this; in a CTF it usually does not matter, but noisy brute enumeration can trip
  rate limits.
- **`iam:PassRole` alone does nothing** - it needs a paired verb (`ec2:RunInstances`,
  `lambda:CreateFunction`, `glue:CreateDevEndpoint`, ...) and a target role to pass.
- **Boundary policies / SCPs**: an Organizations SCP or a permissions boundary can deny an action
  the identity policy allows; simulation accounts for boundaries but not always SCPs.
- **The objective is often reachable without escalating**: always try the direct read
  (`s3`, `secretsmanager`, `ssm`) before building an escalation chain.

## Hardening checklist

- Grant least privilege; avoid `iam:*`, `*:*`, and `PassRole` with wildcarded roles.
- Use permissions boundaries and Organizations SCPs to cap blast radius.
- Prefer short-lived roles over long-lived IAM user keys; rotate and monitor keys.
- Tighten role trust policies; never `"Principal": "*"`.
- Enable CloudTrail, GuardDuty, and Access Analyzer.

## Tools

- `aws` CLI, `jq`.
- `enumerate-iam` - brute-force read-only permission discovery.
- `Pacu` - AWS exploitation framework (`iam__enum_permissions`, `iam__privesc_scan`).
- `ScoutSuite`, `Prowler` - posture assessment across services.
- `PMapper` - graphs IAM escalation paths in an account.

## References

- AWS documentation: "Policy evaluation logic", "IAM JSON policy elements", "Using instance
  profiles".
- Rhino Security Labs: "AWS IAM Privilege Escalation Methods" (the catalogued edge list).
