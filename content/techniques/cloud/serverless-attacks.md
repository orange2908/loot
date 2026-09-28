---
title: "Serverless - Lambda / Cloud Functions Env Leakage, Source Recovery, Handler Injection"
category: cloud
subcategory: serverless
type: technique
tags: [cloud, serverless, lambda, cloud-functions, azure-functions, environment-variables, source-recovery, event-injection, handler, iam-role, ssrf, cold-start, secrets, get-function]
difficulty: medium
summary: "Serverless functions leak secrets through env vars, expose their own source via the deploy API, and trust event input reaching the handler."
when_to_use:
  - "The target is an AWS Lambda, GCP Cloud Function, or Azure Function"
  - "You have credentials that can read function configuration or code"
  - "You can influence the event payload a handler receives"
  - "You need the function's role credentials or its environment secrets"
tools: [awscli, gcloud, az, jq, curl]
related: [aws-enumeration-privesc, cloud-metadata-ssrf, object-storage-misconfig, cicd-attacks]
---

## TL;DR

A serverless function is code plus an environment plus an execution role. Three recurring exposures:
secrets stored in environment variables (readable via the platform API or leaked in errors), the
source code downloadable through the deployment API, and event input that reaches an injectable sink
in the handler. The function's role credentials also live in the runtime environment.

## Recognise it

- A function ARN / name, a Function URL, or an API Gateway endpoint that fronts a Lambda.
- You hold credentials with `lambda:GetFunction*`, `cloudfunctions.functions.get`, or the Azure
  equivalent.
- A verbose error page that dumps a stack trace or `os.environ`.
- A handler that shells out, evaluates, deserialises, or builds a query from event fields.

## Theory

### Where secrets live in a serverless runtime

- **Environment variables** are the default (and worst) place teams put API keys, DB URLs and
  tokens. They are visible to anyone who can call `GetFunctionConfiguration`, and to any code
  running in the function (so any injection dumps them via `os.environ` / `process.env`).
- **The execution role's credentials** are injected into the runtime environment. In AWS Lambda they
  appear as `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, and are also served by
  a container-local credentials endpoint at `$AWS_CONTAINER_CREDENTIALS_FULL_URI` /
  `http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`. Code that runs in the handler can
  read these and then act with the role's IAM permissions (see `aws-enumeration-privesc`).

### Source recovery

The deployment API hands back the deployed artifact:

- **AWS**: `lambda:GetFunction` returns a presigned S3 URL (`Code.Location`) to the deployment
  package. Download and unzip it - you get the full source (interpreted runtimes) or the binary
  (compiled). `lambda:GetLayerVersion` does the same for layers.
- **GCP**: `cloudfunctions.functions.generateDownloadUrl` returns a signed URL to the source zip.
- **Azure**: the app's Kudu/SCM site (`https://<app>.scm.azurewebsites.net`) exposes the file
  system and a zip download when accessible.

Recovered source reveals hardcoded secrets, internal endpoints, and the exact sink to target with
event injection.

### Event / handler injection

The handler receives an event object assembled from the trigger (HTTP request, queue message, S3
notification, ...). If the handler passes event fields into a dangerous sink without validation:

- `os.system` / `subprocess` with an event string -> command injection.
- `eval` / `exec` / `pickle.loads` / `yaml.load` -> code execution.
- a SQL query built by concatenation -> SQL injection, now running with the role's DB access.
- an outbound request built from an event URL -> SSRF, which in a serverless context can reach the
  credentials endpoint above and exfiltrate the role.

The multiplier is that the injected code runs *as the execution role*, so a low-value injection can
become high-value cloud access.

### Cold starts and state

Serverless containers are reused across invocations (warm starts). Data left in `/tmp` or in
module-global variables from a previous invocation can leak between requests - a cross-tenant
concern where one function serves many users.

## Procedure

### AWS

```bash
FN=my-function

# configuration -- environment variables are right here
aws lambda get-function-configuration --function-name "$FN" \
  --query 'Environment.Variables'

# full function: role, runtime, and a presigned URL to the code
aws lambda get-function --function-name "$FN" \
  --query '{Role:Configuration.Role, Runtime:Configuration.Runtime, Code:Code.Location}'

# download and unpack the source
URL=$(aws lambda get-function --function-name "$FN" --query Code.Location --output text)
curl -s "$URL" -o code.zip && unzip -o code.zip -d code/

# enumerate every function quickly
aws lambda list-functions --query 'Functions[].[FunctionName,Runtime,Role]' --output text

# a Function URL (if configured) is directly invokable over HTTP
aws lambda get-function-url-config --function-name "$FN" --query FunctionUrl --output text
```

### GCP

```bash
FN=my-function; REGION=us-central1
gcloud functions describe "$FN" --region "$REGION" --format='value(serviceConfig.environmentVariables)'
gcloud functions describe "$FN" --region "$REGION" --format='value(serviceConfig.serviceAccountEmail)'
# signed URL to the deployed source zip
gcloud functions describe "$FN" --region "$REGION" --gen2 --format='value(buildConfig.source)'
```

### From inside a handler you can influence (AWS)

```bash
# these environment values exist in every Lambda runtime; injected code can read them
#   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN
#   AWS_CONTAINER_CREDENTIALS_FULL_URI (or _RELATIVE_URI under 169.254.170.2)
# an SSRF inside the function can hit the relative credentials endpoint:
curl -s "http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}"
```

## Code - a read-only Lambda triage helper

```python
#!/usr/bin/env python3
"""Read-only AWS Lambda triage: list functions, flag secret-looking env vars, and
report role + source location. Uses only Get/List calls; downloads nothing.

Requires: pip install boto3
"""
from __future__ import annotations

import re
import sys

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    boto3 = None

# Heuristics for environment values that look like secrets.
SECRET_KEY_HINTS = re.compile(
    r"(secret|token|key|passw|cred|api[_-]?key|private|conn|dsn|dburl|access)", re.I
)
SECRET_VALUE_HINTS = re.compile(
    r"^(AKIA|ASIA|AIza|sk_live_|xox[baprs]-|ghp_|eyJ|-----BEGIN)"
)


def looks_secret(key: str, value: str) -> str | None:
    if SECRET_KEY_HINTS.search(key):
        return "name suggests a secret"
    if SECRET_VALUE_HINTS.match(value or ""):
        return "value matches a known credential prefix"
    if len(value or "") >= 32 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", value or ""):
        return "long high-entropy value"
    return None


def triage(profile: str | None = None, region: str | None = None) -> int:
    if boto3 is None:
        print("boto3 not installed: pip install boto3")
        return 1
    session = boto3.Session(profile_name=profile, region_name=region)
    client = session.client("lambda")

    try:
        paginator = client.get_paginator("list_functions")
        functions = [f for page in paginator.paginate() for f in page["Functions"]]
    except ClientError as e:
        print(f"list_functions failed: {e}")
        return 2

    print(f"=== {len(functions)} function(s) ===")
    for fn in functions:
        name = fn["FunctionName"]
        print(f"\n# {name}")
        print(f"  runtime: {fn.get('Runtime', 'n/a')}")
        print(f"  role:    {fn.get('Role', 'n/a')}")
        env = fn.get("Environment", {}).get("Variables", {})
        if not env:
            print("  env:     (none)")
            continue
        print(f"  env:     {len(env)} variable(s)")
        for k, v in env.items():
            reason = looks_secret(k, str(v))
            if reason:
                masked = (str(v)[:4] + "..." + str(v)[-2:]) if len(str(v)) > 8 else "***"
                print(f"    [!] {k} = {masked}   ({reason})")
            else:
                print(f"        {k} = {v}")
    return 0


def main() -> int:
    profile = None
    region = None
    argv = sys.argv[1:]
    if "--profile" in argv:
        profile = argv[argv.index("--profile") + 1]
    if "--region" in argv:
        region = argv[argv.index("--region") + 1]
    return triage(profile, region)


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        assert looks_secret("DB_PASSWORD", "hunter2")
        assert looks_secret("api_key", "x")
        assert looks_secret("X", "AKIAIOSFODNN7EXAMPLE")
        assert looks_secret("TOKEN", "eyJhbGciOiJ")
        assert looks_secret("random", "a" * 40)  # long high-entropy
        assert looks_secret("LOG_LEVEL", "info") is None
        print("[+] self-test ok")
        sys.exit(0)
    sys.exit(main())
```

## Variants & pitfalls

- **Env vars are the first place to look and the most common win.** `get-function-configuration`
  needs only `lambda:GetFunctionConfiguration`.
- **KMS-encrypted env vars**: Lambda can encrypt environment values with a CMK; then the config
  shows ciphertext and you also need `kms:Decrypt` (which the function's own role usually has, so
  injected code can decrypt them, but an external reader may not).
- **Source download is a presigned URL** with a short expiry - fetch it immediately.
- **Compiled runtimes** (Go, Rust, .NET, Java) return a binary/jar, not readable source; still
  useful for strings and embedded secrets.
- **Function URLs and API Gateway** may have `AuthType: NONE`, i.e. anyone can invoke them.
- **The role is the real prize**: even a boring function often has a role with `s3`, `dynamodb`, or
  `secretsmanager` access. Recover the role name and enumerate it (`aws-enumeration-privesc`).
- **SSRF inside a function reaches `169.254.170.2`**, not `169.254.169.254`; the ECS/Lambda
  credentials endpoint is a relative URI in `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`.
- **Warm-container state**: secrets or other users' data may persist in `/tmp` or module globals
  between invocations.
- **GCP/Azure equivalents**: `generateDownloadUrl` for GCP source; the Kudu SCM site for Azure.

## Hardening checklist

- Store secrets in Secrets Manager / Parameter Store / Key Vault, not in environment variables; fetch
  at runtime with a scoped role.
- Grant the execution role least privilege; assume any injection runs as that role.
- Validate and type-check all event input before it reaches a sink; never pass event data to shell,
  eval, or unparameterised SQL.
- Set Function URL / API Gateway auth; do not deploy `AuthType: NONE` for sensitive functions.
- Encrypt environment variables with a CMK and restrict `kms:Decrypt`.

## Tools

- `aws lambda` (`get-function`, `get-function-configuration`, `list-functions`), `gcloud functions`,
  `az functionapp`.
- `Pacu` (`lambda__enum`), `ScoutSuite`, `Prowler`.
- `unzip` / `strings` for recovered packages.

## References

- AWS documentation: "Using Lambda environment variables", "Lambda execution role", "Lambda runtime
  environment credentials".
- Google Cloud documentation: "Cloud Functions - download source code".
