---
title: "Kubernetes CTF - In-Pod Enumeration, Service Accounts and RBAC Probing"
category: cloud
subcategory: kubernetes
type: technique
tags: [cloud, kubernetes, k8s, kubectl, rbac, service-account, jwt, token, can-i, pod, namespace, etcd, apiserver, kubelet, enumeration, privilege-escalation, secrets]
difficulty: medium
summary: "From inside a pod: read the service-account token, ask the API what it can do with `kubectl auth can-i`, and map the escalation edges (secrets, pod-create, node access)."
when_to_use:
  - "You have a shell in a Kubernetes pod"
  - "You found a service-account token at /var/run/secrets/kubernetes.io/serviceaccount/token"
  - "The flag is a Kubernetes Secret, a ConfigMap, or lives on another pod/node"
  - "You need to know what your identity is permitted to do before acting"
tools: [kubectl, curl, jq, kubeletctl]
related: [container-escape, kubernetes-cheatsheet, cloud-metadata-ssrf, cloud-enum-script]
---

## TL;DR

Every pod gets a mounted service-account token that authenticates to the API server. The entire
game is: (1) read that token, (2) enumerate what it is authorised to do via `kubectl auth can-i`,
(3) follow the highest-value permission - reading Secrets, creating a pod, or reaching a node.

## Recognise it

- `/var/run/secrets/kubernetes.io/serviceaccount/` exists (token, ca.crt, namespace).
- Environment variables `KUBERNETES_SERVICE_HOST` / `KUBERNETES_SERVICE_PORT` are set.
- The challenge names a Secret, ConfigMap or a "control plane" you must reach.
- `kubectl` is on `$PATH`, or the API server responds on `https://kubernetes.default.svc`.

## Theory

### The service-account token

Kubernetes projects a JWT into every pod (unless `automountServiceAccountToken: false`). It
identifies the pod as `system:serviceaccount:<namespace>:<name>`. The API server authenticates the
token and then the RBAC authorizer decides each request. So possessing the token is not power by
itself - the *bindings* attached to that service account are.

Modern clusters use short-lived, audience-bound projected tokens (the `TokenRequest` API). Older or
legacy setups store a long-lived token in a Secret. Either way it is a bearer token: whoever has it
acts as that service account.

### RBAC model

- A **Role**/**ClusterRole** is a set of `(apiGroups, resources, verbs)` rules.
- A **RoleBinding**/**ClusterRoleBinding** attaches a Role to a subject (a service account, user, or
  group).
- Authorisation is additive and default-deny: a verb is allowed only if some binding grants it.

`kubectl auth can-i` asks the API server's `SelfSubjectAccessReview` - it is the authoritative,
non-destructive way to learn your permissions without trying each action.

### The escalation edges that matter

| Permission you hold | Why it escalates |
|---|---|
| `get/list secrets` | secrets often contain other tokens, cloud keys, DB passwords |
| `create pods` | schedule a pod that mounts a host path, uses a more powerful service account, or runs on a target node |
| `create pods/exec` or `pods/attach` | run commands in existing pods (other identities) |
| `get pods/log` | read logs that may contain credentials |
| `impersonate` (users/groups/serviceaccounts) | act as any identity, including cluster-admin |
| `escalate`/`bind` on roles | grant yourself more permissions |
| `create/update rolebindings` | bind yourself to a powerful role |
| `get nodes/proxy`, kubelet access | reach the kubelet API and every pod on a node |
| `list` across all namespaces | reconnaissance and lateral movement |

### The kubelet and etcd

- The **kubelet** on each node exposes an API (historically port 10250) that can list pods and, if
  authorization is misconfigured to `AlwaysAllow` or anonymous, exec into them. Modern clusters set
  `--authorization-mode=Webhook` and require a token.
- **etcd** stores all cluster state, including every Secret, usually unencrypted at rest unless
  encryption-at-rest is configured. Direct etcd access (port 2379) with the right client certs
  dumps everything. In a CTF, an exposed etcd or its client certificates is a common objective.

## Enumeration procedure

1. **Read the token bundle.**
```bash
SA=/var/run/secrets/kubernetes.io/serviceaccount
TOKEN=$(cat $SA/token)
NAMESPACE=$(cat $SA/namespace)
CACERT=$SA/ca.crt
APISERVER=https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT
```

2. **Decode the token to learn your identity** (a JWT; the middle segment is base64url JSON).
```bash
echo "$TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq .
```

3. **Ask the API what you can do.** Prefer `kubectl` if present; otherwise use `curl`.
```bash
# with kubectl (it reads the in-pod token automatically)
kubectl auth can-i --list
kubectl auth can-i get secrets
kubectl auth can-i create pods
kubectl auth can-i '*' '*'          # am I cluster-admin?

# without kubectl, via the SelfSubjectRulesReview API
curl -sk -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -X POST "$APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
  -d '{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"'"$NAMESPACE"'"}}' \
  | jq .
```

4. **List reachable resources** for each verb you were granted.
```bash
kubectl get secrets -A
kubectl get pods -A -o wide
kubectl get nodes
kubectl get configmaps -A
```

5. **Map the edges**: for every allowed verb in the table above, note the concrete objective it
   reaches. Record findings; do not chain destructively until you understand the blast radius.

## Code - a read-only RBAC and identity reporter

```python
#!/usr/bin/env python3
"""Enumerate the current pod's Kubernetes identity and permissions, read-only.

Uses only the in-pod service-account token and the API server's review endpoints,
which are non-destructive (they answer "could I", not "do it").

Python 3.11+, standard library only (urllib + ssl + json + base64).
"""
from __future__ import annotations

import base64
import json
import os
import ssl
import sys
import urllib.request

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"

# Permissions worth flagging if present, with why they matter.
HIGH_VALUE = {
    ("secrets", "get"): "read Secrets (tokens, cloud keys, passwords)",
    ("secrets", "list"): "enumerate Secrets cluster/namespace-wide",
    ("pods", "create"): "schedule pods (host mounts, other service accounts, target nodes)",
    ("pods/exec", "create"): "exec into existing pods (other identities)",
    ("pods/attach", "create"): "attach to existing pods",
    ("pods/log", "get"): "read pod logs (may leak credentials)",
    ("nodes", "get"): "node access / kubelet reach",
    ("nodes/proxy", "get"): "proxy to kubelet APIs",
    ("*", "*"): "cluster-admin",
    ("rolebindings", "create"): "bind yourself to more powerful roles",
    ("clusterrolebindings", "create"): "cluster-wide role binding",
    ("serviceaccounts/token", "create"): "mint tokens for other service accounts",
}
IMPERSONATE = ("users", "groups", "serviceaccounts")


def read_file(path: str) -> str:
    try:
        with open(path, "r") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def decode_jwt(token: str) -> dict:
    """Decode the JWT payload (no signature verification -- inspection only)."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


class ApiClient:
    def __init__(self, apiserver: str, token: str, cacert: str | None):
        self.apiserver = apiserver.rstrip("/")
        self.token = token
        self.ctx = ssl.create_default_context()
        if cacert and os.path.exists(cacert):
            self.ctx.load_verify_locations(cacert)
        else:
            # CTF clusters frequently use self-signed control-plane certs
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def post(self, path: str, body: dict) -> dict:
        req = urllib.request.Request(
            self.apiserver + path,
            data=json.dumps(body).encode(),
            method="POST",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(req, context=self.ctx, timeout=15) as resp:
            return json.loads(resp.read())

    def get(self, path: str) -> dict:
        req = urllib.request.Request(
            self.apiserver + path,
            headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, context=self.ctx, timeout=15) as resp:
            return json.loads(resp.read())

    def self_rules(self, namespace: str) -> dict:
        return self.post(
            "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
            {
                "kind": "SelfSubjectRulesReview",
                "apiVersion": "authorization.k8s.io/v1",
                "spec": {"namespace": namespace},
            },
        )


def analyse_rules(review: dict) -> list[str]:
    findings: list[str] = []
    rules = review.get("status", {}).get("resourceRules", [])
    for rule in rules:
        verbs = rule.get("verbs", [])
        resources = rule.get("resources", [])
        for res in resources:
            for verb in verbs:
                if (res, verb) in HIGH_VALUE:
                    findings.append(f"{verb} {res}: {HIGH_VALUE[(res, verb)]}")
                elif res == "*" and verb == "*":
                    findings.append("* * : cluster-admin over these resources")
    for rule in review.get("status", {}).get("nonResourceRules", []):
        pass  # non-resource URLs rarely matter for CTF objectives
    # impersonation is expressed as a verb on the "users"/"groups"/... resources
    for rule in rules:
        if "impersonate" in rule.get("verbs", []) and any(r in IMPERSONATE for r in rule.get("resources", [])):
            findings.append("impersonate: act as arbitrary users/groups/service accounts")
    return sorted(set(findings))


def main() -> int:
    token = read_file(f"{SA_DIR}/token")
    namespace = read_file(f"{SA_DIR}/namespace") or "default"
    cacert = f"{SA_DIR}/ca.crt"
    host = os.environ.get("KUBERNETES_SERVICE_HOST")
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")

    print("=== identity ===")
    if not token:
        print("no service-account token mounted (automountServiceAccountToken may be false)")
        return 1
    claims = decode_jwt(token)
    sub = claims.get("sub") or claims.get("kubernetes.io", {}).get("serviceaccount", {}).get("name")
    print(f"namespace: {namespace}")
    print(f"subject:   {sub}")
    if "exp" in claims:
        print(f"expires:   {claims['exp']} (epoch)")
    aud = claims.get("aud")
    if aud:
        print(f"audience:  {aud}")

    if not host:
        print("\nKUBERNETES_SERVICE_HOST is unset; cannot reach the API server from here.")
        return 0

    apiserver = f"https://{host}:{port}"
    print(f"\napi server: {apiserver}")
    client = ApiClient(apiserver, token, cacert)

    try:
        version = client.get("/version")
        print(f"version: {version.get('gitVersion', '?')}")
    except Exception as exc:
        print(f"[!] /version failed: {exc}")

    print("\n=== permissions (SelfSubjectRulesReview) ===")
    try:
        review = client.self_rules(namespace)
    except Exception as exc:
        print(f"[!] rules review failed: {exc}")
        return 2

    findings = analyse_rules(review)
    if findings:
        print("high-value permissions held:")
        for f in findings:
            print(f"  [!] {f}")
    else:
        print("no high-value permissions detected in this namespace")

    print("\nfull rule set:")
    for rule in review.get("status", {}).get("resourceRules", []):
        verbs = ",".join(rule.get("verbs", []))
        res = ",".join(rule.get("resources", []))
        groups = ",".join(rule.get("apiGroups", []) or ["core"])
        print(f"  verbs=[{verbs}] resources=[{res}] groups=[{groups}]")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        # offline checks of the pure parsers
        sample = (
            "eyJhbGciOiJSUzI1NiJ9."
            + base64.urlsafe_b64encode(json.dumps(
                {"sub": "system:serviceaccount:default:probe", "aud": ["api"], "exp": 1}
            ).encode()).decode().rstrip("=")
            + ".sig"
        )
        claims = decode_jwt(sample)
        assert claims["sub"] == "system:serviceaccount:default:probe"
        review = {"status": {"resourceRules": [
            {"verbs": ["get", "list"], "resources": ["secrets"], "apiGroups": [""]},
            {"verbs": ["create"], "resources": ["pods"], "apiGroups": [""]},
        ]}}
        fnd = analyse_rules(review)
        assert any("secrets" in f for f in fnd) and any("pods" in f for f in fnd), fnd
        print("[+] self-test ok")
        sys.exit(0)
    sys.exit(main())
```

## Variants & pitfalls

- **`automountServiceAccountToken: false`** means no token is mounted; look for one leaked in an
  env var, a ConfigMap, or another pod's mount instead.
- **Bound tokens** have an `aud` claim; they may only work against the API server audience, not
  arbitrary services.
- **`kubectl auth can-i --list`** requires the `SelfSubjectRulesReview` permission, which is granted
  to `system:authenticated` by default in most clusters - but not all. If it fails, probe individual
  verbs with `kubectl auth can-i <verb> <resource>`.
- **Namespace scoping**: a Role grants within one namespace; a ClusterRole across all. `can-i` is
  namespace-aware - check `-n kube-system` separately.
- **Read-only first**: enumerate before acting. Creating pods or bindings changes cluster state and
  may be logged; in a real assessment that matters, and in a CTF a failed destructive attempt can
  lock you out of a rate-limited instance.
- **The API server may be reachable but the kubelet is the target**: kubelet on 10250 with
  `--anonymous-auth=true` or `AlwaysAllow` is a separate, common misconfiguration.
- **etcd**: if you find etcd client certs (often in `/etc/kubernetes/pki/etcd`), the whole cluster
  state including Secrets is readable with `etcdctl`.
- **NetworkPolicy** may block pod-to-API or pod-to-pod traffic; a token you hold may be unusable
  from where you are.

## Hardening checklist

- Set `automountServiceAccountToken: false` on pods that do not call the API.
- Grant least-privilege RBAC; avoid wildcards and cluster-wide bindings.
- Never bind `cluster-admin` to a workload service account.
- Enable encryption-at-rest for Secrets and restrict etcd to the control plane.
- Set kubelet `--authorization-mode=Webhook` and `--anonymous-auth=false`.
- Use PodSecurity "restricted", NetworkPolicies, and audit logging.

## Tools

- `kubectl` (`auth can-i`, `get`, `describe`), with the in-pod token auto-detected.
- `kubeletctl` - kubelet API client for the node-level path.
- `kube-hunter` - cluster-external and in-pod misconfiguration scanner.
- `rbac-lookup`, `rakkess` - human-readable RBAC matrices.
- `etcdctl` - only where etcd access and certs are in scope.

## References

- Kubernetes documentation: "Using RBAC Authorization", "Configure Service Accounts for Pods",
  "Authorization Overview", "Reviewing your access with `kubectl auth can-i`".
- Kubernetes documentation: "Encrypting Secret Data at Rest".
