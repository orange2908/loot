---
title: "SSRF - Cloud Metadata Services and What They Actually Give You"
category: web
subcategory: ssrf
type: technique
tags: [ssrf, cloud-metadata, imds, imdsv1, imdsv2, link-local, ec2, instance-profile, metadata-flavor, azure-imds, gcp-metadata, ecs-task-role, container-credentials, hop-limit, aws, gcp, azure, kubernetes, service-account]
difficulty: medium
summary: "169.254.169.254 answers any local process with no authentication; IMDSv2's token and hop limit are what turn a GET-only SSRF into a dead end."
when_to_use:
  - "You have SSRF against a workload running in a cloud environment"
  - "You need to know whether IMDSv2 actually blocks the SSRF you have"
  - "You are working out which provider's metadata conventions apply"
  - "Deciding whether recovered credentials are usable given your egress"
related: [ssrf-fundamentals, ssrf-bypass-filters]
tools: [burp, curl]
---

## TL;DR

Cloud instances expose a configuration service on a link-local address that is unrouted, unauthenticated, and
answers **any process on the instance**. SSRF makes your request look like such a process. Whether that
yields credentials depends on the provider's access requirements: a bare GET is enough for AWS IMDSv1 and for
nothing else. IMDSv2, GCP and Azure each require something a simple URL-fetch SSRF usually cannot supply.

## Recognise it

- The target is on EC2, GCE, Azure, or a container platform on top of one.
- SSRF confirmed, and the response body (or an error containing it) comes back to you.
- A fetch to `169.254.169.254` behaves differently from a fetch to an unroutable address - a fast response or
  a distinctive error rather than a timeout.
- Server headers, hostnames (`ip-10-0-1-23.ec2.internal`), or error traces naming a cloud SDK.

## Theory

### Why a link-local address

`169.254.0.0/16` is the IPv4 link-local range: not routable, valid only on the local link. Every major
provider uses `169.254.169.254` for instance metadata. The design assumption is that **being on the instance
is the authorisation** - anything able to send a packet from the instance is, by construction, already
running there.

SSRF breaks that assumption without breaking anything technical. Your request originates on the instance
because the server made it. The metadata service is behaving exactly as designed; the flawed premise is that
local origin implies trust.

What makes it a high-value target rather than a curiosity: the metadata tree contains the instance's
credentials. On AWS, an instance with an attached IAM role serves temporary credentials for that role through
the metadata service, which is the intended way for SDKs to obtain them.

### AWS: IMDSv1 versus IMDSv2

**IMDSv1** is a plain HTTP GET:

```
GET http://169.254.169.254/latest/meta-data/
```

The tree includes `iam/security-credentials/<role-name>`, which returns an access key, secret key and session
token; `/latest/user-data`, often containing bootstrap scripts and occasionally secrets; and
`/latest/dynamic/instance-identity/document` for region and account identifiers.

**IMDSv2** is session-oriented, and its design is specifically an SSRF countermeasure. To read anything you
must first obtain a token:

```
PUT http://169.254.169.254/latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600
```

and then send that token in `X-aws-ec2-metadata-token` on every subsequent request.

The three requirements this imposes map directly onto SSRF capability:

1. **A non-GET method.** The token request is a `PUT`. Most URL-fetch SSRF issues a GET and offers no way to
   change it.
2. **A custom request header.** Both the TTL header on the token request and the token header on the data
   request. Most SSRF cannot set arbitrary headers.
3. **Two chained requests**, with the response from the first used in the second. A single-shot SSRF cannot
   carry state between requests.

Additionally, IMDSv2 responses default to an **IP TTL of 1** (a "hop limit"), so the response cannot cross a
routing hop. Where the application runs in a container with a bridged network, the extra hop drops the packet
- which is why IMDSv2 frequently blocks access from a container even when the request is otherwise
well-formed.

The practical conclusion is unusually clean: **against IMDSv2, a plain GET-only SSRF gets nothing.** That is
worth establishing early rather than grinding at it. Instances can be configured to require IMDSv2
(`HttpTokens: required`), and that setting is the single most effective mitigation in this area.

### ECS and EKS: a different endpoint

Containers on ECS do not use the instance metadata service for credentials. Instead the container runtime
sets `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`, and the SDK fetches credentials from `169.254.170.2` plus that
path. Two consequences: the endpoint differs, and you generally need the environment variable's value, which
means a separate disclosure (an error page, `/proc/self/environ` via LFI, a debug endpoint).

On EKS, the modern pattern (IRSA / Pod Identity) delivers a projected service-account token as a **file** in
the pod, not through metadata. That makes it reachable via a file-read primitive rather than SSRF - a useful
distinction when deciding which bug you actually need.

### GCP

GCP's metadata server requires a header on every request:

```
Metadata-Flavor: Google
```

Requests without it are refused. This is deliberately an SSRF countermeasure: a plain URL fetch does not set
custom headers, so it cannot read metadata. An older alternative header (`X-Google-Metadata-Request: True`)
was removed. GCP also rejects requests carrying an `X-Forwarded-For` header, which blocks a proxy-based
route.

Metadata is reachable both at `169.254.169.254` and at the name `metadata.google.internal`. The
service-account token lives under
`/computeMetadata/v1/instance/service-accounts/default/token`, and the scopes granted to the instance bound
that token's reach - a token with only `devstorage.read_only` is not a general-purpose credential.

### Azure

Azure IMDS requires both a header and a query parameter:

```
GET http://169.254.169.254/metadata/instance?api-version=2021-02-01
Metadata: true
```

Same reasoning as GCP: the header requirement exists so that a naive fetch cannot reach it. Azure also
refuses requests that arrive with an `X-Forwarded-For` header. Managed-identity tokens come from
`/metadata/identity/oauth2/token` with a `resource` parameter, and the identity's role assignments bound what
the token can do.

### The pattern across providers

Provider defences converge on **requiring something a URL-fetch primitive cannot express**:

| Provider | Requirement | What SSRF needs |
|----------|------------|-----------------|
| AWS IMDSv1 | nothing | a GET |
| AWS IMDSv2 | PUT + header + chained request + hop limit 1 | full request control, on the host network |
| GCP | `Metadata-Flavor: Google` | header control |
| Azure | `Metadata: true` + api-version | header control |
| ECS | knowledge of a per-container path | a separate disclosure |

So the diagnostic question is not "can I reach 169.254.169.254" but "how much of the request can I control".
An SSRF through a full HTTP proxy feature, or one that reflects headers, is a different capability from one
that fetches a URL.

### What credentials do and do not get you

Recovered credentials are **temporary and scoped**. Realistic limits:

- They carry the permissions of the role, which may be narrow. A role that can read one bucket reads one
  bucket.
- They expire, typically in hours.
- Using them requires an egress path from wherever you are, or the ability to keep issuing requests through
  the SSRF - which is slow and awkward.
- Provider-side logging records their use, including the fact that they were used from an unusual address.

Determining what a credential can actually do is its own step, and it is entirely possible to recover
credentials that are worth nothing.

## Attack

1. **Establish the provider.** Hostnames, headers, error traces, or which metadata endpoint responds.
2. **Establish your request control.** Method? Headers? Redirects? Multiple chained requests? This decides
   everything that follows.
3. **Check whether the response comes back.** Blind SSRF against metadata yields nothing unless you can
   observe the result somehow.
4. **Try the provider's convention.** IMDSv1's bare GET, or the required header for GCP/Azure.
5. **If IMDSv2 is enforced, stop and reassess** - a GET-only SSRF will not get through, and time is better
   spent elsewhere.
6. **If credentials are recovered, enumerate their scope** before assuming impact.

## Code

An offline model: given an SSRF's capabilities, report which providers' metadata services are reachable and
why. It encodes the requirement table above, so the output is a capability analysis rather than a request.

```python
#!/usr/bin/env python3
"""Decide which cloud metadata services a given SSRF capability can reach.

Encodes each provider's access requirements (method, headers, chained requests,
network hop) and matches them against what an SSRF primitive can express.

Offline; pure decision logic. Makes no requests.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SsrfCapability:
    """What the SSRF primitive can actually express."""
    can_set_method: bool = False
    can_set_headers: bool = False
    can_chain_requests: bool = False     # use a response in a later request
    response_visible: bool = False
    same_network_namespace: bool = True  # False models a container hop
    can_set_query: bool = True


@dataclass
class MetadataService:
    provider: str
    endpoint: str
    needs_method: str | None = None
    needs_header: str | None = None
    needs_chain: bool = False
    needs_no_hop: bool = False
    needs_extra_disclosure: str | None = None
    credential_path: str = ""


SERVICES = [
    MetadataService("AWS IMDSv1", "169.254.169.254",
                    credential_path="/latest/meta-data/iam/security-credentials/<role>"),
    MetadataService("AWS IMDSv2", "169.254.169.254",
                    needs_method="PUT", needs_header="X-aws-ec2-metadata-token-ttl-seconds",
                    needs_chain=True, needs_no_hop=True,
                    credential_path="/latest/meta-data/iam/security-credentials/<role>"),
    MetadataService("GCP", "metadata.google.internal",
                    needs_header="Metadata-Flavor: Google",
                    credential_path="/computeMetadata/v1/instance/service-accounts/default/token"),
    MetadataService("Azure IMDS", "169.254.169.254",
                    needs_header="Metadata: true",
                    credential_path="/metadata/identity/oauth2/token?resource=..."),
    MetadataService("AWS ECS task role", "169.254.170.2",
                    needs_extra_disclosure="AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
                    credential_path="$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"),
]


def reachable(service: MetadataService, cap: SsrfCapability) -> tuple[bool, list[str]]:
    """Can this capability satisfy this service's requirements?"""
    blockers: list[str] = []
    if service.needs_method and not cap.can_set_method:
        blockers.append(f"needs a {service.needs_method} request; SSRF issues a GET")
    if service.needs_header and not cap.can_set_headers:
        blockers.append(f"needs header '{service.needs_header}'; SSRF cannot set headers")
    if service.needs_chain and not cap.can_chain_requests:
        blockers.append("needs a token from a first request reused in a second")
    if service.needs_no_hop and not cap.same_network_namespace:
        blockers.append("response TTL is 1; a container network hop drops it")
    if service.needs_extra_disclosure:
        blockers.append(f"needs the value of {service.needs_extra_disclosure} from another disclosure")
    if not cap.response_visible:
        blockers.append("response is not observable, so credentials cannot be read back")
    return (not blockers), blockers


def assess(cap: SsrfCapability, label: str) -> list[str]:
    print(f"\n== {label} ==")
    reached: list[str] = []
    for service in SERVICES:
        ok, blockers = reachable(service, cap)
        if ok:
            reached.append(service.provider)
            print(f"  [reachable] {service.provider:<20} {service.credential_path}")
        else:
            print(f"  [blocked  ] {service.provider:<20} {blockers[0]}")
            for extra in blockers[1:]:
                print(f"              {'':<20} {extra}")
    return reached


if __name__ == "__main__":
    # The classic shape: fetch a URL, see the body. Nothing else.
    basic = SsrfCapability(response_visible=True)
    got = assess(basic, "GET-only SSRF, response visible")
    assert got == ["AWS IMDSv1"], got
    print("  -> IMDSv1 only; every other provider needs something a GET cannot express")

    # Blind SSRF gets nothing here, even from IMDSv1.
    blind = SsrfCapability(response_visible=False)
    assert assess(blind, "blind SSRF (no response body)") == []
    print("  -> credentials are only useful if you can read them back")

    # Header control is what unlocks GCP and Azure.
    with_headers = SsrfCapability(can_set_headers=True, response_visible=True)
    got = assess(with_headers, "SSRF with header control")
    assert "GCP" in got and "Azure IMDS" in got
    assert "AWS IMDSv2" not in got, "IMDSv2 also needs a PUT and a chained request"

    # Full request control on the host network reaches IMDSv2.
    full = SsrfCapability(can_set_method=True, can_set_headers=True,
                          can_chain_requests=True, response_visible=True,
                          same_network_namespace=True)
    got = assess(full, "full request control, host network")
    assert "AWS IMDSv2" in got

    # The same capability from inside a container is stopped by the hop limit.
    containerised = SsrfCapability(can_set_method=True, can_set_headers=True,
                                   can_chain_requests=True, response_visible=True,
                                   same_network_namespace=False)
    got = assess(containerised, "full request control, container network hop")
    assert "AWS IMDSv2" not in got, "hop limit 1 drops the response across a bridge"
    assert "AWS IMDSv1" in got, "v1 has no hop restriction"
    print("  -> the hop limit is why IMDSv2 often blocks containers specifically")

    # ECS always needs a second disclosure, whatever the SSRF can do.
    assert "AWS ECS task role" not in assess(full, "full control vs ECS")
    print("  -> ECS credentials need the relative URI from the environment first")

    print("\nself-test ok")
```

## Variants & pitfalls

- **Establish request control before payloads.** It decides the entire outcome.
- **IMDSv2 genuinely stops GET-only SSRF.** Recognising that quickly is worth more than persistence.
- **The hop limit blocks containers** even with otherwise-full request control.
- **GCP and Azure reject `X-Forwarded-For`**, closing proxy-style routes.
- **`metadata.google.internal` and the IP are equivalent** on GCP; a blocklist that covers only one misses
  the other.
- **User-data often contains more than credentials** - bootstrap scripts, config, occasionally secrets.
- **Credentials may be worthless.** Enumerate the role's permissions before claiming impact.
- **Using recovered credentials is logged**, including the source address.
- **Alternative IP encodings** of `169.254.169.254` defeat naive string blocklists - see `ssrf-bypass-filters`.
- **Kubernetes service-account tokens are files, not metadata.** A file-read primitive reaches them; SSRF
  does not.

### Defence / what closes this

Require IMDSv2 on every instance (`HttpTokens: required`) and set the hop limit to 1 - this is the single
highest-value change, and it structurally defeats GET-only SSRF. Better still, set
`HttpEndpoint: disabled` on instances that do not need metadata at all. Attach the narrowest possible IAM
role, so that credentials recovered by any means are worth little, and prefer short-lived, workload-specific
identity (IRSA/Pod Identity on EKS, workload identity on GCP) over instance-wide roles. Block outbound
traffic to `169.254.0.0/16` from application containers with a network policy or local firewall rule, which
removes the reach regardless of application bugs. Apply the SSRF defences in `ssrf-fundamentals` - allowlist
destinations, resolve once and pin the address, disable redirect following - and never return fetched
response bodies to users. Keep bootstrap secrets out of user-data, using a secrets manager instead. Finally,
alert on credential use from outside the expected network, since that signal catches the cases where
everything else failed.

## Tools

- Burp Repeater - for varying method and headers when the SSRF exposes them.
- `curl` - confirm provider conventions against a test instance you own.
- Cloud provider CLIs - to enumerate what a recovered credential can actually do.

## References

- AWS, instance metadata and user data: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
- AWS, use IMDSv2: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- AWS, ECS task IAM roles: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
- Google Cloud, VM metadata: https://cloud.google.com/compute/docs/metadata/overview
- Google Cloud, querying metadata: https://cloud.google.com/compute/docs/metadata/querying-metadata
- Azure, instance metadata service: https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- PayloadsAllTheThings, SSRF (cloud metadata): https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
