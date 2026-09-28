# Running CTF-Brain

Everything below was run on this machine against this repo. Timings are real.

The stack is **one container**. There is no database server, no queue, no reverse
proxy. SQLite lives inside the container, the knowledge base is markdown on your
disk, and the web UI is three static files. That is the whole thing.

```
docker-compose.yml
  └── service: ctfbrain          image ctfbrain:latest, built from ./Dockerfile
        ports    8000 -> 8000
        volumes  ./content  -> /app/content   (read-only, your markdown)
                 ctfbrain-data -> /app/data   (named volume, the built index)
        health   curl /api/health every 30s
```

---

## Prerequisites

- Docker with Compose v2 (`docker compose`, not `docker-compose`). Check with
  `docker info` and `docker compose version`.
- Port 8000 free, or set `CTFBRAIN_PORT`.
- About 1.5 GB of disk for the image and the index volume.

Nothing else. No Python on the host, no network at runtime.

---

## Start it

```bash
cd /Users/macbook/ctfs/ctf-brain
docker compose up -d
```

Then open <http://localhost:8000>.

First run builds the image, which takes a few minutes: it installs dependencies,
copies the knowledge base and builds an index inside the image. A rebuild after a
code-only change is seconds, because the dependency layers are cached. A rebuild
after content changes re-runs the in-image index and takes a couple of minutes.

Startup is about 4 seconds when the baked index is current, and about 30 seconds
when it has to reindex first.

The `make` targets are thin wrappers if you prefer them:

| make | raw docker |
|---|---|
| `make docker-up` | `docker compose up -d` |
| `make docker-down` | `docker compose down` |
| `make docker-logs` | `docker compose logs -f` |
| `make docker-shell` | `docker compose exec ctfbrain /bin/bash` |
| `make docker-build` | `docker compose build` |

### A different port

```bash
CTFBRAIN_PORT=8123 docker compose up -d      # http://localhost:8123
```

The variable only changes the host side. Inside the container it is always 8000,
so the healthcheck and the entrypoint do not care.

Changing the port on an already-running stack is fine: Compose sees the mapping
differs and recreates the container for you. You do not need to `down` first.
Set the variable in your shell profile, or in a `.env` file next to
`docker-compose.yml`, if you want it to stick.

### Reachable from other machines on your LAN

By default Compose publishes on all interfaces already. **There is no
authentication**, so only do this on a network you trust, and never on a
competition network.

---

## Check it actually works

```bash
curl -s localhost:8000/api/health
# {"ok":true,"version":"1.0.0","documents":5359,"built_at":"..."}

docker compose ps            # want: Up (healthy)
docker compose logs --tail 20
```

`Up (health: starting)` for the first ~20 seconds is normal; that is the
healthcheck's `start_period`.

A fuller check:

```bash
curl -s 'localhost:8000/api/search?q=gcd&limit=3' | python3 -m json.tool | head -20
curl -s localhost:8000/api/stats | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["documents"], "docs")'
```

---

## Using it from the shell instead of the browser

The container runs the CLI too, so you do not need Python installed:

```bash
docker compose run --rm ctfbrain search "padding oracle"
docker compose run --rm ctfbrain search "heap uaf cat:pwn type:technique"
docker compose run --rm ctfbrain show techniques:crypto:rsa-common-modulus
docker compose run --rm ctfbrain stats
docker compose run --rm ctfbrain tags -c crypto
```

`--rm` throws the one-off container away afterwards. It shares the same index
volume as the running server, so results match.

Anything not in the entrypoint's command list is executed directly:

```bash
docker compose run --rm ctfbrain python -c "print('hi')"
docker compose run --rm ctfbrain sh
```

---

## After you add or edit content

`content/` is bind-mounted, so the container sees your edits immediately, but the
**search index does not update by itself**. The entrypoint rebuilds it on start
if any markdown file is newer than the index:

```bash
docker compose restart
```

That takes roughly 15 seconds for the current 5,359 documents. Confirm it
happened by watching `built_at` move:

```bash
curl -s localhost:8000/api/health
docker compose logs --tail 20        # prints the per-category counts when it reindexes
```

If you would rather reindex without a restart:

```bash
docker compose exec ctfbrain python -m ctfbrain.cli index
```

The running server notices the index file was replaced and reopens it on the next
query, so an already-open browser tab picks it up without a reload of the server.

### Ingestion pipelines need the host, not the container

The pipelines write into `content/`, which is mounted read-only inside the
container. Run them on the host with the project venv, then restart:

```bash
make ingest-notes SRC="/path/to/notes"
make add-repo URL=https://github.com/owner/name
docker compose restart
```

---

## Rebuild rules

Two different things, worth keeping straight:

| You changed | Do this |
|---|---|
| Anything in `content/` | `docker compose restart` |
| Python, JS, CSS, HTML, Dockerfile, requirements | `docker compose build && docker compose up -d` |

A `restart` reuses the existing image, so code changes will not appear until you
rebuild. If a change seems not to have landed, that is almost always why.

`docker compose build` on its own does not touch the running container, so the
site stays up while the new image is built. Only `up -d` swaps it, which is a
couple of seconds of downtime.

Force a fully clean image:

```bash
docker compose build --no-cache
docker compose up -d --force-recreate
```

---

## Stopping and cleaning up

Three levels, least to most destructive:

```bash
docker compose stop     # stop, keep container, image and index
docker compose down     # remove container and network, keep image and index volume
docker compose down -v  # also delete the index volume
```

`down -v` is safe. The index is derived from `content/`, and the next start
rebuilds it in about 15 seconds. Your markdown is never in the volume.

To reclaim the image too:

```bash
docker compose down -v
docker rmi ctfbrain:latest
```

---

## Running without Docker

Useful when you want to edit the code, or if Docker is not available.

```bash
make install     # creates .venv, installs dependencies
make index       # builds data/index.db from content/
make serve       # http://localhost:8000
```

Or directly:

```bash
.venv/bin/python -m ctfbrain.cli index
.venv/bin/python -m ctfbrain.cli serve --port 8000 --open
.venv/bin/ctfbrain search gcd
```

Requires Python 3.10+ **with FTS5 compiled in**. Check:

```bash
python3 -c "import sqlite3; sqlite3.connect(':memory:').execute('CREATE VIRTUAL TABLE t USING fts5(x)')"
```

Silence means you are fine. An error means use Docker, which pins a Python that
definitely has it.

---

## Troubleshooting

**Port 8000 already in use**

```bash
lsof -nP -iTCP:8000 -sTCP:LISTEN
CTFBRAIN_PORT=8123 docker compose up -d
```

Note a stray host-side `uvicorn` from a `make serve` session is a common cause.
Kill it with `pkill -f "uvicorn ctfbrain.api"`.

**Container restarts in a loop**

```bash
docker compose logs --tail 50
```

`restart: unless-stopped` means a crash retries forever and the logs are the only
way to see why.

**A document you just added is missing**

Two possibilities, in order:

```bash
docker compose run --rm ctfbrain lint      # frontmatter failed to parse?
docker compose restart                      # index just stale?
```

**Search returns nothing sensible**

Drop to a single word. Check the vocabulary actually in the corpus with
`docker compose run --rm ctfbrain tags -c crypto`. Tags are the primary search
surface, so a missing result is usually a tagging gap rather than a ranking one.

**`docker compose` not found**

You have the old standalone binary. Either install the Compose v2 plugin or
substitute `docker-compose` in every command above.

---

## What is where inside the container

```
/app/content     your markdown, read-only bind mount from ./content
/app/data        the named volume: index.db plus ingestion caches
/app/ctfbrain    the application code, baked into the image
/app/vendor      vendored upstream attack scripts, baked in
```

Poke around with:

```bash
docker compose exec ctfbrain sh
docker compose exec ctfbrain ls -la /app/data
docker compose exec ctfbrain du -sh /app/data
```

Current sizes: image about 700 MB, index volume about 130 MB.
