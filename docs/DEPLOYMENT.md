# Deployment

## Docker (recommended)

```bash
make docker-up              # build + run on http://localhost:8000
make docker-logs
make docker-down
make docker-up PORT=8123    # different port
```

The image bakes an index at build time. `content/` is bind-mounted read-only, and
`docker-entrypoint.sh` rebuilds the index on start if any markdown file is newer than
`data/index.db`, so editing notes on the host and restarting is all you need.

The built index lives in the named volume `ctfbrain-data`, not in the image layer, so
rebuilding the image does not discard it.

One-off commands:

```bash
docker compose run --rm ctfbrain search "padding oracle"
docker compose run --rm ctfbrain stats
docker compose exec ctfbrain /bin/bash
```

Why Docker is the safe default: it pins Python 3.12 with a SQLite that definitely has
FTS5. Some system Pythons ship without it, and CTF-Brain cannot run without FTS5.

## Local

```bash
make install && make index && make serve
```

To get `ctfbrain` on your `PATH`:

```bash
pipx install -e .                       # isolated, recommended
# or
echo 'export PATH="$HOME/ctf-brain/.venv/bin:$PATH"' >> ~/.zshrc
```

Requires Python 3.10+ with FTS5. Check with:

```bash
python3 -c "import sqlite3; sqlite3.connect(':memory:').execute('CREATE VIRTUAL TABLE t USING fts5(x)')"
```

Silence means you are fine.

## Sharing it with a team

It has **no authentication**, because it is a personal tool. Only expose it on a network you
control, and never on a competition network where other teams can reach it.

On a trusted LAN:

```bash
ctfbrain serve --host 0.0.0.0 --port 8000
# or, in compose, change the port mapping to "0.0.0.0:8000:8000"
```

Behind nginx with basic auth, if you must:

```nginx
location / {
    auth_basic           "ctf-brain";
    auth_basic_user_file /etc/nginx/.htpasswd;
    proxy_pass           http://127.0.0.1:8000;
    proxy_set_header     Host $host;
}
```

## Offline use

This is the intended mode. Once `content/` and `data/index.db` exist, nothing reaches the
network: the UI ships its own CSS and JS, syntax highlighting is server-side, and markdown
is rendered locally.

Only the `ingest/` pipelines need network, and only when you run them.

To prepare a laptop before a competition:

```bash
make ingest      # pull everything current
make index
make test        # confirm it works
```

Then unplug.

## Backups

Everything that matters is `content/`. It is plain markdown in git, so commit it.

```bash
git add content/ && git commit -m "notes from <ctf>"
```

`data/index.db` is derived and gitignored; `make index` rebuilds it in seconds.
`vendor/` is also derived, and `make ingest-vendor` recreates it, but committing it is
reasonable if you want the scripts available without network.

## Resource use

A corpus of a few thousand documents indexes in seconds and produces an index in the tens
of megabytes. The server idles at roughly 80-120 MB RSS. Queries are single-digit
milliseconds. It runs comfortably on anything.
