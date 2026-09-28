#!/bin/sh
# CTF-Brain container entrypoint.
#   serve  (default) : reindex if needed, then run the web UI
#   index            : rebuild the index and exit
#   <anything else>  : exec it (e.g. `docker run ctfbrain search gcd`)
set -e

INDEX=${CTFBRAIN_DATA:-/app/data}/index.db
CONTENT=${CTFBRAIN_CONTENT:-/app/content}

reindex_if_stale() {
  # A bind-mounted content/ can be newer than the index baked into the image.
  if [ ! -f "$INDEX" ]; then
    echo "[ctfbrain] no index, building..."
    python -m ctfbrain.cli index --quiet
  elif [ -n "$(find "$CONTENT" -name '*.md' -newer "$INDEX" -print -quit 2>/dev/null)" ]; then
    echo "[ctfbrain] content is newer than the index, rebuilding..."
    python -m ctfbrain.cli index --quiet
  fi
}

case "$1" in
  serve)
    reindex_if_stale
    echo "[ctfbrain] serving on http://0.0.0.0:${PORT:-8000}"
    exec python -m uvicorn ctfbrain.api:app --host 0.0.0.0 --port "${PORT:-8000}" --log-level warning
    ;;
  index)
    exec python -m ctfbrain.cli index
    ;;
  search|show|stats|tags|lint|code|related|random|categories)
    reindex_if_stale
    exec python -m ctfbrain.cli "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
