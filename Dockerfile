# CTF-Brain - offline CTF knowledge base.
# Build:  docker build -t ctfbrain .
# Run:    docker run -p 8000:8000 -v "$PWD/content:/app/content:ro" ctfbrain
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    CTFBRAIN_ROOT=/app \
    CTFBRAIN_CONTENT=/app/content \
    CTFBRAIN_DATA=/app/data

WORKDIR /app

# System packages: git is used by the ingestion pipelines; curl powers the healthcheck.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Dependencies first, so edits to content/ or ctfbrain/ do not bust this layer.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml README.md ./
COPY ctfbrain/ ./ctfbrain/
COPY ingest/ ./ingest/
COPY docs/ ./docs/
COPY content/ ./content/

RUN pip install --no-cache-dir --no-deps -e . \
 && mkdir -p /app/data \
 && python -m ctfbrain.cli index --quiet

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

# entrypoint.sh reindexes when content/ is bind-mounted, then serves.
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["serve"]
