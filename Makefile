# CTF-Brain
.DEFAULT_GOAL := help
SHELL := /bin/bash
VENV := .venv
PY   := $(VENV)/bin/python
PIP  := $(VENV)/bin/pip
PORT ?= 8000

.PHONY: help install venv index serve open search stats lint test clean catalog \
        docker-build docker-up docker-down docker-logs docker-shell \
        ingest ingest-ctftime ingest-github ingest-corpora ingest-vendor ingest-siunam \
        reindex check

help: ## Show this help
	@echo "CTF-Brain - offline CTF knowledge base"
	@echo ""
	@grep -hE '^[a-zA-Z_-]+:.*## ' $(lastword $(MAKEFILE_LIST)) \
	 | sed -E 's/^([a-zA-Z_-]+):.*## /\1|/' \
	 | awk -F'|' '{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "  Quick start:  make install && make index && make serve"

venv: $(VENV)/bin/python
$(VENV)/bin/python:
	python3 -m venv $(VENV)
	$(PIP) install --quiet --upgrade pip

install: venv ## Create the venv and install all dependencies
	$(PIP) install --quiet -r requirements.txt
	$(PIP) install --quiet -e .
	@echo "installed - now run: make index"

index: ## (Re)build the search index from content/
	$(PY) -m ctfbrain.cli index

reindex: index ## Alias for `index`

serve: ## Run the web UI on http://localhost:$(PORT)
	$(PY) -m ctfbrain.cli serve --port $(PORT)

open: ## Run the web UI and open a browser
	$(PY) -m ctfbrain.cli serve --port $(PORT) --open

search: ## Search from the shell: make search Q="padding oracle"
	@$(PY) -m ctfbrain.cli search $(Q)

stats: ## Corpus statistics
	@$(PY) -m ctfbrain.cli stats

catalog: ## Regenerate docs/CATALOG.md from the index
	$(PY) scripts/gen_catalog.py

lint: ## Report frontmatter problems in content/
	@$(PY) -m ctfbrain.cli lint -v

test: ## Run the test suite
	$(PY) -m pytest tests/ -q

check: index lint test ## Full local verification: index, lint, test

# ---------------------------------------------------------------- ingestion
ingest: ingest-ctftime ingest-github ingest-corpora ingest-repos ingest-siunam ## Run every ingestion pipeline, then reindex
	$(MAKE) index

ingest-siunam: ## Harvest siunam321's CTF writeups (siunam321.github.io)
	$(PY) ingest/siunam.py all

ingest-ctftime: ## Harvest writeups from ctftime.org
	$(PY) ingest/ctftime.py all

ingest-github: ## Harvest writeups from GitHub team repos
	$(PY) ingest/github_writeups.py all
	$(PY) ingest/alpacahack.py all

ingest-corpora: ## Mirror CTF Wiki / HackTricks / PayloadsAllTheThings / WSTG
	$(PY) ingest/reference_corpora.py all

ingest-repos: ## Re-ingest every tracked challenge repo
	$(PY) ingest/challenge_repos.py all

ingest-vendor: ## Vendor upstream attack scripts into vendor/
	$(PY) ingest/vendor_scripts.py all

ingest-notes: ## Import personal notes: make ingest-notes SRC="/path/to/notes"
	@test -n "$(SRC)" || (echo 'usage: make ingest-notes SRC="/path/to/notes"'; exit 1)
	$(PY) ingest/local_notes.py import --src "$(SRC)"
	$(MAKE) index

add-repo: ## Track and ingest a challenge repo: make add-repo URL=https://github.com/o/n
	@test -n "$(URL)" || (echo 'usage: make add-repo URL=https://github.com/owner/name'; exit 1)
	$(PY) ingest/challenge_repos.py add --url "$(URL)" --note "$(NOTE)"
	$(PY) ingest/challenge_repos.py all
	$(MAKE) index
	@echo ""
	@echo "Added. Find it with:  ctfbrain search \"\" --tag challenge-source"

repos: ## List the challenge repos being tracked
	@$(PY) ingest/challenge_repos.py list

# ------------------------------------------------------------------- docker
docker-build: ## Build the container image
	docker compose build

docker-up: ## Start CTF-Brain in Docker on http://localhost:$(PORT)
	CTFBRAIN_PORT=$(PORT) docker compose up -d
	@echo "CTF-Brain is starting at http://localhost:$(PORT)"

docker-down: ## Stop the container
	docker compose down

docker-logs: ## Tail container logs
	docker compose logs -f

docker-shell: ## Shell inside the running container
	docker compose exec ctfbrain /bin/bash

clean: ## Remove the index, caches and build artefacts
	rm -f data/index.db data/index.db-wal data/index.db-shm data/index.building*
	find . -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache *.egg-info
