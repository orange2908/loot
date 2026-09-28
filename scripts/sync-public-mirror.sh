#!/usr/bin/env bash
#
# Publish the current branch to the public mirror as a single squashed commit.
#
#   GITHUB_TOKEN=xxx scripts/sync-public-mirror.sh
#   GITHUB_TOKEN=xxx scripts/sync-public-mirror.sh --dry-run
#
# Why a squashed snapshot rather than the full history: this repository's early
# commits contain credentials that were carried in ingested third-party
# writeups. They are redacted in the current tree, but they still exist in old
# commits, and GitHub push protection scans every commit in a push. Publishing a
# snapshot of the redacted tree keeps the public mirror clean without rewriting
# the private repository's history.
#
# The token is read from the environment and never written to disk, never added
# as a git remote, and scrubbed from any output.
set -euo pipefail

MIRROR_REPO="${MIRROR_REPO:-orange2908/loot}"
MIRROR_BRANCH="${MIRROR_BRANCH:-main}"
SOURCE_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
SNAPSHOT_BRANCH="public-snapshot-$$"
DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

die() { echo "error: $*" >&2; exit 1; }

[ -n "${GITHUB_TOKEN:-}" ] || die "set GITHUB_TOKEN (a PAT with push access to $MIRROR_REPO)"
[ -z "$(git status --porcelain)" ] || die "working tree is dirty; commit or stash first"

# Refuse to publish if a credential slipped back into the tree.
echo "==> scanning for credentials"
if git ls-files -z | xargs -0 grep -lPI \
     'AKIA(?!IOSFODNN7EXAMPLE|ABCDEFGHIJKLMNOP|XXXX)[0-9A-Z]{16}|ASIA(?!XXXX)[0-9A-Z]{16}|\b\d/\d{16}:[0-9a-f]{32}\b|AIzaSy[A-Za-z0-9_-]{33}|BEGIN [A-Z ]*PRIVATE KEY|xox[baprs]-[0-9A-Za-z-]{20,}|github_pat_[A-Za-z0-9_]{50,}' \
     2>/dev/null | grep . ; then
  die "credentials found in tracked files (listed above). Run the ingest redactor before publishing."
fi
echo "    clean"

cleanup() {
  git checkout --quiet "$SOURCE_BRANCH" 2>/dev/null || true
  git branch -D "$SNAPSHOT_BRANCH" --quiet 2>/dev/null || true
}
trap cleanup EXIT

echo "==> building snapshot from $SOURCE_BRANCH ($(git rev-parse --short HEAD))"
git checkout --quiet --orphan "$SNAPSHOT_BRANCH"
git add -A
git commit --quiet -m "CTF-Brain: offline, searchable CTF knowledge base

$(git --no-pager show -s --format=%s "$SOURCE_BRANCH") (source $(git rev-parse --short "$SOURCE_BRANCH"))

Public mirror of a private working repository, published as a single snapshot
commit. Ingested and vendored content belongs to its original authors; every
document carries a source link, and provenance is recorded in
vendor/PROVENANCE.md, content/reference/ext-CORPORA-PROVENANCE.md and
content/reference/chal-REPOS-PROVENANCE.md. Credentials appearing in mirrored
writeups are redacted. See LICENSE for the scope of each licence."

echo "    $(git ls-files | wc -l | tr -d ' ') files"

if [ "$DRY_RUN" = "1" ]; then
  echo "==> dry run, not pushing"
  exit 0
fi

echo "==> pushing to $MIRROR_REPO ($MIRROR_BRANCH)"
if ! git push --force \
      "https://x-access-token:${GITHUB_TOKEN}@github.com/${MIRROR_REPO}.git" \
      "${SNAPSHOT_BRANCH}:${MIRROR_BRANCH}" 2>&1 \
      | sed "s|${GITHUB_TOKEN}|***|g"; then
  die "push failed (output above, token scrubbed)"
fi

echo "==> done: https://github.com/${MIRROR_REPO}"
