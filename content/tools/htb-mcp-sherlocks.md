---
title: "Tool - htb-mcp (Hack The Box MCP server) with Sherlock support"
category: sherlocks
subcategory: htb-api
type: tool
tags: [htb-mcp, mcp, claude-code, hackthebox, htb, sherlock, sherlocks, app-token, download, submit-answer, hacktheblue, automation]
summary: "Local MCP server (~/tools/htb-mcp) exposing HTB Labs to Claude: machines, challenges and Sherlocks (list, info, tasks, download, submit). Token file, restart, and gotchas."
tools: [htb-mcp, uv]
related: [htb-sherlock-api-submit, sherlock-triage]
---

## Where things live

| What | Path |
|---|---|
| Source (editable uv tool install) | `~/tools/htb-mcp` (GitHub `seriotonctf/htb-mcp`) |
| Launcher | `~/.local/bin/htb-mcp` |
| Token | `~/.config/htb-mcp/token` (mode 600, `HTB_TOKEN_FILE` in `~/.claude.json`) |
| Downloads | `~/.local/share/htb-mcp/downloads/sherlock-<id>-<ts>.zip` |

## Rotating the token

```sh
# HTB -> Profile -> Account Settings -> App Tokens -> create (1 year)
cp ~/.config/htb-mcp/token ~/.config/htb-mcp/token.bak.$(date +%s)
printf '%s' 'eyJ...' > ~/.config/htb-mcp/token && chmod 600 ~/.config/htb-mcp/token
# the server reads the file on every call, so no restart is needed for a new token
# symptom of an expired token: "HTTP 401: Token is invalid or expired"
```

## Sherlock tools

| Tool | Use |
|---|---|
| `sherlocks_list` | keyword/state/difficulty/category search (defaults to state=all) |
| `sherlock_categories` | category ids for filtering |
| `sherlock_info` | profile + scenario + file info (id or exact name) |
| `sherlock_tasks` | questions, masks, completed flags |
| `sherlock_download_link` / `sherlock_download` | zip saved privately; returns path, sha256, `archive_password: hacktheblue` |
| `sherlock_submit_task` | numeric sherlock id + task id + answer |

New tools appear only after the MCP server restarts (restart Claude Code).

## Workflow

1. `sherlock_tasks("SaSync")` and read every mask.
2. `sherlock_download("SaSync")`, then `7z x -phacktheblue <path>`.
3. Analyse (`ctfbrain show playbooks:sherlock-triage`).
4. Submit one sure answer first, then the rest, paced (HTB returns `Too Many Attempts.` after a burst).

## Development

```sh
cd ~/tools/htb-mcp
uv run pytest -q
uv run ruff check && uv run ruff format --check
uv run python scripts/generate_tool_docs.py   # regenerate docs/tools.md and docs/tool-schemas.json
```
