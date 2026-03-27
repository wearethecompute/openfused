# Workspace Context

## Current Focus
A2A compatibility layer for the OpenFused daemon (see `/A2A_COMPATIBILITY_DRAFT.md`)

## Active Work
- **Branch**: `a2a-compat-daemon` (current)
- **daemon/src/server.rs** — modified, adding A2A routes
- **daemon/src/store.rs** — modified, adding task storage helpers
- **worker/** — being rebuilt (deleted old, new in progress)

## Architecture Decisions
- A2A is a facade over OpenFused's file-first store — NOT a replacement
- Tasks stored as files under `tasks/<id>/` in the store
- Agent Card generated from `.mesh.json` + `PROFILE.md`
- SSE streaming tails `events.ndjson` (file-backed, not in-memory)
- Auth: unauthenticated Agent Card, bearer token for task endpoints

## What Needs Doing
1. Daemon A2A routes (Phase 1): Agent Card, POST /message:send, GET /tasks/{id}
2. Store helpers: create_task, update_task_status, append_event, write_artifact
3. Task file format: task.json, input.json, events.ndjson, artifacts/
4. Tests for the A2A layer
5. Worker rebuild (registry + landing page)

## Recent
- Codex produced `A2A_COMPATIBILITY_DRAFT.md` — full design doc
- Branch `a2a-compat-daemon` created with initial daemon/store changes
