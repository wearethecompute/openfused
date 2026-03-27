# A2A Phase 1 — Daemon Routes

**Status**: OPEN
**Assignee**: _unassigned_
**Created**: 2026-03-26

## Description
Implement the Phase 1 A2A endpoints in the Rust daemon (`daemon/src/server.rs`):

1. `GET /.well-known/agent-card.json` — generated from .mesh.json + PROFILE.md
2. `POST /message:send` — create task, normalize A2A request, return Task object
3. `GET /tasks/{id}` — read task.json, return A2A task object
4. `GET /tasks` — list all tasks

## Reference
- Design: `/A2A_COMPATIBILITY_DRAFT.md`
- Daemon code: `daemon/src/server.rs`, `daemon/src/store.rs`

## Acceptance Criteria
- Agent Card served at well-known URL with correct fields
- Incoming message creates task directory with task.json + input.json
- Task retrieval returns proper A2A-shaped JSON
- All routes behind optional `--a2a` flag on daemon

## Outcome
_Fill in when DONE_
