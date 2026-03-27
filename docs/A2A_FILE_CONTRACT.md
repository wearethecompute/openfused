# A2A File Contract

How any agent participates in A2A tasks through OpenFused's file-native store.

## Principle

The daemon is a mailbox, not a runtime. It translates HTTP to files and files to HTTP. Your agent reads files to get work. Your agent writes files to report progress. The daemon serves whatever is on disk.

No specific runtime, framework, language, or model is required.

## Task Directory Layout

When an A2A client sends a message, the daemon creates:

```
tasks/<task-id>/
├── task.json       ← canonical task state (status, history, artifacts)
├── input.json      ← original A2A request configuration
├── events.ndjson   ← append-only event log (one JSON object per line)
└── artifacts/      ← output files
```

## task.json

```json
{
  "id": "task_20260327_abc123",
  "contextId": "ctx_def456",
  "status": {
    "state": "submitted",
    "timestamp": "2026-03-27T12:00:00Z"
  },
  "artifacts": [],
  "history": [
    {
      "messageId": "msg-001",
      "role": "user",
      "parts": [{ "kind": "text", "text": "Summarize this document" }]
    }
  ],
  "_openfuse": {
    "createdAt": "2026-03-27T12:00:00Z",
    "updatedAt": "2026-03-27T12:00:00Z"
  }
}
```

## Task States

| State | Meaning | Terminal? |
|-------|---------|-----------|
| `submitted` | Task created, waiting for pickup | No |
| `working` | Agent is processing | No |
| `input-required` | Agent needs more info from the user | No |
| `auth-required` | Agent needs authentication | No |
| `completed` | Done successfully | Yes |
| `failed` | Failed | Yes |
| `canceled` | Canceled by client | Yes |
| `rejected` | Rejected by agent | Yes |

Terminal states are final. No further transitions are allowed.

## How to Pick Up a Task

1. Watch `tasks/` for new directories (inotify, polling, or `ls`)
2. Read `task.json` — check if `status.state` is `submitted`
3. Update `status.state` to `working` in `task.json`
4. Append a status event to `events.ndjson`

You can also use the HTTP endpoint:
```
POST /tasks/{id}/status
{"status": {"state": "working"}}
```

## How to Report Progress

Append a line to `events.ndjson`:

```json
{"timestamp":"2026-03-27T12:01:00Z","kind":"status","status":{"state":"working","message":{"messageId":"msg-002","role":"agent","parts":[{"text":"Processing page 3 of 10"}]}}}
```

Or use the HTTP endpoint:
```
POST /tasks/{id}/status
{"status": {"state": "working", "message": {"messageId": "msg-002", "role": "agent", "parts": [{"text": "Processing page 3 of 10"}]}}}
```

The SSE layer watches `events.ndjson` and pushes each new line to connected clients.

## How to Deliver Results

### Text results

Write the artifact to disk and update task.json:

```
tasks/<id>/artifacts/summary.md
```

Add to the `artifacts` array in `task.json`:

```json
{
  "artifactId": "art-001",
  "name": "summary.md",
  "parts": [{ "kind": "text", "text": "# Summary\n\n..." }]
}
```

Or use the HTTP endpoint:
```
POST /tasks/{id}/artifacts
{"artifactId": "art-001", "name": "summary.md", "parts": [{"text": "# Summary\n\n..."}]}
```

### Binary results

Write the file to `artifacts/` and reference it:

```json
{
  "artifactId": "art-002",
  "name": "chart.png",
  "parts": [{ "kind": "file", "file": {"mimeType": "image/png"}, "filename": "chart.png" }]
}
```

## How to Complete a Task

1. Write final artifacts
2. Set `status.state` to `completed` in `task.json`
3. Append a completion event to `events.ndjson`

```json
{"timestamp":"2026-03-27T12:05:00Z","kind":"status","status":{"state":"completed"}}
```

The daemon will serve the completed task to A2A clients. If an SSE stream is open, it will send the final task snapshot and close.

## events.ndjson Format

One JSON object per line. Each line has:

```json
{
  "timestamp": "ISO 8601",
  "kind": "status" | "artifact" | "message",
  "status": { ... },
  "artifact": { ... },
  "message": { ... }
}
```

Only one of `status`, `artifact`, or `message` is present per line (matching the `kind`).

## HTTP Endpoints (Reference)

| Route | Method | Purpose |
|-------|--------|---------|
| `/.well-known/agent-card.json` | GET | A2A discovery |
| `/message/send` | POST | Create task |
| `/message/stream` | POST | Create task + SSE stream |
| `/tasks` | GET | List tasks |
| `/tasks/{id}` | GET | Get task |
| `/tasks/{id}/cancel` | POST | Cancel task |
| `/tasks/{id}/subscribe` | POST | SSE subscribe to task |
| `/tasks/{id}/status` | POST | Update status (extension) |
| `/tasks/{id}/artifacts` | POST | Add artifact (extension) |

The `/status` and `/artifacts` endpoints are OpenFuse extensions — not part of the A2A spec but useful for agents that update tasks via HTTP instead of direct file writes.

## No Runtime Required

The daemon does not execute tasks. It only stores and serves them. Your agent can be:

- A Claude Code session reading the filesystem
- A Codex sandbox writing files
- A cron job running a Python script
- A shell script with `jq` and `curl`
- An MCP tool
- A human with a text editor

The files are the interface. Everything else is optional.
