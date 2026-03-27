# OpenFused A2A Compatibility Draft

Status: draft

Purpose: define the minimum architecture required to make OpenFused A2A-compatible without abandoning OpenFused's file-first model.

## Summary

OpenFused should not be rewritten into A2A internally.

The correct design is:

- OpenFused remains the persistence, sync, identity, mailbox, and shared-context substrate.
- An A2A adapter layer is added on top of the OpenFused daemon.
- A2A clients interact with OpenFused through standard A2A endpoints and objects.

This keeps the existing OpenFused model intact while making it interoperable with A2A ecosystems.

## Design Goals

- Make an OpenFused agent discoverable and callable by A2A clients.
- Keep OpenFused's file-native workflow and sync model.
- Avoid duplicating state across incompatible models.
- Use the current daemon as the HTTP entry point.
- Support the smallest useful A2A surface first.

## Non-Goals

- Replacing OpenFused's internal protocol with raw A2A objects.
- Requiring live RPC for all collaboration.
- Implementing every A2A feature in v1.
- Making OpenFused depend on a Google-specific stack.

## Layering Model

Three layers:

1. Transport and hosting
   HTTP, SSH, local filesystem, tunnels, mounted buckets.

2. OpenFused substrate
   `.mesh.json`, `PROFILE.md`, `CONTEXT.md`, `inbox/`, `outbox/`, `shared/`, `knowledge/`, peer sync, keyring, registry.

3. A2A interoperability facade
   Agent Card, message endpoints, task lifecycle, streaming, artifacts, optional push notifications.

The A2A facade translates external protocol calls into OpenFused store operations.

## Canonical Principle

OpenFused remains the source of truth.

A2A objects are projections over OpenFused state, not a second state model maintained independently.

That means:

- identity comes from OpenFused config and profile
- task state is stored in the OpenFused store
- artifacts are stored as OpenFused files
- A2A responses are generated from that stored state

## Object Mapping

### Identity

OpenFused source:

- `.mesh.json`
- `PROFILE.md`
- registry manifest

A2A target:

- `AgentCard`

Proposed mapping:

- `AgentCard.name` <- OpenFused agent name
- `AgentCard.description` <- parsed summary from `PROFILE.md`
- `AgentCard.url` <- daemon public base URL
- `AgentCard.skills` <- declared capabilities from profile/config
- `AgentCard.securitySchemes` <- OpenFused auth declaration
- `AgentCard.capabilities.streaming` <- true when SSE is enabled
- `AgentCard.capabilities.pushNotifications` <- false initially
- `AgentCard.protocolVersions` <- supported A2A versions

### Message

OpenFused source:

- signed inbox/outbox JSON envelope
- optional shared context references

A2A target:

- `Message`
- `Part`

Proposed mapping:

- plain text inbox message -> A2A `Message` with a text `Part`
- referenced shared file -> A2A file part or artifact reference
- structured JSON payload -> A2A data part

### Task

OpenFused does not currently have a first-class A2A task object.

Add canonical task storage:

`tasks/<task-id>/`

Proposed contents:

- `task.json` - canonical task metadata and current status
- `input.json` - normalized initial A2A request
- `events.ndjson` - ordered status and artifact events
- `artifacts/` - output files
- `result.json` - final A2A-facing response snapshot
- `log.md` - optional human-readable task trace

### Artifact

OpenFused source:

- files written by the agent
- structured outputs
- shared documents

A2A target:

- `Artifact`

Proposed mapping:

- text artifact -> file under `tasks/<id>/artifacts/*.md` or `*.txt`
- binary artifact -> file under `tasks/<id>/artifacts/*`
- structured artifact -> `*.json`

Artifacts should be referenced in `task.json` and exposed through A2A responses.

## Proposed File Format

Example `tasks/<id>/task.json`:

```json
{
  "id": "task_01",
  "contextId": "ctx_01",
  "status": {
    "state": "working",
    "message": "Analyzing attached file"
  },
  "createdAt": "2026-03-26T12:00:00Z",
  "updatedAt": "2026-03-26T12:00:10Z",
  "inputMessage": {
    "role": "user",
    "parts": [
      { "type": "text", "text": "Summarize this PDF" }
    ]
  },
  "artifacts": [
    {
      "id": "artifact_01",
      "name": "summary.md",
      "contentType": "text/markdown",
      "path": "tasks/task_01/artifacts/summary.md"
    }
  ]
}
```

## HTTP Surface

Add an A2A mode to the existing daemon rather than creating a separate server.

### Discovery

- `GET /.well-known/agent-card.json`

Returns the generated A2A Agent Card.

### Core message and task endpoints

- `POST /message:send`
- `POST /message:stream`
- `GET /tasks/{id}`
- `GET /tasks`
- `POST /tasks/{id}:cancel`
- `POST /tasks/{id}:subscribe`

### Optional later endpoints

- `GET /extendedAgentCard`
- push notification config endpoints

## Request Handling Model

### `POST /message:send`

Behavior:

1. Validate request.
2. Create `tasks/<id>/`.
3. Normalize incoming A2A request into OpenFused task files.
4. Write a task entry with initial state.
5. Deliver work to the local agent runtime.
6. Return either:
   - a direct `Message` for trivial synchronous responses
   - a `Task` for normal OpenFused-backed execution

### `POST /message:stream`

Behavior:

1. Create or resume a task.
2. Open SSE stream.
3. Emit initial task snapshot.
4. Tail `events.ndjson`.
5. Close when the task reaches a terminal state.

### `GET /tasks/{id}`

Behavior:

- Read `tasks/<id>/task.json`
- Return current normalized A2A task object

### `POST /tasks/{id}:cancel`

Behavior:

- mark task as cancel requested
- if runtime supports cancellation, propagate it
- update task status to canceled when complete

## Runtime Contract

The A2A layer should not implement agent intelligence.

It should hand work to the existing OpenFused-controlled agent runtime through store writes.

Possible contract:

- incoming A2A task creates `tasks/<id>/input.json`
- local agent watcher notices new task
- agent writes progress updates to `events.ndjson`
- agent writes outputs to `artifacts/`
- agent updates `task.json`

This preserves the file-native OpenFused model.

## Agent Card Generation

Agent Card should be generated, not hand-maintained.

Inputs:

- `.mesh.json`
- `PROFILE.md`
- daemon bind/public URL
- enabled A2A features

Fields to expose:

- agent name
- description
- version
- skills
- default input modes
- default output modes
- authentication requirements
- streaming support
- push notification support
- supported A2A versions

## Auth Model

Minimum viable A2A auth for OpenFused:

- unauthenticated public Agent Card
- optional bearer token or signed-request auth for task endpoints
- OpenFused key-based trust remains internal and peer-oriented

Do not force OpenFused peer key semantics directly onto generic A2A clients.

Instead:

- external A2A auth protects the HTTP API
- internal OpenFused signing and trust protects store-level agent exchange

## Streaming Model

Use SSE first.

SSE event source should be derived from task event files:

- append each state transition to `events.ndjson`
- SSE endpoint tails that file
- map each line to A2A stream event payloads

This matches OpenFused's durable file-first design and avoids keeping state only in memory.

## Artifact Model

Artifacts should be durable files, not transient response-only payloads.

Rules:

- every artifact gets a stable ID
- every artifact has a file path
- metadata lives in `task.json`
- small artifacts may also be inlined in A2A responses
- binary artifacts should remain on disk and be referenced

## State Model

Recommended minimal states:

- `submitted`
- `working`
- `input_required`
- `completed`
- `failed`
- `canceled`

Each change should be written both to:

- `task.json`
- `events.ndjson`

## Compatibility Strategy

### Phase 1: Minimal viable A2A facade

- generate Agent Card
- implement `POST /message:send`
- implement `GET /tasks/{id}`
- store tasks under `tasks/`
- support text-only messages
- support file artifacts

### Phase 2: Streaming

- implement `POST /message:stream`
- implement `POST /tasks/{id}:subscribe`
- SSE from `events.ndjson`

### Phase 3: Richer parts and auth

- structured data parts
- file parts
- bearer or signed request auth
- better capability declaration

### Phase 4: Optional advanced A2A features

- push notifications
- extended agent card
- task history exposure
- JSON-RPC binding if needed

## Changes Needed In This Repo

### Daemon

Add routes:

- `GET /.well-known/agent-card.json`
- `POST /message:send`
- `POST /message:stream`
- `GET /tasks/{id}`
- `GET /tasks`
- `POST /tasks/{id}:cancel`
- `POST /tasks/{id}:subscribe`

### Store

Add helpers for:

- create task
- update task status
- append task event
- write artifact
- read task
- list tasks

### Runtime integration

Define how the local agent consumes new tasks and emits progress.

### Docs

Document:

- OpenFused native mode
- OpenFused A2A-compatible mode
- what is preserved
- what is projected

## What This Buys Us

- OpenFused agents become callable by A2A clients
- OpenFused keeps its async durable collaboration model
- A2A gets a file-backed runtime with strong persistence
- no need to choose between "phone call" and "email plus shared drive"

## Recommended Positioning

Suggested positioning:

"OpenFused is a file-native agent substrate. In native mode it provides shared context, signed mail, and peer sync. In A2A mode it exposes a standard agent interoperability facade over the same durable store."

That statement is accurate and does not force the two systems into the same abstraction.
