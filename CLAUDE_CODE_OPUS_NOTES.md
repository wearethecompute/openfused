# Claude Code Opus Notes

Date: 2026-03-26
Branch: `a2a-compat-daemon`
Author: Codex

## Why This File Exists

This is a handoff note for Claude Code Opus.

It captures:

- what we discussed with the user
- how OpenFused compares to A2A
- why A2A compatibility is strategically useful
- what was implemented on this branch
- what is still missing
- what I think the best next steps are

## What The User Was Trying To Understand

The user started by asking for the open-source A2A protocol repo and how it compares to OpenFused.

The core confusion was:

- are these competing protocols
- are they compatible
- are they on different layers
- can OpenFused become A2A-compatible
- would A2A care about OpenFused

The user eventually landed on the right analogy:

- A2A is like talking to someone live
- OpenFused is like emailing someone and sharing a folder/notebook

That analogy is good enough to preserve.

## Canonical Comparison

### A2A

A2A is an agent interoperability protocol.

It standardizes:

- how one agent calls another
- how capabilities are advertised
- how long-running work is represented as tasks
- how progress/results are streamed or retrieved

It is an external API / interoperability layer.

### OpenFused

OpenFused is a file-native collaboration substrate for agents.

It provides:

- persistent shared context
- signed messaging
- optional encryption
- peer sync
- file-based collaboration
- registry and peer identity mechanisms

It is a persistence / collaboration / memory layer.

### Clean Relationship

These are different layers.

The best stack is:

- OpenFused underneath
- A2A on top

Meaning:

- OpenFused remains the durable store, identity, mailbox, and shared context substrate
- A2A becomes the standardized external interface

This is the main strategic insight from the conversation.

## Positioning Sentence For OpenFused

The best concise description produced in the conversation was:

"OpenFused is a file-native collaboration substrate for AI agents: a shared context mesh where agents exchange signed messages, sync state, and persist working memory through ordinary files."

A shorter GitHub description candidate was:

"File-native shared memory and signed messaging for AI agents."

## Adoption Assessment

My assessment to the user was:

- low chance of broad mainstream adoption as-is
- moderate chance of niche open-source or hacker adoption
- much stronger adoption odds if OpenFused gains A2A compatibility

Reason:

- OpenFused is differentiated and interesting
- but the ecosystem is clustering around MCP and A2A-like standards
- OpenFused as a substrate is stronger than OpenFused as a standalone alternative protocol pitch

So the strategic direction is:

- keep OpenFused's distinct file-native model
- add an A2A facade instead of competing head-on with A2A

## Review Of The Draft Strategy

We created a draft doc first:

- [A2A_COMPATIBILITY_DRAFT.md](./A2A_COMPATIBILITY_DRAFT.md)

That draft says:

- do not rewrite OpenFused into A2A internally
- add an A2A adapter/facade on top of the daemon
- keep OpenFused as the source of truth
- store A2A task state in the OpenFused store

I later reviewed that draft from both sides.

### My Review Summary

Useful to OpenFused:

- yes
- gives a standard ingress/interoperability surface

Useful to A2A:

- yes, but mostly as an implementation substrate, bridge, sample, or reference architecture
- probably not as a change to A2A core abstractions

Best collaboration target:

- integration
- bridge
- sample
- reference implementation

Not:

- trying to merge the concepts at the protocol-core level

### Gaps I Identified In The Draft

The draft is directionally right, but still weak in a few places:

1. It does not state a precise A2A conformance target.
2. It does not fully define runtime ownership of task execution.
3. It does not define locking/concurrency semantics for task state.
4. It does not provide a strict external state translation table.
5. It is still more architectural than operational.

So the draft is a good north star, not yet a complete implementation spec.

## What I Implemented On This Branch

I created branch:

- `a2a-compat-daemon`

I then implemented the first minimal A2A slice in the Rust daemon, not the TS side.

Files changed:

- [daemon/src/server.rs](./daemon/src/server.rs)
- [daemon/src/store.rs](./daemon/src/store.rs)

I did not modify unrelated user changes in:

- `.gitignore`
- `worker/`
- `.claude/`

### New A2A-ish HTTP Surface

Added routes:

- `GET /.well-known/agent-card.json`
- `POST /message:send`
- `GET /tasks`
- `GET /tasks/{id}`

These are intentionally the smallest useful slice.

Not yet implemented:

- `POST /message:stream`
- `POST /tasks/{id}:subscribe`
- `POST /tasks/{id}:cancel`
- push notifications
- extended agent card
- JSON-RPC binding

### What The New Routes Do

#### `GET /.well-known/agent-card.json`

Generates a simple A2A-style Agent Card from:

- `.mesh.json`
- `PROFILE.md`
- request host/proto headers

Current card includes:

- name
- description
- URL
- version
- protocolVersions
- input/output modes
- very simple capabilities block
- simple skill declarations

This is not fully rigorous A2A card modeling yet. It is a practical first pass.

#### `POST /message:send`

Accepts a minimal A2A-shaped request and creates a file-backed task.

It currently:

1. validates that message parts exist
2. creates a task id
3. writes task files under `tasks/<id>/`
4. returns a `task` object immediately

This does not yet execute the task. It only persists and exposes it.

#### `GET /tasks`

Lists stored tasks by reading `tasks/*/task.json`.

#### `GET /tasks/{id}`

Returns a specific stored task.

## New Task Storage Model

In the Rust daemon store I added:

- `TaskStatus`
- `TaskArtifact`
- `TaskRecord`

And store helpers:

- create task
- read task
- list tasks
- read profile text

Current canonical task layout:

- `tasks/<id>/task.json`
- `tasks/<id>/input.json`
- `tasks/<id>/events.ndjson`
- `tasks/<id>/artifacts/`

This mirrors the direction proposed in the draft.

## Verification I Performed

I built the daemon:

- `cargo build` in `daemon/`

Build succeeded.

I also did a localhost smoke test against a temporary store by running the daemon and calling the new routes.

Verified:

- agent card route returns JSON
- message send creates a task
- task get returns the created task
- task list returns the created task

There was one moment where `GET /tasks` initially came back empty during the smoke flow, but rechecking showed the task file was written and listing then worked. I did not find a reproducible persistent bug there afterward.

## Important Current Limitations

This branch is not A2A-complete.

It is only the first compatibility slice.

Big missing pieces:

### 1. No actual task runner contract

Right now `POST /message:send` creates durable task state, but nothing consumes it automatically.

Needed next:

- define who watches `tasks/<id>/input.json`
- define how the local runtime updates `task.json`
- define how outputs are written to `artifacts/`

### 2. No streaming

There is no SSE yet.

Needed next:

- `POST /message:stream`
- `POST /tasks/{id}:subscribe`
- event tailing from `events.ndjson`

### 3. No cancellation model

Needed next:

- cancellation state
- runtime contract for honoring cancellation

### 4. Agent Card is only a first pass

The card is practical but still under-specified versus full A2A semantics.

Needs:

- sharper skill mapping
- more precise auth declaration
- cleaner capability surface
- explicit conformance target

### 5. No real auth boundary for generic A2A clients yet

The OpenFused daemon still has its own internal security assumptions.

The A2A facade needs its own clean client auth story.

My recommendation is:

- do not force OpenFused keyring semantics directly onto generic A2A clients
- instead expose a standard A2A-facing auth scheme
- keep OpenFused trust semantics internal for mesh/peer exchange

## What I Think Should Happen Next

### Immediate next step

Implement the runtime contract, not more surface area.

Concretely:

1. define task execution ownership
2. update task status transitions on disk
3. make artifacts real
4. only then add streaming

If we add more endpoints before defining execution semantics, the facade will look broader than it really is.

### Strong next milestone

Minimal end-to-end A2A execution:

1. `POST /message:send`
2. task gets created
3. local runtime picks it up
4. task transitions `submitted -> working -> completed`
5. artifact or text result is written
6. `GET /tasks/{id}` returns meaningful progress/result

Once that works, streaming becomes much easier and much less speculative.

## Strategic Recommendation

Do not pitch this as:

- "OpenFused replaces A2A"

Do pitch it as:

- "OpenFused can be an A2A-compatible runtime and storage substrate"

That is a much stronger and more defensible story.

Best framing:

- A2A is the phone call / live conversation layer
- OpenFused is the email + shared drive + persistent notebook layer

Combined:

- A2A becomes the standard external interface
- OpenFused remains the durable shared context backend

That is the harmonized architecture.

## Notes On Collaboration With The A2A Side

Would A2A care?

Probably yes, if presented as:

- a bridge
- a sample implementation
- a reference architecture
- a backend/runtime pattern

Probably no, if presented as:

- a competing replacement protocol
- a request to reshape A2A around OpenFused

So if upstream collaboration ever happens, the likely good targets are:

- `a2aproject/a2a-samples`
- docs/discussion
- a separate integration repo

not necessarily changes to the A2A core spec repo.

## Final Practical Summary

Current state of this branch:

- concept validated
- draft doc written
- first daemon-based A2A ingress implemented
- durable task files added
- verified locally

What this branch is best viewed as:

- a foundation
- not yet a finished A2A implementation

If you continue this work, I would preserve the current design principle:

OpenFused stays the source of truth. A2A is a facade over OpenFused state, not a separate competing state model.
