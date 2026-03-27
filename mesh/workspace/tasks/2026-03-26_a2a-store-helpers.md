# A2A Store Helpers

**Status**: OPEN
**Assignee**: _unassigned_
**Created**: 2026-03-26

## Description
Add task lifecycle helpers to the daemon store (`daemon/src/store.rs`):

- `create_task(id, input_message)` — creates `tasks/<id>/` with task.json + input.json
- `update_task_status(id, state, message)` — updates task.json status
- `append_event(id, event)` — appends line to events.ndjson
- `write_artifact(id, artifact_name, content)` — writes to tasks/<id>/artifacts/
- `read_task(id)` — reads and returns task.json
- `list_tasks()` — lists all task directories

## Reference
- Design: `/A2A_COMPATIBILITY_DRAFT.md` (Object Mapping > Task section)
- File format: task.json example in the draft

## Acceptance Criteria
- All helpers work with the file-based task format from the draft
- Proper error handling for missing tasks
- Task state transitions validated (no going backwards except cancel)

## Outcome
_Fill in when DONE_
