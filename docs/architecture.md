# Architecture

## Scope

The first release tests filesystem authorization for file-processing agents.
The implemented foundation is a direct MCP read workflow; model-driven execution
and aggregate test reports are still pending.

## Implemented flow

```text
run_files CLI
  → run_file_batch
  → MCP client → filesystem MCP server → FileTools
  → FileService → LinuxFilePlatform
  → ReadResult → audit writer + public MCP response
  → audit reader → request-ID matching
  → SecurityEvent → Detector.detect
  → JSONL operation results and detector findings
```

The server writes its audit record before returning a normal tool response.
A failed audit write does not undo an operation that already happened.

The client reuses one MCP session for a sequential batch. The CLI loads audit
records after the normal batch and session shutdown complete.

## Responsibilities

| Module | Responsibility |
| --- | --- |
| `batch.py` | Validate cases, execute calls, preserve completed results on batch failure |
| `audit_reader.py` | Parse JSONL, reject malformed records and duplicate IDs |
| `audit_match.py` | Require one-to-one matching for a normally completed batch |
| `audit_events.py` | Convert matched evidence without re-reading or resolving paths |
| `expectations.py` | Compare policy, execution and one specified rule's status |
| `cases.py` | Bind each input to its expectation and validate case IDs |
| `suite.py` | Pending orchestration of execution, detection and verdicts |
| `FileService` | Bounded byte reads and result construction |
| `LinuxFilePlatform` | Directory handles, openat2 constraints and authorization checks |
| `Detector` | Dispatch rules and isolate rule errors; never authorize operations |

## Evidence contracts

The public MCP response contains request ID, policy and execution states, reason,
bounded content encoded as Base64, byte count, truncation and content digest.
It excludes resolved paths and authorized roots.

The internal audit record contains schema version, request ID, original path,
resolved path, authorized roots, policy state, execution state and reason.
It excludes file content. The audit file resides outside the test workspace.

Normal-batch matching requires:
- unique request IDs on both sides;
- no missing or additional audit records;
- matching original path, policy state, execution state and reason.

An aborted batch can have an audit record whose response never reached the
client. It requires separate reconciliation; normal-batch matching must not
label that record fabricated. That recovery workflow is not implemented.

The present audit is one final record per request, not a sequence of proposal,
policy and execution events. It cannot independently prove the absence of
`tool.execution_started`, nor defend against a compromised audit producer.

## Detection semantics

A filesystem SecurityEvent uses:
- `event_id = request_id + ":filesystem.read"`;
- `resource_type = "filesystem"`, `operation = "read"`;
- `FileAccessData(resolved_path, authorized_roots)`.

“Read” describes the requested operation, not proof that bytes were read.
Roots are converted from a JSON list to a tuple. Unknown roots remain `None`;
an empty tuple means no roots are authorized.

The path rule accepts absolute POSIX path evidence without NUL or unresolved
`..` components. It compares path components without filesystem access.
Repeated separators, including leading `//`, are treated as `/` under the
lab's path contract. This is not symlink resolution.

Out-of-scope target evidence produces `detected`. Missing or invalid evidence
produces `not_evaluated`, including some requests blocked before a target path
can be obtained. A policy block does not automatically imply a finding.

## Outcome separation

Keep run state, policy state, execution state, detection, impact and verdict
separate. The current expected-outcome function compares policy, execution and
the result of one specified rule for one event. Missing or duplicate matching
findings fail that expectation. Additional rules remain visible in output.

A verdict of `failed` means the expectation was not met, not that an attack
succeeded. Detector errors also remain operational failures. Marker disclosure
and a complete event-chain verdict are not implemented.

## Planned additions

1. Suite orchestration and canonical local JSON report.
2. One agent adapter with bounded steps and explicit tool-proposal records.
3. Text injection fixtures, normal controls and synthetic impact markers.
4. Optional Langfuse export correlated by run/request identifiers.
5. A narrow ELF-string extraction scenario reusing the same workflow.

Do not introduce a general causal-event framework, numerical risk scoring or
new platform adapters until a concrete scenario needs them.
