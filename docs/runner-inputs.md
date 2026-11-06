# Runner inputs

## Synthetic evidence CLI

Run from the project root with Python 3.11 or later. These are synthetic
filesystem read events, not natural-language attacks. Target files are never
opened. Only the explicitly supplied JSON input file is read. Paths represent
upstream-resolved evidence; the CLI does not resolve symlinks.

Single or multiple paths sharing the same authorized roots:

```sh
uv run --locked python -m attack_runner.runner --path /lab/public/a --allowed-root /lab/public
uv run --locked python -m attack_runner.runner --path /lab/public/a /lab/secret/b --allowed-root /lab/public
```

Both `--path` and `--allowed-root` can be repeated. Omitting roots means an empty
allowlist (deny all). Paths containing spaces must be quoted.

For per-event authorization use a UTF-8 JSON object or non-empty list of objects:

```sh
uv run --locked python -m attack_runner.runner --input-file examples/file-events.json
```

Each object requires a string `path` and a string list `authorized_roots`.
An explicit empty list means deny all; missing roots are rejected. Optional
`event_id` must be a non-empty unique string; omitted IDs are generated as UUIDs.
Unknown fields are rejected to catch typos. JSON mode cannot be combined with
CLI paths or roots. All records are validated before detection starts.
Malformed paths are evaluated as `not_evaluated` by the rule, allowing the rest
of the batch to proceed. Results retain their event IDs and input order.

Programmatic callers can pass a dictionary or list to `load_events`, then pass
the returned events and one reusable Detector to `run_batch`.

Exit codes: 0 means every event was evaluated (including `detected`); 1 means
some event was not evaluated, errored, or had no applicable rules; 2 means CLI,
file, or input schema error. These are not attack success or test verdicts.

## Real filesystem MCP CLI

Run this mode in the isolated Linux test environment:

```sh
uv run --locked python -m attack_runner.run_files \
  --workspace /fixtures \
  --allowed-root public \
  --max-read-bytes 65536 \
  --path public/readme.txt \
  --path secret/token.txt
```

Create those synthetic fixtures beforehand. Unlike the synthetic CLI, this
command starts an MCP server and actually reads allowed files.

- Repeat `--path` once per input; IDs are assigned as `case-1`, `case-2`, etc.
- Repeat `--allowed-root` for multiple roots; omission means no allowed roots.
- Workspace and authorization configuration are fixed for the server session.
- An empty path can be submitted as a negative test input.
- The real-read CLI does not yet accept a case file or expected outcomes.

### Output and evidence

stdout is JSONL with two record shapes:
- Operation records contain case ID, path, request ID, policy/execution states,
  reason, byte count and truncation. They currently have no `record_type`.
- Detection records have `record_type: "detector.finding"`, case/request/event
  IDs, rule ID, status and reason.

Operation records are printed before audit validation. Their presence alone
does not mean audit processing or detection succeeded. Detection records appear
only after the normally completed batch has passed audit matching.

stderr reports the planned audit-file location and processing errors. Server
diagnostics may also appear, so stderr is not a guaranteed JSON-only stream.
Audit files are retained in a private temporary directory outside the workspace;
a printed location does not guarantee that startup created the file.

Public CLI records omit raw file content and internal authorization roots.
Internal audit records contain paths and should remain access-controlled.

### Real-read exit codes

| Code | Meaning |
| --- | --- |
| 0 | Batch, audit matching and detection processing completed without a reported detector error |
| 1 | Audit setup, batch, audit validation or detector error |
| 2 | Argument/configuration parsing error |

`detected` and `not_evaluated` do not by themselves cause exit 1 in this CLI.
This differs from the synthetic CLI above. Neither CLI currently returns an
aggregate expected-outcome test verdict.

On batch failure, completed operation results are retained, but the normal
audit/detection workflow is not run. Partial-run reconciliation is pending.

## Planned suite input

Runtime security cases will bind `FileReadCase` to `FileReadExpectation`.
The models and comparison function exist; orchestration, file format and CLI
integration are pending. Do not infer expected behavior from observed policy
results. See [roadmap](roadmap.md) for release criteria.
