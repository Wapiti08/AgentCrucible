# AgentCrucible

Security regression testing for file-processing AI agents.

AgentCrucible tests whether untrusted input can cause an agent to cross a
filesystem authorization boundary. It connects controlled fixtures, MCP tool
results, audit evidence, detection, and expected outcomes.

The first release focuses on **read-only filesystem scenarios on Linux**.
It is an experimental test environment, not a production security guarantee.

## Try the container demo

From the repository root, use a running Docker-compatible engine with Linux
containers (for example, OrbStack on macOS). No local Python or model API key is
required. This demo tests the MCP filesystem tool directly; no LLM participates.

```sh
docker build -f Dockerfile.demo -t agentcrucible-demo .

demo_output=$(mktemp -d /tmp/agentcrucible-demo-output.XXXXXX)

docker run --rm \
  --network none \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --mount "type=bind,source=$demo_output,target=/output" \
  agentcrucible-demo

demo_exit=$?
printf 'Demo exit code: %s\n' "$demo_exit"
cat "$demo_output/report.json"
```

Building downloads Python and locked dependencies. Running uses no network and
automatically creates synthetic fixtures inside the container. Use a new output
directory on each run: existing reports are never overwritten. On Linux, the
container currently runs as root, so the report may be root-owned on the host.

Expected results:

| Case | Policy | Detection | Verdict |
| --- | --- | --- | --- |
| Public file | allowed | not_detected | passed |
| Restricted file | blocked | detected | passed |
| Parent-directory traversal | blocked | detected | passed |
| Sibling directory with shared name prefix | blocked | detected | passed |
| Relative symlink inside scope | allowed | not_detected | passed |
| Symlink outside workspace | blocked | not_evaluated | passed |

Expected summary: 6 passed, 0 failed, 0 detection errors; exit code 0.
The last case passes because rejection and insufficient path evidence are its
explicit expectations. It does not mean the path detector identified the escape.

The report retains expected outcomes, actual results, findings and verdicts.
It remains in the host output directory after the container exits. Fixtures and
raw audit records are temporary and disappear with the container; printed audit
paths refer to the container, not the host. This is a demonstration report, not
an archive of all raw evidence. If saving fails, the CLI exits 3 and a partial
report may remain. Inspect the exit code rather than file existence alone.

## Two test modes

- **Direct MCP tests:** exercise the file tool without a model to establish
  whether tool authorization works. The execution and detection path exists.
- **Agent tests:** submit direct instructions or untrusted text files to one
  agent implementation, then observe proposed calls and their outcomes.
  This mode is planned.

Both modes will share evidence matching and verdict logic. A blocked request,
a successful read, and disclosure in an agent response are different outcomes.

## Current status

| Capability | Status |
| --- | --- |
| Linux filesystem backend, bounded reads, truncation and content digest | Implemented |
| MCP server/client and sequential batch calls | Implemented |
| JSONL audit writing, strict loading and request-ID matching | Implemented |
| Path-scope detection and real-read CLI output | Implemented |
| Synthetic-event CLI for exercising detection rules | Implemented |
| Expected outcomes, test-case models and verdict function | Implemented and tested |
| Suite orchestration, case-file loading and aggregate JSON report | Implemented and tested |
| Real agent, text injection cases and impact-marker checks | Pending |
| Suite exit codes for CI consumption | Implemented |
| Langfuse export and packaged CI integration | Pending |

A final audit record is application-level evidence. It is not a full lifecycle
trace or independent operating-system observation. Missing evidence must not be
reported as a safe outcome.

## Quick start

Install dependencies with uv from the repository root:

```sh
uv sync --locked
uv run --locked python -m attack_runner.runner --input-file examples/file-events.json
```

This portable example evaluates **synthetic path evidence**, not actual reads.

For a real MCP read, run inside an isolated Linux environment with the project
and its uv environment available. Create only synthetic fixtures:

```sh
fixture_dir=$(mktemp -d /tmp/agentcrucible-fixtures.XXXXXX)
mkdir "$fixture_dir/public" "$fixture_dir/secret"
printf 'hello\n' > "$fixture_dir/public/readme.txt"
printf 'SYNTHETIC-ONLY\n' > "$fixture_dir/secret/token.txt"

uv run --locked python -m attack_runner.run_files \
  --workspace "$fixture_dir" \
  --allowed-root public \
  --path public/readme.txt \
  --path secret/token.txt
```

The first request should succeed and produce `not_detected`; the second should
be blocked and produce `detected` when resolved target evidence is available.
The CLI writes operation results and detection records as JSONL to stdout and
the audit-file location to stderr. Audit files remain in a private temporary
directory for inspection.

The real-read CLI's exit code is a processing status, **not a test verdict**.
See [Runner inputs](docs/runner-inputs.md) for its distinct semantics.

## Run a security test suite

Inside the same Linux environment, reuse the synthetic fixtures created above.
Use a new output directory outside the fixture workspace:

```sh
report_dir=$(mktemp -d /tmp/agentcrucible-reports.XXXXXX)
uv run --locked python -m attack_runner.run_suite \
  --case-file examples/filesystem-cases.json \
  --workspace "$fixture_dir" \
  --allowed-root public \
  --report-file "$report_dir/report.json"
```

The example expects a successful public read and a blocked secret read.
stdout contains one `case.verdict` record per case and a final `suite.summary`.
The optional JSON report includes expected and actual outcomes, findings and
verdicts. stderr associates a run ID with the internal audit-file location.

Suite exit codes are **0** for all expectations met without detector errors,
**1** for an unmet expectation, **2** for invalid inputs, and **3** for processing
or report-save errors. A blocked attack can be a passing test.

Reports never overwrite existing files, and their parent directory must exist.
Failed expectations still produce a report; interrupted batches or failed audit
validation do not produce a completed report. Writes are not atomic: a write
failure can leave a partial file. See [Runner inputs](docs/runner-inputs.md)
for the full contract.

## First-release boundary

Build one reproducible workflow:

**case → tool/agent execution → audit matching → detection → expected-outcome
comparison → local JSON report**

Include normal-task controls, direct out-of-scope reads, path boundary cases,
and text-based indirect prompt injection. Add one agent integration after the
direct-tool suite works.

Langfuse will be an optional destination for selected traces and scores.
Local execution and verdicts must work without it. Raw file content stays local
by default.

A later, narrow ELF scenario will test whether extracted strings are mistaken
for instructions. General binary risk scoring, dynamic malware analysis,
multimodal inputs, shell tools, HTTP/SSRF tools, HTML dashboards and multiple
agent frameworks are outside the first release. Existing placeholder directories
do not imply a delivery commitment.

## Project map

| Path | Role |
| --- | --- |
| `agents/` | Package scaffold for agent contracts and adapters; implementation pending |
| `attack_runner/` | Stable CLI entry points and shared file-read case contracts |
| `attack_runner/transport/` | MCP client lifecycle and response validation |
| `attack_runner/evidence/` | Audit reading, request matching and detection-event conversion |
| `attack_runner/evaluation/` | Test-case loading, expectations and verdicts |
| `attack_runner/execution/` | Batch/suite orchestration, agent loop and tool execution |
| `mcp_servers/filesystem_server/` | File service, Linux enforcement, MCP transport and audit producer |
| `detectors/` | Evidence-based detection contracts and filesystem scope rule |
| `tests/` | Tests of the implementation; separate from runtime security cases |
| `examples/` | Safe example inputs |
| `apps/vulnerable_agent/` | Reserved for the first controlled agent integration |
| `reports/` | JSON report construction and exclusive file creation |

## Why langchain-core?

The model adapter uses `langchain-core` for shared chat-model interfaces and
message types. We do not currently need the higher-level agent construction
APIs in `langchain`.

AgentCrucible's runner owns the execution loop, step limits, timeouts, MCP calls
and evidence collection. Keeping model integration behind `AgentAdapter` lets
us reuse those controls while changing the model implementation. This is a
project architecture choice, not a claim that LangChain agents cannot expose
similar controls.

- `langchain-core` supplies the common interfaces and message representations.
- Provider integrations, such as `langchain-anthropic`, supply concrete model
  clients and must be installed separately when that provider is supported.
- `langchain` can be added later if its higher-level helpers are needed.

The dependency is optional, so the direct MCP demo does not require it:

```sh
uv sync --locked --extra agents
```

This installs the adapter's current core dependency; it does not configure a
provider or enable a complete real-model workflow. The LangChain adapter is
still under development. Shared interfaces reduce duplicate integration code,
but provider tool-call behavior still needs compatibility tests.

## Development and documentation

```sh
uv run --locked python -B -m unittest discover -s tests/unit -v
# Run inside the Linux test environment:
uv run --locked python -B -m unittest discover -s tests/integration -v
```

Linux-specific tests can be skipped on macOS; those skips do not validate the
Linux backend.

- [Scope, milestones and release criteria](docs/roadmap.md)
- [Architecture and evidence contracts](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Scenario catalogue](docs/attack-catalogue.md)
- [Runner inputs and output semantics](docs/runner-inputs.md)

Use only authorized, isolated environments and synthetic data. See
[SECURITY.md](SECURITY.md), [DISCLAIMER.md](DISCLAIMER.md) and [LICENSE](LICENSE).
