# AgentCrucible

Security regression testing for file-processing AI agents.

AgentCrucible tests whether untrusted input can cause an agent to cross a
filesystem authorization boundary. It connects controlled fixtures, MCP tool
results, audit evidence, detection, and expected outcomes.

The first release focuses on **read-only filesystem scenarios on Linux**.
It is an experimental test environment, not a production security guarantee.

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
| Expected outcomes, test-case models and verdict function | Written; integration and focused tests pending |
| Suite orchestration, case-file loading and aggregate JSON report | Pending |
| Real agent, text injection cases and impact-marker checks | Pending |
| Langfuse export and CI test-verdict interface | Pending |

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
| `attack_runner/` | MCP batch execution, audit matching, event conversion, expectations and future suite orchestration |
| `mcp_servers/filesystem_server/` | File service, Linux enforcement, MCP transport and audit producer |
| `detectors/` | Evidence-based detection contracts and filesystem scope rule |
| `tests/` | Tests of the implementation; separate from runtime security cases |
| `examples/` | Safe example inputs |
| `apps/vulnerable_agent/` | Reserved for the first controlled agent integration |
| `reports/` | Reserved for aggregate reports |

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
