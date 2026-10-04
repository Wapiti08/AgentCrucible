# AgentCrucible

A proving ground for AI agents and their tool boundaries.

AgentCrucible is a defensive security workbench for controlled attack simulations
against AI agents and MCP tools. Its goal is to connect authorization decisions,
runtime evidence, detection, and test verdicts in one reproducible experiment,
using synthetic data rather than real targets.

## Current Status

The project is under active development, starting with filesystem access.

- **Available:** a synthetic-event CLI with single-path, batch, and JSON input;
  a reusable detector engine; and the `FS_PATH_OUTSIDE_SCOPE` rule.
- **In progress:** the filesystem service and Linux backend, including directory
  handles, `openat2` bindings, and authorization-root checks. The safe file-read
  workflow is not complete.
- **Planned:** agent-to-MCP orchestration, attack-case verdicts, correlation,
  scoring, reports, SandScope integration, and shell/HTTP scenarios.

The current CLI evaluates supplied path evidence. It does **not** run an agent,
open target files, resolve symlinks, or prove that filesystem enforcement works.
This is an experimental lab, not a production security boundary.

## Quick Start

With [uv](https://docs.astral.sh/uv/) installed:

```sh
git clone https://github.com/Wapiti08/AgentCrucible.git
cd AgentCrucible
uv sync --locked
uv run --locked python -m attack_runner.runner --input-file examples/file-events.json
```

The example contains two synthetic events: a read within `/lab/public` produces
`not_detected`, and a read outside that scope produces `detected`.

You can also supply multiple paths sharing an authorization scope:

```sh
uv run --locked python -m attack_runner.runner \
  --path /lab/public/readme.txt /lab/secret/token.txt \
  --allowed-root /lab/public
```

The CLI can run on Linux or macOS; the filesystem backend is Linux-specific.
Linux backend integration tests should run in an isolated Linux container.

Exit code `0` means all events were evaluated, **including detected events**.
Code `1` indicates incomplete evaluation or detection errors; code `2` indicates
an input error. These codes are not attack outcomes or test verdicts.

See [Runner inputs](docs/runner-inputs.md) for the JSON contract and batch behavior.

## Intended Architecture

The target workflow is:

1. The runner loads a controlled attack case and its expected outcomes.
2. The agent proposes a tool call.
3. Policy evaluates the request against trusted authorization configuration.
4. The MCP tool executes only an allowed operation, within sandbox constraints.
5. Detectors evaluate evidence; correlation and scoring add context.
6. The runner compares observations with expectations and produces a report.

These are design responsibilities, not a claim that the full flow is implemented.
The agent's proposed arguments are untrusted. Detectors identify behavior but do
not grant permission; enforcement belongs at the tool boundary. A detector
finding alone is not evidence that protected content was actually read.

Run status, policy outcome, execution outcome, detection outcome, actual impact,
and test verdict remain separate. A blocked attack can be a passing test. An
intentionally vulnerable scenario can also pass when its expected behavior is
reproduced and verified.

## Project Layout

The table describes module responsibilities; see Current Status for availability.

| Path | Responsibility |
| --- | --- |
| `attack_runner/` | Input loading and detection CLI; future experiment orchestration and verdicts. |
| `apps/vulnerable_agent/` | Controlled test agent that proposes tool calls. |
| `mcp_servers/filesystem_server/` | Filesystem request/result models, service layer, and platform backends. |
| `mcp_servers/shell_server/`, `mcp_servers/web_server/` | Future command-execution and HTTP/SSRF scenarios. |
| `detectors/engine.py`, `detectors/rules/` | Common event/result contracts, rule dispatch, and focused detection rules. |
| `detectors/correlator.py`, `detectors/scoring.py` | Future evidence correlation and explainable risk scoring. |
| `sandbox/sandscope_adapter/` | Planned integration with the Rust SandScope sandbox. |
| `binary_analysis/` | Planned binary metadata extraction and risk rules. |
| `reports/` | Planned JSON and HTML reports. |
| `tests/`, `examples/` | Tests and safe example inputs. |
| `docs/` | Architecture, threat model, and attack catalogue. |

## Next Milestone: A Complete Filesystem Experiment

Complete the safe-read backend and service, then connect them to the runner.
The first end-to-end scenarios will cover:

- a normal read inside an authorized fixture directory;
- a direct request outside the authorized scope;
- a `..` traversal attempt;
- a symbolic-link escape attempt.

For a “path escape must be blocked” case, a passing verdict requires all expected
conditions: a blocked policy decision, no tool execution, the expected finding,
no protected synthetic content returned, and a complete event chain without
infrastructure errors.

Shell execution and HTTP/SSRF scenarios follow the filesystem workflow.
Langfuse is a planned optional observability adapter, not a dependency for
security evidence or core tests.

## Safety and Intended Use

Use this project only for authorized, isolated, non-destructive testing.
For execution scenarios:

- Use synthetic files, credentials, services, and exfiltration markers.
- Keep execution inside a dedicated test workspace.
- Do not target real credentials, user directories, public systems, or unrelated files.
- Deny outbound internet and host-network access by default.
- Avoid destructive commands, persistence, malware, and denial of service.

These are operating requirements, not guarantees currently enforced by every
component. Read the [security policy](SECURITY.md), [disclaimer](DISCLAIMER.md),
and [threat model](docs/threat-model.md) before running attack scenarios.

## Documentation

- [Architecture and event model](docs/architecture.md)
- [Runner inputs](docs/runner-inputs.md)
- [Threat model](docs/threat-model.md)
- [Attack catalogue](docs/attack-catalogue.md)
- [License](LICENSE)
