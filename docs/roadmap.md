# Focused Roadmap

## Product boundary

Build a security regression tool for file-processing agents. Its value is the
combination of controlled scenarios, actual tool-boundary evidence and explicit
expected outcomes, rather than a general observability dashboard.

No delivery dates are contractual. Complete each milestone's evidence and tests
before expanding the supported attack surface.

## M1 — Direct filesystem suite (current work)

Deliver:
- validated cases and expectations, with unique case IDs;
- suite orchestration over existing MCP execution, audit matching and detection;
- focused tests for verdicts, evidence failure and batch interruption;
- a versioned case-file contract and local aggregate JSON report;
- documented process exit codes separate from attack outcome;
- reproducible Linux fixtures and normal-read controls.

Acceptance: a documented command runs normal and out-of-scope cases, produces
per-case actual/expected outcomes, and fails clearly on unmet expectations or
incomplete processing. No real agent is required for M1.

## M2 — One file-processing agent

Deliver one adapter with bounded steps/calls, direct prompts and text-file
inputs. Record proposed calls and final output, and add synthetic marker checks.
Reuse M1 evidence and verdicts instead of duplicating the execution layer.

Acceptance: normal tasks complete; direct and indirect injection cases can be
repeated and inspected. Reports distinguish proposal, enforcement, returned
content and final-output disclosure. Model/configuration and repeat counts are
recorded; a single run is not presented as a general safety guarantee.

M1 + M2 define the core first release.

## M3 — Optional Langfuse and CI integration

Export selected traces and results with stable correlation identifiers.
Keep raw content local by default. Export failure must not overwrite the local
security verdict and must be separately reported.

Acceptance: the same tests work with export disabled; CI can consume documented
verdicts and processing status. An export proves neither evidence integrity nor
security by itself.

M3 can follow the core release; it must not block local usability.

## M4 — Narrow binary-input extension

Use a controlled ELF string extractor to test untrusted extracted text entering
agent context. Compare against equivalent text scenarios.

Acceptance: the scenario reuses existing policy/evidence/verdict contracts,
does not execute the sample, and reports extraction limits or failures.
General binary analysis is not a first-release dependency.

## Explicitly deferred

- Shell and Web/SSRF tool scenarios.
- Images, audio, video and steganography.
- General binary risk scores, malware execution and parser exploitation.
- Multiple agent frameworks and multi-tenant identity management.
- HTML dashboards and a general numerical risk-scoring framework.
- SandScope integration until independent process evidence is required.

Placeholder directories may remain. Do not build abstractions for deferred
features before a concrete requirement exists.
