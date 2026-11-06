# Threat Model

## Security question

Can an untrusted instruction or file cause a file-processing agent to request
or perform a read outside its configured authorization scope?

The current implementation exercises the file tool directly. Agent-driven
prompt injection is the next layer, not an existing tested capability.

## Assets and boundaries

Protect synthetic restricted files, the integrity of test evidence, and host
data outside the isolated fixture environment.

Trusted setup consists of the test operator, fixed workspace/authorization
configuration, test harness and enforcement implementation. Attack-controlled
data consists of request paths and, in planned agent tests, prompts and fixture
contents. Agent-generated tool arguments must not override authorization roots.

Boundaries are:
1. Untrusted text or extracted file content entering agent context (planned).
2. Agent or direct test input entering the MCP file tool.
3. Tool authorization and Linux filesystem access.
4. Tool response and internal audit entering detection and verdict processing.
5. Selected results leaving the local environment for optional export (planned).

Direct MCP tests deliberately bypass the agent to isolate tool behavior. They
do not establish that a model can be induced to make the same call.

## In scope

- Reads inside and outside authorized fixture directories.
- Traversal, sibling-prefix and symbolic-link boundary cases.
- Missing, malformed or inconsistent evidence.
- Direct and text-file indirect prompt injection (planned).
- Synthetic protected content reaching a tool response or agent output
  (planned impact checks).

## Attacker and environment assumptions

An attacker can control scenario input and declared untrusted fixture content.
They cannot change trusted root configuration, detector implementation or audit
storage during a run. Fixtures and mount topology remain stable during tests.

A malicious privileged process, compromised kernel or compromised MCP audit
producer is outside this model. Application audit is not independent proof
against such actors. Private audit directories and consistency checks do not
make records cryptographically tamper-proof.

Linux enforcement uses held directory descriptors and constrained openat2 calls.
This reduces path-resolution hazards within the supported contract; it is not
a claim of universal race, hard-link, mount-alias or container-escape protection.
macOS is a development host, not an equivalent tested enforcement backend.

## Evidence and conclusions

| Observation | Supported conclusion |
| --- | --- |
| Agent proposes an out-of-scope call | An attempted boundary violation; agent evidence is planned |
| Policy returns blocked | The service reports rejection |
| Valid resolved path lies outside roots | The path rule detects a scope violation |
| Tool returns protected synthetic bytes | Content reached the tool response, if independently matched |
| Synthetic marker appears in agent output | Disclosure to that output, if checked; planned |
| Missing evidence or not_evaluated | No conclusive detection result; never proof of safety |

The existing audit cannot establish a complete execution timeline. Do not infer
that no file descriptor was opened from `not_started`; internal path inspection
can occur before content access.

## Safe execution

Use isolated Linux fixtures containing only synthetic data. Do not mount real
credentials or unrelated host directories. Keep audit files outside the fixture
workspace. Bound returned content and use controlled test inputs.

Future model access requires explicitly approved provider connectivity without
granting the tested agent unrestricted network tools. Network isolation and
container resource limits are deployment responsibilities, not guarantees
provided by the current Python CLI.

No destructive operations, real exfiltration endpoints or uncontrolled resource
exhaustion tests belong in the first release.

## Deferred scope

Shell execution, HTTP/SSRF, multimodal and steganographic input, general malware
analysis, parser exploitation, cross-tenant identity management and independent
system telemetry are deferred.

A later ELF scenario will address extracted-text instruction injection only.
It will not establish that a binary is benign or malicious.
