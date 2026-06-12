# Security Policy

## Supported Versions

| Version | Supported              |
| ------- | ---------------------- |
| 4.0.x   | ✅ Current             |
| 3.0.x   | ⚠️ Security fixes only |
| < 3.0   | ❌ End of life         |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email **alex@zanderpinkdesign.com** with:

1. Description of the vulnerability
2. Steps to reproduce
3. Affected versions
4. Impact assessment (if known)

You will receive an acknowledgment within **48 hours** and a detailed response within **5 business days**.

## Disclosure Policy

- We follow [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure).
- After a fix is released, we will publish a GitHub Security Advisory.
- Credit will be given to reporters unless they request otherwise.

## Security Architecture

CORD Engine is itself a security product — it evaluates AI agent actions for safety. Its own security posture:

| Layer                         | Mechanism                 | Description                                                         |
| ----------------------------- | ------------------------- | ------------------------------------------------------------------- |
| **14-Dimension Risk Scoring** | Constitutional evaluation | Every proposed action scored across 14 risk dimensions (0–99)       |
| **Hard Blocks**               | Non-overridable           | Critical safety violations cannot be bypassed by any user or system |
| **VIGIL Threat Scanner**      | Proactive defense         | Scans for prompt injection, canary tokens, trajectory anomalies     |
| **Red Team Validated**        | 40 attack scenarios       | 100% block rate across adversarial test suite                       |
| **Zero Dependencies**         | Self-contained            | No npm dependencies — entire engine is standalone                   |

## Dependency Policy

- **Zero runtime dependencies** — CORD Engine has no npm dependencies
- All evaluation logic is implemented from scratch
- No network calls during evaluation (fully offline-capable)

## Supply Chain

- Published to npm with provenance
- 482 tests across 13 test suites
- Red team validation suite included in repository
