# Changelog

All notable changes to CORD Engine are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [4.3.1] — 2026-06-11

### Security

- **Path containment fix**: `isPathAllowed()` (cord.js) used `abs.startsWith(allowedPath)`, which matches sibling directory prefixes — `/tmp/project2` passed a scope check for `/tmp/project` even though the trees are unrelated. Both the repoRoot check and the allowPaths check now use `path.relative` to require a true parent-child relationship. This was a live scope escape: `isPathAllowed` had no second gate behind it.
- **Sandbox allow-list hardened** (sandbox.js): same sibling-prefix pattern in `validatePath()`'s first gate. The traversal check behind it already caught siblings, so this gate was not a live escape — but relying on the second gate as the rescue is one refactor away from silent loss of containment. Both gates now agree, and both now also reject cross-drive paths (`path.isAbsolute` on the relative result).
- Regression tests added for the sibling-prefix escape in both `cord.test.js` (verified to fail against the old code) and `sandbox.test.js` (defense-in-depth).
- This fix previously shipped only as a downstream postinstall patch in codebot-ai (`scripts/apply-cord-engine-patch.js`); it is now upstream.
- **VIGIL session ID collision fix** (memory.js): auto-generated session IDs were `vigil_${Date.now()}` — millisecond resolution, so two `startSession()` calls in the same millisecond collided and silently resurrected the previous session's threat memory instead of starting fresh. In practice: clean prompts could be memory-escalated to BLOCK by threats from a *previous* session (this surfaced as an intermittent false-positive in the test suite, ~3 in 10 runs). IDs now include a monotonic counter; regression test pins `Date.now` to force the collision deterministically.

## [4.2.0] — 2026-02-25

### Added

- **CORD Command Center** — real-time agent management dashboard (zero dependencies)
  - 8 pages: Dashboard, Agents, Skills, Channels, Sessions, Cron, Logs, Security
  - Live SSE streaming of CORD decisions and gateway logs
  - In-browser agent workspace editor (SOUL.md, IDENTITY.md, etc.)
  - Token/key sanitization on all API responses
- **Multi-agent system** — 4 specialized agents managed through CORD
  - Lazarus (⚡ main), Pink (🩷 brand ops), Sentinel (🛡️ security), Pixel (📱 social media)
- **Pixel social media agent** — Twitter/X, Instagram, TikTok content management
  - Social posting skill with Twitter API v2 integration
  - Content creator skill with brand voice guide and caption templates
  - Social analytics skill (shared) with weekly report format
  - Content calendar cadence and hashtag strategy
- **Shopify integration skill** — full Admin API coverage for Pink agent
  - Orders: list, get, fulfill with tracking
  - Products: list, create, update inventory levels
  - Customers: search, list
  - Analytics: order counts by status, product counts
  - Fallback to browser-based Shopify admin when API keys unavailable
- **Custom agent skills** — brand-ops, shopify-ops, sentinel-ops, cord-security, social-posting, content-creator, social-analytics

## [4.1.0] — 2026-02-25

### Added

- **Plan-level validation**: `validatePlan()` checks aggregate task lists for cross-task privilege escalation, data exfiltration chains, and cumulative network exposure
- **Framework adapters (JS)**: LangChain (`wrapLangChain`, `wrapChain`, `wrapTool`), CrewAI (`wrapCrewAgent`), AutoGen (`wrapAutoGenAgent`)
- **Framework adapters (Python)**: LangChain (`CORDCallbackHandler`, `wrap_langchain_llm`), CrewAI (`wrap_crewai_agent`), LlamaIndex (`wrap_llamaindex_llm`)
- **Threat model documentation**: `THREAT_MODEL.md` with attacker capabilities, TCB definition, all 40 red team vectors catalogued
- **Audit log PII redaction**: 3 levels (`none`, `pii`, `full`) — SSN, credit card, email, phone auto-redacted
- **Audit log encryption**: Optional AES-256-GCM encryption-at-rest via `CORD_LOG_KEY` env var
- **Runtime containment**: `SandboxedExecutor` with path validation, command allow-lists, blocked dangerous patterns, output size limits, network byte quotas
- **Evaluation cache**: LRU cache with configurable TTL (default 60s, max 1000 entries)
- **Batch evaluation**: `evaluateBatch(proposals[])` for bulk processing
- **Early-exit optimization**: Hard-blocks skip scored checks entirely

### Changed

- `logger.js` expanded with redaction, encryption, and configurable logging levels
- `evaluateProposal()` returns early on hard-blocks (skips phases 2–4)
- `executor.js` uses `SandboxedExecutor` when available (graceful fallback)
- `cord/index.js` exports frameworks, cache, `validatePlan`, `evaluateBatch`

### Security

- PII no longer stored in plain text in audit logs (default: `pii` redaction)
- Plan-level evasion attack surface closed via aggregate validation
- Dangerous shell patterns (`rm -rf /`, `curl|sh`, `nc -l`, etc.) blocked at sandbox level
- Network byte quotas prevent slow exfiltration via LEGION executor

## [4.0.3] — 2026-02-25

### Fixed

- npm package trimmed to 55KB (excluded tests, logs, node_modules from publish)
- Package `files` array made explicit per-file instead of directory globs

## [4.0.2] — 2026-02-25

### Fixed

- Correct require paths in `bin/cord-engine` CLI entry point

## [4.0.1] — 2026-02-25

### Fixed

- Add `bin/` directory to npm package for global CLI install

## [4.0.0] — 2026-02-25

### Added

- CORD v3 protocol pipeline — 14 weighted risk checks across 5 phases
- VIGIL threat patrol daemon — 8 detection layers (patterns, normalization, memory, canaries, proactive, semantic, rate limiting, circuit breaking)
- CLI tool: `cord-engine eval`, `cord-engine scan`, `cord-engine demo`
- Red team test suite — 40 attack vectors across 9 layers, 40/40 blocked
- Financial risk detection (`financialRisk`) — money transfer, wallet, payment fraud patterns
- Network target risk detection (`networkTargetRisk`) — suspicious domains, raw IPs, .onion, ngrok
- Session management with intent locks and scope enforcement
- Hash-chained audit log with SHA-256 integrity verification
- LEGION multi-model orchestrator with CORD-gated execution
- OpenAI and Anthropic SDK middleware wrappers
- Plain-English explanation engine (`cord/explain.js`)

### Changed

- Renamed from SENTINEL to CORD (Counter-Operations & Risk Detection)
- Python SDK version synced to 4.0.0

## [3.0.2] — 2026-02-24

### Added

- Initial npm publish of `cord-engine` package
- Core evaluation pipeline with 6 risk checks
- Intent lock system for session scope enforcement

## [2.2.0] — 2026-02-24

### Added

- Python SDK (`cord_engine`) with 9-step evaluation pipeline
- Interceptor system: `@cord_guard` decorator, `guard_registry`, `CORDEnforcer` context manager
- `ToolBlocked` and `ToolChallenged` exception types
- PyPI publish of `cord-engine` package

## [1.0.0] — 2026-02-23

### Added

- Initial SENTINEL implementation
- Constitutional protocol enforcement (11 articles)
- Basic injection, exfiltration, and privilege risk detection
