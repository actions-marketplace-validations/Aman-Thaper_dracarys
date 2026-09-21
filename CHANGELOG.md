# Changelog

## 0.1.3
Detector coverage: three new vulnerability classes, each with a deterministic oracle.
The generalization scorecard goes from 10/10 to **13/13 at recall 1.0**, still with
**0 false positives** on the hardened control app.

- **Path traversal** (CWE-22): a traversal payload returns the contents of a system file
  that the baseline response did not contain. Probes are read-only GETs.
- **Server-side template injection** (CWE-1336): an injected expression is evaluated
  server-side to its computed result *and* the literal payload is absent — so a payload
  that is merely reflected can never be reported as SSTI.
- **CORS misconfiguration** (CWE-942): an untrusted `Origin` is reflected into
  `Access-Control-Allow-Origin` together with `Access-Control-Allow-Credentials: true`.
  A wildcard origin *without* credentials is deliberately not reported — it is normal for
  public APIs and cannot be used to read an authenticated response.
- The testbed apps grew matching vulnerable endpoints (and the hardened control grew
  hardened counterparts), so the new detectors are scored against apps they were not
  written for. Traversal in the fixtures resolves against a simulated filesystem and
  never touches the real disk.
- Site-level detectors can now see the crawled surface (`ScanContext.templates` /
  `.baselines`), not just the base URL.
- 83 tests, ~85% coverage.

## 0.1.2
Distribution surfaces: the scanner is now reachable from an editor, an agent, and the web.

- **MCP server** (`dracarys-mcp`, extra `[mcp]`): `scan_target` and `list_detectors` over
  stdio for MCP-capable agents. Reuses `runner.authorize`, so a non-loopback target still
  requires an explicit authorization flag rather than the agent deciding on its own.
  Supports both mcp SDK generations (`FastMCP` in 1.x, `MCPServer` in 2.x).
- **VS Code extension** (`editors/vscode`): scan a target URL or open a SARIF report and
  review findings beside your code. Ships as a `.vsix` on the release.
- **Landing page** (`site/`) deployed to GitHub Pages.
- `publish-pypi.yml` publishes to PyPI on release via Trusted Publishing (OIDC) — no token
  is stored in the repository.
- **Fix:** `scanner/report.py` hardcoded its version and had drifted; it now reads the
  installed package metadata.

## 0.1.1
Publishing fixes — first release usable from the GitHub Marketplace.

- **Fix:** `action.yml` referenced `infra/docker/Dockerfile.action`, but GitHub requires a
  container action's local image file to be named `Dockerfile`. Moved to the repo root so
  the Action can actually build for consumers.
- **Fix:** `ci.yml` had an unquoted step name containing `: `, making the workflow invalid
  YAML — every run failed at startup with no jobs. Quoted.
- Replaced placeholder publishing metadata (repo URLs, author, description, SARIF
  `informationUri`, README/example `uses:` refs) with the real `Aman-Thaper/dracarys`.

## 0.1.0
Initial release.

### Scanner (generic DAST)
- Target-agnostic engine: crawler (links, forms, params) + OpenAPI import.
- Detectors: SQL injection (error/boolean/time), reflected XSS, IDOR/BOLA
  (differential), open redirect, exposed files & secrets, missing security headers,
  verbose-error / DB-error disclosure, exposed API schema. All CWE-mapped with evidence.
- Deterministic oracles; low false positives (0 on the hardened control app).
- Reports: table, JSON, SARIF 2.1.0, Markdown, HTML.
- `dracarys scan` CLI with an authorization gate, safe non-destructive payloads,
  scope/budget/timeout controls, and severity-based exit codes.
- `dracarys scan-selftest` generalization scorecard (recall 1.0 across independent apps).
- HTTP API: `POST /api/scan`.
- GitHub Action (Docker) with SARIF output for GitHub code scanning.

### Verified remediation + platform
- Autonomous campaign loop against the bundled DRACARYS BANK lab: recon → hypotheses →
  bounded exploitation → deterministic validation → attack-graph → remediation →
  patched rebuild → retest → FIX VERIFIED.
- Attack-graph construction and multi-step chain discovery to a protected canary.
- Next.js command center; FastAPI control plane; SQLAlchemy async persistence; Alembic.
- 72 tests (unit/integration/e2e/evaluation), mypy + ruff clean, CI.
