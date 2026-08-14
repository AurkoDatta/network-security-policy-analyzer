# Design: Complete Network Security Policy Analyzer (Phases 2-5)

## Status

Approved. Source of truth for feature detail remains `prompt.txt` (full project brief and phase/milestone breakdown) and `CLAUDE.md` (architecture, schemas, and locked-in decisions). This document exists only to record the decomposition and sequencing decision for finishing the project, per the brainstorming skill's process for oversized requests.

## Context

Phase 1 (scaffold, DB schema, skeleton services) is complete and committed (5 commits on `main`). The remaining work — Phases 2 through 5 of `prompt.txt` — is too large for a single implementation plan. It spans four largely independent subsystems (analysis engine, API gateway, frontend, polish/docs/CI) that depend on each other sequentially but not concurrently.

## Decomposition

Each phase below is its own sub-project with its own implementation plan, built in order. Every milestone within a phase ends in a commit; every phase ends in a push to GitHub.

1. **Phase 2 — Analysis Engine** (`analyzer/src/{parsers,detectors,compliance}`)
   AWS Security Group parser, generic firewall (YAML/JSON) parser, simplified IAM policy parser; permissiveness/conflict/orphaned-rule detectors; risk scorer; CIS/HIPAA/PCI-DSS compliance rulesets + matcher engine. Pure Python, no DB or HTTP coupling to the API — fully unit-testable in isolation. Built first because everything downstream (API orchestration, frontend results display) depends on its output shape (`Finding`, `RiskScore` — already modeled in `analyzer/src/models.py`).

2. **Phase 3 — API Gateway & Auth**
   `POST /api/policies/upload`, `GET/DELETE /api/policies/:id`, `POST /api/policies/:id/analyze` (orchestrates a call to the analyzer service), `WebSocket /ws/analyze/:id` for live progress, `GET /api/analyses/:id`, `GET /api/analyses/:id/report` (PDF), JWT register/login/refresh mounted via the existing (unmounted) `authenticate` middleware, user-scoped access control.
   Scope decision (confirmed with user): both PDF report generation and WebSocket live progress are built in full now, not deferred.

3. **Phase 4 — React Frontend**
   Upload form (drag-and-drop), policy list, findings table (sortable/filterable), rule detail panel, risk gauge, compliance breakdown chart, Cytoscape.js network diagram, risk matrix, PDF/JSON export triggers.

4. **Phase 5 — Polish, Testing, Docs, CI**
   Coverage top-up to the targets in `CLAUDE.md`/`prompt.txt` (analyzer 85%+, API 75%+, frontend 60%+), E2E happy-path tests, real content for `docs/architecture.md` / `docs/api.md` / `docs/user-guide.md`, GitHub Actions CI, Docker multi-stage build optimization, no-AI-attribution pass.

## Non-goals (per CLAUDE.md locked decisions)

- No dedicated GCP parser — generic YAML/JSON firewall parser covers it.
- No ML-based recommendation engine — heuristic only.
- No Redis/job-queue — analysis stays synchronous-per-request (with WebSocket progress events emitted during that request), consistent with the existing docker-compose (Redis intentionally omitted).

## Process

For each phase: read the relevant `prompt.txt` milestone + `CLAUDE.md` sections → `superpowers:writing-plans` for a detailed implementation plan for that phase only → `superpowers:test-driven-development` where practical for new logic (parsers, detectors, scorer, compliance matcher) → implement → run the phase's test suite → commit using `prompt.txt`'s exact conventional-commit messages → push → move to next phase.
