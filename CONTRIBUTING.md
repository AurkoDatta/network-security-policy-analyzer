# Contributing

## Workflow

1. Branch off `main` (`feat/...`, `fix/...`, matching the change type).
2. Follow the existing TDD pattern in this repo: write the failing test
   first, then the minimal implementation, then verify it passes.
3. Commit using [Conventional Commits](https://www.conventionalcommits.org/)
   (`feat:`, `fix:`, `test:`, `docs:`, `chore:`, `perf:`, `ci:`,
   `refactor:`). Write commit messages in normal prose — no AI/LLM
   attribution anywhere, ever.
4. Keep coverage at or above each service's target: analyzer 85%+, API
   75%+, frontend 60%+.
5. Open a PR against `main` with a clear description of what changed and
   why.

## Local setup

See the Quick Start section in `README.md` for Docker Compose and local
per-service setup instructions.

## Project structure

- `analyzer/` — Python/FastAPI analysis engine. Pure functions in
  `src/parsers/`, `src/detectors/`, `src/compliance/`; `src/main.py` is a
  thin HTTP wrapper around them. Follow the existing style: typed
  function signatures, pydantic models for structured data, a short
  module docstring only where the WHY isn't obvious from the code.
- `api/` — Node/Express/TypeScript API gateway. Routes stay thin;
  business logic that isn't a one-line database call belongs in
  `src/services/`.
- `frontend/` — React/TypeScript/Tailwind UI. Components live in
  `src/components/` (reusable, presentational), pages in `src/pages/`
  (route-level, own their data fetching via the hooks in `src/hooks/`).

## Adding a new compliance framework

Add a JSON file to `analyzer/src/compliance/rulesets/`, following the
shape of the existing `cis.json`/`hipaa.json`/`pci_dss.json` files, and
add the framework name to `_BUNDLED_FRAMEWORKS` in
`analyzer/src/compliance/loader.py`. No API changes are needed — the
analyze endpoint already accepts a `compliance_frameworks` list.

## Adding a new rule source format

Add a parser module to `analyzer/src/parsers/` that exports a
`parse_<name>(raw: bytes) -> list[NormalizedRule]` function following the
existing parsers' shape (validate size, parse JSON/YAML, raise
`ParserError` on anything malformed), then register it in
`_PARSERS` in `analyzer/src/parsers/__init__.py`.

## Reporting issues

Open a GitHub issue with reproduction steps, expected vs. actual
behavior, and which service (analyzer/api/frontend) is affected.
