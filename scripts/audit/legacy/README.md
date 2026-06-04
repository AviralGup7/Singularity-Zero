# Legacy audit / patch scripts

These are historical one-shot scripts produced during prior cleanup passes.
They are preserved for reference but are not part of the active codebase and
are not exercised in CI.

Most were generated against a hard-coded Windows path
(`D:\cyber security test pipeline - Copy\...`) and are unlikely to run on
another machine. Treat them as documentation of past refactors, not as
production tooling.

Active auditing lives in:

- `../audit_runner.py` — main audit driver used by CI
- `../audit_bug*.py`, `../audit_phase*.py` — focused issue audits
- `../../src/infrastructure/observability/` — runtime instrumentation
