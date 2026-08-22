# Frontend Copy Guidelines

## Tone
- Keep language operational, concise, and actionable.
- Prefer concrete status text over vague labels.
- Use calm failure wording with stage + reason when possible.

## Style
- Avoid pop-culture references in product copy.
- Keep button labels short and task-focused.
- Use sentence case for status messages and alerts.

## Guardrail
- The copy guard blocks forbidden exact phrases in user-facing frontend sources.
- Guarded files include `frontend/src/**/*.tsx`, `frontend/src/**/*.jsx`, and `frontend/src/i18n/**/*.json`.
- Run `npm run check:copy-guard` before opening a frontend PR.
