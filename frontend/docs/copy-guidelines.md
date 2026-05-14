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
- The copy guard blocks a forbidden exact phrase in user-facing frontend sources.
- Guarded files include `src/**/*.tsx`, `src/**/*.jsx`, and `src/i18n/**/*.json`.
- Run `npm run check:copy-guard` before opening a frontend PR.
