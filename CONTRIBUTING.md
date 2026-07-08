# Contributing

## Branch Naming Convention

Use the existing convention: `type-subject-description`:

- `bug-audit-*` — bug fixes found during audit
- `fix-modal-close-and-build-stale` — fixes
- `feature-*` — new features

## Feature Branches

All feature work happens under `features/*` branches. After review they are merged into `main`.

## Adding a New Page

1. **Create lazy route** in `App.tsx`:
   ```tsx
   const NewPage = lazy(() => import('./pages/NewPage'));
   ```
2. **Add RouteGuard** — wrap the route with the existing `ProtectedRoute` component.
3. **Command palette entry** — add an item in `useCommandPaletteItems` or the `items` prop passed to `CommandPalette`.
4. **i18n keys** — add `navigation.newPage` to `src/i18n/en/translation.json` and `src/i18n/es/translation.json`.

## Health Checklist

Before opening a PR, run:

```bash
npm run health
```

This runs:
- `check:types` — TypeScript type-check without emit
- `lint` — ESLint on all files
- `check:copy-guard` — verify no forbidden phrases
- `build` — full production build
- `audit` — npm audit
- `check:size` — size-limit analysis

## Code Conventions

- Use `@/` absolute imports instead of deep relative paths.
- All API error messages live in `src/i18n/*/translation.json` — never hardcode user-facing strings.
- Store methods (Zustand) must have JSDoc block comments.
- Commits must follow [Conventional Commits](https://www.conventionalcommits.org/). Use `npm run cz` to be prompted.
