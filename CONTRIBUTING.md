# Contributing Guidelines

Thank you for contributing to the Cyber Security Test Pipeline. Please review these development conventions, branch naming patterns, and PR verification procedures.

---

## 🌿 Branch Naming & Commits

Use the conventional commit and branch format:
- `feat/feature-name` — New scanning capabilities or UI features.
- `fix/bug-description` — Fixes for identified bugs and regression issues.
- `refactor/subsystem-name` — Code restructuring and performance optimizations.
- `doc/topic-name` — Documentation improvements and guides.

Commit messages must adhere to [Conventional Commits](https://www.conventionalcommits.org/) (e.g. `feat(pipeline): add adaptive retry handler`).

---

## 🐍 Backend Quality Checklist

Before submitting a backend pull request, ensure all linters, type checks, and test suites pass:

```bash
# 1. Format and lint
ruff format .
ruff check . --fix

# 2. Type checking
mypy src/

# 3. Architecture boundaries and unit tests
pytest tests/architecture/
pytest tests/unit/
pytest tests/integration/

# 4. System doctor check
cstp system doctor
```

---

## 🎨 Frontend Quality Checklist

When modifying or adding frontend components in `frontend/`:

```bash
cd frontend

# 1. Run type check
npx tsc --noEmit

# 2. Run linter
npm run lint

# 3. Run component tests
npm run test

# 4. Verify production build
npm run build
```

---

## 📄 Adding New Pages & Routes

1. **Create Component**: Place your page in `frontend/src/pages/`.
2. **Register Route**: Add lazy-loaded route definition in `frontend/src/App.tsx`.
3. **Add Navigation Entry**: Update navigation items and command palette shortcuts in `frontend/src/components/layout/`.
4. **Translations**: Add localization keys to `frontend/src/i18n/`.
