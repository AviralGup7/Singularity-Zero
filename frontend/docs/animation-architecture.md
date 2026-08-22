# Animation Architecture

## Stack
- Primary UI motion: `framer-motion`
- Micro-interactions: `motion` (`motion/react-mini`)
- Lightweight list/table transitions: `@formkit/auto-animate`
- Cinematic timelines only: `gsap`
- State moments only: `lottie-react`
- Data visualization motion: D3-based SVG charts (direct `d3-*` modules)
- 3D reserved domain: `three` + `@react-three/fiber`

## Ownership Rules
- `frontend/src/components/charts/**`: no `framer-motion`, `motion/*`, `gsap`, `lottie-react`, `three`.
- `frontend/src/components/charts/**`: no `recharts` imports (D3-based chart rendering only).

## Performance Rules
- Use `LazyMotion` for Framer features.
- Prefer transform/opacity animations.
- Respect reduced motion via `useMotionPolicy`.
- Enforce animation chunk budgets with `npm run check:anim-budget`.

## React 19 Note
- Ops charts use direct D3 modules with typed SVG rendering.

## CI/Local Checks
- `npm run check:copy-guard`
- `npm run check:types`
- `npm run lint`
- `npm run build`
