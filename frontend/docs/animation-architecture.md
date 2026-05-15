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
- `src/components/charts/**`: no `framer-motion`, `motion/*`, `gsap`, `lottie-react`, `three`.
- `src/components/charts/**`: no `recharts` imports (D3-based chart rendering only).
- `gsap` is only allowed in:
  - `src/components/motion/CinematicIntro.tsx`
  - `src/components/PipelineStageTimeline.tsx`
- `lottie-react` is only allowed in:
  - `src/components/motion/StatePulse.tsx`

## Performance Rules
- Use `LazyMotion` for Framer features.
- Prefer transform/opacity animations.
- Respect reduced motion via `useMotionPolicy`.
- Enforce animation chunk budgets with `npm run check:anim-budget`.

## React 19 Note
- `@visx/*` currently declares peer dependencies up to React 18.
- Until React 19-compatible Visx releases are available, ops charts use direct D3 modules with typed SVG rendering.

## CI/Local Checks
- `npm run check:copy-guard`
- `npm run check:types`
- `npm run lint`
- `npm run build` (includes animation budget check)
