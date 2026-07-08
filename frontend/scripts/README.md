# Build Scripts

## `check-animation-budget.mjs`

Runs after `vite build` to enforce gzip-size budgets on JS chunks.

**Thresholds** (defined inline at the top of the script):

| Key                 | Default Budget | Notes                                  |
| ------------------- | -------------- | -------------------------------------- |
| `totalJsGzip`       | 1050 KB        | Sum of all JS assets                   |
| `appShellChunkGzip` | 95 KB          | The main `index-*.js` entry chunk      |
| `gsapChunkGzip`     | 40 KB          | GSAP animation chunk                   |
| `lottieChunkGzip`   | 75 KB          | Lottie animation chunk                 |

**How to update:** Edit the `BUDGETS` object in the script. Run `npm run check:anim-budget` (or `npm run build` which calls it automatically) to verify.

## `copy-guard.mjs`

Scans all `.tsx`, `.jsx`, and `.json` files under `src/` (excluding `node_modules`, `dist`, `coverage`, tests, stories) for a forbidden phrase.

**Default forbidden phrase:** `cyberpunk 2077` (set via `COPY_GUARD_FORBIDDEN` env var to override).

**Why it exists:** Prevents leakage of IP-sensitive placeholder text from mocks/copy decks into production source files.

**How to update:** Change the `forbiddenPhrase` variable or set `COPY_GUARD_FORBIDDEN` env var before running.

## `download-fonts.mjs`

Downloads web fonts used by the dashboard UI. Not run as part of the build pipeline.

## `patch_ts_errors.py`

Python utility to patch known TypeScript errors in bulk. Run manually as needed.

## `write_modal.py`

Python utility to scaffold modal components. Run manually as needed.
