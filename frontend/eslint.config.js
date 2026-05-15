// For more info, see https://github.com/storybookjs/eslint-plugin-storybook#configuration-flat-config-format
import storybook from "eslint-plugin-storybook";

import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import jsxAlly from 'eslint-plugin-jsx-a11y'
import security from 'eslint-plugin-security'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([globalIgnores(['dist', 'node_modules', 'src/components/ui-shadcn']), {
  files: ['**/*.{ts,tsx}'],
  extends: [
    js.configs.recommended,
    tseslint.configs.recommended,
    reactHooks.configs.flat.recommended,
    reactRefresh.configs.vite,
    jsxAlly.flatConfigs.recommended,
    security.configs.recommended,
  ],
  languageOptions: {
    ecmaVersion: 2020,
    globals: globals.browser,
  },
  rules: {
    '@typescript-eslint/no-unused-vars': ['error', {
      argsIgnorePattern: '^_',
      caughtErrorsIgnorePattern: '^_',
      varsIgnorePattern: '^_',
    }],
    'react-hooks/immutability': 'warn',
    'react-hooks/preserve-manual-memoization': 'warn',
    'react-hooks/purity': 'warn',
    'react-hooks/refs': 'warn',
    'react-hooks/set-state-in-effect': 'warn',
    'react-refresh/only-export-components': 'warn',
    'jsx-a11y/click-events-have-key-events': 'warn',
    'jsx-a11y/interactive-supports-focus': 'warn',
    'jsx-a11y/label-has-associated-control': 'warn',
    'jsx-a11y/no-autofocus': 'warn',
    'jsx-a11y/no-noninteractive-element-interactions': 'warn',
    'jsx-a11y/no-noninteractive-tabindex': 'warn',
    'jsx-a11y/no-static-element-interactions': 'warn',
    'jsx-a11y/role-has-required-aria-props': 'warn',
  },
}, {
  files: ['src/**/*.{ts,tsx}'],
  ignores: [
    'src/pages/CockpitPage.tsx',
    'src/components/motion/CinematicIntro.tsx',
    'src/components/PipelineStageTimeline.tsx',
    'src/components/motion/StatePulse.tsx',
  ],
  rules: {
    'no-restricted-imports': ['error', {
      paths: [
        {
          name: 'gsap',
          message: 'GSAP is reserved for cinematic/timeline components only.',
        },
        {
          name: 'lottie-react',
          message: 'Lottie is reserved for state moment components only.',
        },
        {
          name: 'three',
          message: 'Three.js is reserved for 3D pipeline graph modules only.',
        },
        {
          name: '@react-three/fiber',
          message: 'React Three Fiber is reserved for 3D pipeline graph modules only.',
        },
      ],
    }],
  },
}, {
  files: ['src/components/charts/**/*.{ts,tsx}'],
  rules: {
    'no-restricted-imports': ['error', {
      paths: [
        {
          name: 'framer-motion',
          message: 'Charts must use data-viz libraries only (D3/Visx/Recharts), not UI motion engines.',
        },
        {
          name: 'motion/react',
          message: 'Charts must use data-viz libraries only (D3/Visx/Recharts), not UI motion engines.',
        },
        {
          name: 'motion/react-mini',
          message: 'Charts must use data-viz libraries only (D3/Visx/Recharts), not UI motion engines.',
        },
        {
          name: 'gsap',
          message: 'GSAP is not allowed inside chart components.',
        },
        {
          name: 'lottie-react',
          message: 'Lottie is not allowed inside chart components.',
        },
        {
          name: 'three',
          message: 'Three.js is not allowed inside chart components.',
        },
        {
          name: '@react-three/fiber',
          message: 'React Three Fiber is not allowed inside chart components.',
        },
        {
          name: 'recharts',
          message: 'Ops-core chart components should use D3-based rendering rather than Recharts.',
        },
      ],
    }],
  },
}, ...storybook.configs["flat/recommended"]])
