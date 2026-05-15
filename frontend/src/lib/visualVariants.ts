import type { Variants } from 'framer-motion';
import type { VisualState } from './visualState';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const stageVariants: any = {
  idle: {
    scale: 1,
    opacity: 0.72,
    x: 0,
    filter: 'blur(0px)',
  },
  active: (vs: VisualState) => ({
    scale: 1 + vs.intensity * 0.18,
    opacity: 0.82 + vs.flow * 0.18,
    x: 0,
    filter: 'blur(0px)',
  }),
  unstable: (vs: VisualState) => {
    const jitter = Math.max(1, Math.round(vs.instability * 4));
    return {
      scale: 1 + vs.intensity * 0.12,
      opacity: 0.88,
      x: [0, -jitter, jitter, -1, 0],
      filter: `blur(${(vs.instability * 1.2).toFixed(2)}px)`,
    };
  },
  critical: (vs: VisualState) => ({
    scale: 1.08 + vs.urgency * 0.16,
    opacity: 1,
    x: [0, -2, 2, -1, 0],
    filter: 'drop-shadow(0 0 10px rgba(255, 59, 59, 0.6))',
  }),
};

