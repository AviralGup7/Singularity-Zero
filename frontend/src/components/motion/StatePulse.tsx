import { useMemo, type ComponentType } from 'react';
import RawLottiePlayer from 'lottie-react';
import { useMotionPolicy } from '@/hooks/useMotionPolicy';

type PulseState = 'loading' | 'success' | 'error' | 'empty';

interface StatePulseProps {
  state: PulseState;
  className?: string;
}

interface LottieComponentProps {
  animationData: unknown;
  loop?: boolean;
}

const LottiePlayer =
  ((RawLottiePlayer as unknown as { default?: ComponentType<LottieComponentProps> }).default ??
    (RawLottiePlayer as unknown as ComponentType<LottieComponentProps>));

const baseAnimation = {
  v: '5.7.6',
  fr: 60,
  ip: 0,
  op: 120,
  w: 120,
  h: 120,
  nm: 'state-pulse',
  ddd: 0,
  assets: [],
  layers: [
    {
      ddd: 0,
      ind: 1,
      ty: 4,
      nm: 'ring',
      sr: 1,
      ks: {
        o: { a: 0, k: 100 },
        r: { a: 0, k: 0 },
   
        p: { a: 0, k: [60, 60, 0] },
   
        a: { a: 0, k: [0, 0, 0] },
        s: {
          a: 1,
          k: [
   
            { t: 0, s: [70, 70, 100] },
   
            { t: 60, s: [110, 110, 100] },
   
            { t: 120, s: [70, 70, 100] },
          ],
        },
      },
      shapes: [
   
        { ty: 'el', p: { a: 0, k: [0, 0] }, s: { a: 0, k: [80, 80] }, nm: 'Ellipse Path 1' },
   
        { ty: 'st', c: { a: 0, k: [0, 0.96, 1, 1] }, o: { a: 0, k: 90 }, w: { a: 0, k: 8 }, lc: 2, lj: 2 },
   
        { ty: 'tr', p: { a: 0, k: [0, 0] }, a: { a: 0, k: [0, 0] }, s: { a: 0, k: [100, 100] }, r: { a: 0, k: 0 }, o: { a: 0, k: 100 } },
      ],
      ip: 0,
      op: 120,
      st: 0,
      bm: 0,
    },
  ],
};

const stateColor: Record<PulseState, string> = {
  loading: '#37f6ff',
  success: '#1fe28a',
  error: '#ff5568',
  empty: '#8a96ad',
};

export function StatePulse({ state, className }: StatePulseProps) {
  const { policy } = useMotionPolicy('status');
  const fallbackLabel: Record<PulseState, string> = {
    loading: 'Loading',
    success: 'Done',
    error: 'Error',
    empty: 'Idle',
  };

  const animation = useMemo(() => {
    const cloned = structuredClone(baseAnimation);
   
    const ring = cloned.layers?.[0]?.shapes?.[1];
    if (ring && typeof ring === 'object' && 'c' in ring) {
  // eslint-disable-next-line security/detect-object-injection
      (ring as { c: { a: number; k: number[] } }).c.k = hexToRgbArray(stateColor[state]);
    }
    return cloned;
   
  }, [state]);

  if (!policy.allowLottie) {
    return (
      <span className={`state-pulse-fallback state-pulse-${state} ${className ?? ''}`}>
  // eslint-disable-next-line security/detect-object-injection
        {fallbackLabel[state]}
      </span>
    );
  }

  return (
    <div className={`state-pulse ${className ?? ''}`} aria-hidden="true">
      <LottiePlayer animationData={animation} loop />
    </div>
  );
}

   
function hexToRgbArray(hex: string): [number, number, number, number] {
  const sanitized = hex.replace('#', '');
  const parsed = Number.parseInt(sanitized, 16);
  const r = ((parsed >> 16) & 255) / 255;
  const g = ((parsed >> 8) & 255) / 255;
  const b = (parsed & 255) / 255;
   
  return [r, g, b, 1];
}
