import { useMemo } from 'react';
import { useTheme } from '@/context/ThemeContext';
import { useDisplay } from '@/context/DisplayContext';
import {
  resolveMotionPolicy,
  resolveComponentMotionStrategy,
  type MotionComponentClass,
} from '@/lib/motionPolicy';

function detectSystemReducedMotion(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return false;
  }
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

function detectConstrainedDevice(): boolean {
  if (typeof navigator === 'undefined') {
    return false;
  }
  const cores = typeof navigator.hardwareConcurrency === 'number' ? navigator.hardwareConcurrency : 8;
  const memory = typeof (navigator as Navigator & { deviceMemory?: number }).deviceMemory === 'number'
    ? (navigator as Navigator & { deviceMemory?: number }).deviceMemory!
    : 8;
  return cores <= 4 || memory <= 4;
}

export function useMotionPolicy(component: MotionComponentClass = 'page') {
  const { theme } = useTheme();
  const { display } = useDisplay();

  return useMemo(() => {
    const policy = resolveMotionPolicy({
      intensity: theme.motionIntensity,
      capability: theme.effectCapability,
      animationsEnabled: display.animations,
      reduceMotionEnabled: display.reduceMotion,
      systemPrefersReducedMotion: detectSystemReducedMotion(),
      constrainedDevice: detectConstrainedDevice(),
    });

    const strategy = resolveComponentMotionStrategy(component, policy);
    return { policy, strategy };
  }, [
    component,
    theme.motionIntensity,
    theme.effectCapability,
    display.animations,
    display.reduceMotion,
  ]);
}
