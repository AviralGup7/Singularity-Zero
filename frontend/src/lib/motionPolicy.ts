export type MotionIntensity = 'off' | 'low' | 'medium' | 'high';
export type EffectCapability = 'auto' | 'full' | 'reduced' | 'none';
export type MotionTier = 'static' | 'reduced' | 'full';

export type MotionComponentClass =
  | 'layout'
  | 'page'
  | 'card'
  | 'list'
  | 'status'
  | 'hero'
  | 'graph';

export type MotionEngine = 'framer' | 'gsap' | 'lottie' | 'auto-animate' | 'none';

export interface MotionPolicy {
  tier: MotionTier;
  intensity: MotionIntensity;
  capability: EffectCapability;
  reducedMotion: boolean;
  constrainedDevice: boolean;
  allowFramer: boolean;
  allowGsap: boolean;
  allowLottie: boolean;
  allowAutoAnimate: boolean;
}

export interface ComponentMotionStrategy {
  component: MotionComponentClass;
  engine: MotionEngine;
  fallback: MotionTier;
  duration: number;
  stagger: number;
  distance: number;
}

export interface MotionPolicyInput {
  intensity: MotionIntensity;
  capability: EffectCapability;
  animationsEnabled: boolean;
  reduceMotionEnabled: boolean;
  systemPrefersReducedMotion: boolean;
  constrainedDevice: boolean;
}

const DEFAULT_STRATEGY: ComponentMotionStrategy = {
  component: 'card',
  engine: 'none',
  fallback: 'static',
  duration: 0,
  stagger: 0,
  distance: 0,
};

const COMPONENT_RULES: Record<MotionComponentClass, Omit<ComponentMotionStrategy, 'component'>> = {
  layout: { engine: 'framer', fallback: 'reduced', duration: 0.42, stagger: 0.06, distance: 14 },
  page: { engine: 'framer', fallback: 'reduced', duration: 0.36, stagger: 0.04, distance: 20 },
  card: { engine: 'framer', fallback: 'reduced', duration: 0.28, stagger: 0.03, distance: 12 },
  list: { engine: 'auto-animate', fallback: 'reduced', duration: 0.22, stagger: 0.02, distance: 8 },
  status: { engine: 'lottie', fallback: 'reduced', duration: 0.26, stagger: 0, distance: 0 },
  hero: { engine: 'gsap', fallback: 'reduced', duration: 0.7, stagger: 0.08, distance: 24 },
  graph: { engine: 'gsap', fallback: 'reduced', duration: 0.65, stagger: 0.05, distance: 18 },
};

function resolveTier(input: MotionPolicyInput): MotionTier {
  if (!input.animationsEnabled || input.intensity === 'off') {
    return 'static';
  }
  if (input.reduceMotionEnabled || input.systemPrefersReducedMotion) {
    return 'static';
  }
  if (
    input.capability === 'none' ||
    (input.capability === 'auto' && input.constrainedDevice)
  ) {
    return 'reduced';
  }
  if (input.capability === 'reduced' || input.intensity === 'low') {
    return 'reduced';
  }
  return 'full';
}

export function resolveMotionPolicy(input: MotionPolicyInput): MotionPolicy {
  const tier = resolveTier(input);
  return {
    tier,
    intensity: input.intensity,
    capability: input.capability,
    reducedMotion: input.reduceMotionEnabled || input.systemPrefersReducedMotion,
    constrainedDevice: input.constrainedDevice,
    allowFramer: tier !== 'static',
    allowGsap: tier === 'full',
    allowLottie: tier !== 'static',
    allowAutoAnimate: tier !== 'static',
  };
}

export function resolveComponentMotionStrategy(
  component: MotionComponentClass,
  policy: MotionPolicy
): ComponentMotionStrategy {
  const configured = COMPONENT_RULES[component];
  if (!configured) {
    return { ...DEFAULT_STRATEGY, component };
  }

  if (policy.tier === 'static') {
    return { ...DEFAULT_STRATEGY, component };
  }

  if (policy.tier === 'reduced') {
    return {
      ...configured,
      component,
      engine: configured.engine === 'gsap' ? 'framer' : configured.engine,
      duration: Math.min(configured.duration, 0.24),
      stagger: Math.min(configured.stagger, 0.02),
      distance: Math.min(configured.distance, 8),
      fallback: 'static',
    };
  }

  return {
    ...configured,
    component,
  };
}
