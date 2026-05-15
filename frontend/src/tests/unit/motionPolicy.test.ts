import { describe, expect, it } from 'vitest';
import { resolveMotionPolicy, resolveComponentMotionStrategy } from '@/lib/motionPolicy';

describe('motion policy', () => {
  it('returns full tier when animations are enabled and capability is high', () => {
    const policy = resolveMotionPolicy({
      intensity: 'high',
      capability: 'full',
      animationsEnabled: true,
      reduceMotionEnabled: false,
      systemPrefersReducedMotion: false,
      constrainedDevice: false,
    });

    expect(policy.tier).toBe('full');
    expect(policy.allowFramer).toBe(true);
    expect(policy.allowGsap).toBe(true);
  });

  it('returns reduced tier when device is constrained under auto capability', () => {
    const policy = resolveMotionPolicy({
      intensity: 'high',
      capability: 'auto',
      animationsEnabled: true,
      reduceMotionEnabled: false,
      systemPrefersReducedMotion: false,
      constrainedDevice: true,
    });

    expect(policy.tier).toBe('reduced');
    expect(policy.allowFramer).toBe(true);
    expect(policy.allowGsap).toBe(false);
  });

  it('returns static tier when reduced motion is enabled', () => {
    const policy = resolveMotionPolicy({
      intensity: 'high',
      capability: 'full',
      animationsEnabled: true,
      reduceMotionEnabled: true,
      systemPrefersReducedMotion: false,
      constrainedDevice: false,
    });

    expect(policy.tier).toBe('static');
    expect(policy.allowFramer).toBe(false);
    expect(policy.allowLottie).toBe(false);
  });

  it('downgrades gsap strategy to framer in reduced tier', () => {
    const policy = resolveMotionPolicy({
      intensity: 'high',
      capability: 'reduced',
      animationsEnabled: true,
      reduceMotionEnabled: false,
      systemPrefersReducedMotion: false,
      constrainedDevice: false,
    });

    const strategy = resolveComponentMotionStrategy('hero', policy);
    expect(strategy.engine).toBe('framer');
    expect(strategy.distance).toBeLessThanOrEqual(8);
  });
});
