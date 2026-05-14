export type VisualState = {
  intensity: number;
  urgency: number;
  instability: number;
  flow: number;
  confidence: number;
};

export const DEFAULT_VISUAL_STATE: VisualState = {
  intensity: 0.2,
  urgency: 0.2,
  instability: 0,
  flow: 0,
  confidence: 0.9,
};

export function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(1, value));
}

