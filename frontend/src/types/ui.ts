export type VisualTone = 'neutral' | 'accent' | 'success' | 'warning' | 'danger' | 'info';
export type VisualIntensity = 'subtle' | 'balanced' | 'bold';
export type StatusState = 'idle' | 'running' | 'completed' | 'failed' | 'stalled';

export interface VisualVariantProps {
  tone?: VisualTone;
  intensity?: VisualIntensity;
  status?: StatusState;
  interactive?: boolean;
}
