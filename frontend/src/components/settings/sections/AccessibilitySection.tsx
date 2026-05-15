import { SettingsSectionCard, SettingToggle } from '../SettingsComponents';

interface AccessibilitySectionProps {
  reduceMotion: boolean;
  highContrast: boolean;
  focusIndicators: boolean;
  screenReaderOptimizations: boolean;
  onReduceMotionChange: (v: boolean) => void;
  onHighContrastChange: (v: boolean) => void;
  onFocusIndicatorsChange: (v: boolean) => void;
  onScreenReaderOptimizationsChange: (v: boolean) => void;
}

export function AccessibilitySection({ reduceMotion, highContrast, focusIndicators, screenReaderOptimizations, onReduceMotionChange, onHighContrastChange, onFocusIndicatorsChange, onScreenReaderOptimizationsChange }: AccessibilitySectionProps) {
  return (
    <SettingsSectionCard title="Accessibility" icon="\u267f">
      <SettingToggle label="Reduce Motion" checked={reduceMotion} onChange={onReduceMotionChange} description="Minimize animations and transitions" />
      <SettingToggle label="High Contrast" checked={highContrast} onChange={onHighContrastChange} description="Increase contrast for better visibility" />
      <SettingToggle label="Focus Indicators" checked={focusIndicators} onChange={onFocusIndicatorsChange} description="Show visible focus outlines" />
      <SettingToggle label="Screen Reader Optimizations" checked={screenReaderOptimizations} onChange={onScreenReaderOptimizationsChange} description="Enhance ARIA labels and live regions" />
    </SettingsSectionCard>
  );
}
