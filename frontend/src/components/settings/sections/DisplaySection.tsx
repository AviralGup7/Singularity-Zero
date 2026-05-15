import { type DensityMode, type FontSize } from '../../../context/DisplayContext';
import type { EffectCapability, MotionIntensity } from '../../../lib/motionPolicy';
import { SettingsSectionCard, SettingSelect, SettingToggle } from '../SettingsComponents';

const densityOptions: { value: DensityMode; label: string; icon: string; description: string }[] = [
  { value: 'compact', label: 'Compact', icon: 'D1', description: 'More content, less spacing' },
  { value: 'comfortable', label: 'Comfortable', icon: 'D2', description: 'Balanced spacing (default)' },
  { value: 'spacious', label: 'Spacious', icon: 'D3', description: 'Extra padding and breathing room' },
];

const fontSizeOptions: { value: FontSize; label: string; icon: string; description: string }[] = [
  { value: 'small', label: 'Small', icon: 'A-', description: 'More content visible' },
  { value: 'medium', label: 'Medium', icon: 'A', description: 'Default text size' },
  { value: 'large', label: 'Large', icon: 'A+', description: 'Easier to read' },
];

const motionIntensityOptions: { value: MotionIntensity; label: string; description: string }[] = [
  { value: 'high', label: 'High', description: 'Maximum visual motion and transitions' },
  { value: 'medium', label: 'Medium', description: 'Balanced motion for daily use' },
  { value: 'low', label: 'Low', description: 'Subtle transitions only' },
  { value: 'off', label: 'Off', description: 'No motion effects' },
];

const effectCapabilityOptions: { value: EffectCapability; label: string; description: string }[] = [
  { value: 'auto', label: 'Auto', description: 'Adapt effects to device capability' },
  { value: 'full', label: 'Full', description: 'Force full effects and cinematic animation' },
  { value: 'reduced', label: 'Reduced', description: 'Keep lightweight effects only' },
  { value: 'none', label: 'None', description: 'Disable advanced effects' },
];

interface DisplaySectionProps {
  density: DensityMode;
  fontSize: FontSize;
  animations: boolean;
  gridBackground: boolean;
  motionIntensity: MotionIntensity;
  effectCapability: EffectCapability;
  onDensityChange: (v: DensityMode) => void;
  onFontSizeChange: (v: FontSize) => void;
  onAnimationsChange: (v: boolean) => void;
  onGridBackgroundChange: (v: boolean) => void;
  onMotionIntensityChange: (v: MotionIntensity) => void;
  onEffectCapabilityChange: (v: EffectCapability) => void;
}

export function DisplaySection({
  density,
  fontSize,
  animations,
  gridBackground,
  motionIntensity,
  effectCapability,
  onDensityChange,
  onFontSizeChange,
  onAnimationsChange,
  onGridBackgroundChange,
  onMotionIntensityChange,
  onEffectCapabilityChange,
}: DisplaySectionProps) {
  return (
    <SettingsSectionCard title="Display" icon="display">
      <SettingSelect
        label="Density"
        value={density}
        onChange={v => onDensityChange(v as DensityMode)}
        options={densityOptions.map(o => ({ label: `${o.icon} ${o.label}`, value: o.value }))}
        description="Control spacing and content density"
      />
      <SettingSelect
        label="Font Size"
        value={fontSize}
        onChange={v => onFontSizeChange(v as FontSize)}
        options={fontSizeOptions.map(o => ({ label: `${o.icon} ${o.label}`, value: o.value }))}
        description="Adjust text size for readability"
      />
      <SettingSelect
        label="Motion Intensity"
        value={motionIntensity}
        onChange={v => onMotionIntensityChange(v as MotionIntensity)}
        options={motionIntensityOptions.map(o => ({ label: o.label, value: o.value }))}
        description={motionIntensityOptions.find(o => o.value === motionIntensity)?.description}
      />
      <SettingSelect
        label="Effects Capability"
        value={effectCapability}
        onChange={v => onEffectCapabilityChange(v as EffectCapability)}
        options={effectCapabilityOptions.map(o => ({ label: o.label, value: o.value }))}
        description={effectCapabilityOptions.find(o => o.value === effectCapability)?.description}
      />
      <SettingToggle label="Animations" checked={animations} onChange={onAnimationsChange} description="Enable UI animations" />
      <SettingToggle label="Grid Background" checked={gridBackground} onChange={onGridBackgroundChange} description="Show atmospheric background grid" />
    </SettingsSectionCard>
  );
}
