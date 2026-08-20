import { THEME_PRESETS } from '@/context/ThemeContext';
import type { ThemeMode, ThemePreset } from '@/context/ThemeContext';
import { SettingsSectionCard } from '../SettingsComponents';

const accentColors = [
  { name: 'Cyan', value: '#00f3ff' },
  { name: 'Warm Amber', value: '#c47a4a' },
  { name: 'Neon Pink', value: '#ff00ff' },
  { name: 'Emerald', value: '#39ff14' },
  { name: 'Coral', value: '#ff6b6b' },
  { name: 'Gold', value: '#ffea00' },
  { name: 'Lavender', value: '#a85d8a' },
  { name: 'Sky Blue', value: '#38bdf8' },
];

const themeModes: { mode: ThemeMode; label: string; icon: string; description: string }[] = [
  { mode: 'dark', label: 'Night Mode', icon: 'Dark', description: 'Dark cyberpunk theme with neon accents' },
  { mode: 'light', label: 'Day Mode', icon: 'Light', description: 'Soft warm tones for comfortable daytime viewing' },
];

interface ThemeSectionProps {
  themeMode: ThemeMode;
  themePreset: ThemePreset;
  accentColor: string;
  onThemeModeChange: (mode: ThemeMode) => void;
  onThemePresetChange: (preset: ThemePreset) => void;
  onAccentColorChange: (color: string) => void;
}

export function ThemeSection({ themeMode, themePreset, accentColor, onThemeModeChange, onThemePresetChange, onAccentColorChange }: ThemeSectionProps) {
  return (
    <SettingsSectionCard title="Theme" icon="">
      <div className="theme-options">
        {themeModes.map(opt => (
          <button
            key={opt.mode}
            className={`theme-option-card ${themeMode === opt.mode ? 'active' : ''}`}
            onClick={() => onThemeModeChange(opt.mode)}
          >
            <span className="theme-option-icon">{opt.icon}</span>
            <span className="theme-option-label">{opt.label}</span>
            <span className="theme-option-desc">{opt.description}</span>
          </button>
        ))}
      </div>

      <div className="mt-4">
        <span className="setting-label"><span className="setting-title">Color Scheme</span></span>
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mt-2">
          {(Object.entries(THEME_PRESETS) as [ThemePreset, typeof THEME_PRESETS[ThemePreset]][]).map(([key, preset]) => (
            <button
              key={key}
              className={`relative flex flex-col items-center gap-2 p-3 rounded-xl border transition-all duration-200 cursor-pointer ${
                themePreset === key
                  ? 'border-accent bg-accent-dim shadow-glow-accent-sm'
                  : 'border-line bg-surface hover:border-line hover:bg-surface-hover'
              }`}
              onClick={() => onThemePresetChange(key)}
              title={preset.description}
              aria-label={`Select ${preset.label} theme`}
            >
              <span className="text-xs font-semibold text-text-primary">{preset.label}</span>
              <div className="flex gap-1 mt-1">
                {preset.preview.map((color, i) => (
                  <span
                    key={i}
                    className="w-4 h-4 rounded-full border border-line"
                    style={{ backgroundColor: color }}
                  />
                ))}
              </div>
              {themePreset === key && (
                <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-accent" />
              )}
            </button>
          ))}
        </div>
      </div>

      <div className="accent-color-picker mt-4">
        <span className="setting-label"><span className="setting-title">Accent Color Override</span></span>
        <p className="text-xs text-text-tertiary mb-2">Override the accent color for the current theme</p>
        <div className="accent-colors">
          {accentColors.map(color => (
            <button
              key={color.value}
              className={`accent-color-btn ${accentColor === color.value ? 'active' : ''}`}
              style={{ '--swatch-color': color.value } as React.CSSProperties}
              onClick={() => onAccentColorChange(color.value)}
              title={color.name}
              aria-label={`Set accent color to ${color.name}`}
            />
          ))}
        </div>
      </div>
    </SettingsSectionCard>
  );
}
