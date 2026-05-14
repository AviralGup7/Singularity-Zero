import { type ThemeMode } from '../../../context/ThemeContext';
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

const themeOptions: { mode: ThemeMode; label: string; icon: string; description: string }[] = [
  { mode: 'dark', label: 'Night Mode', icon: '\ud83c\udf19', description: 'Dark cyberpunk theme with neon accents' },
  { mode: 'light', label: 'Day Mode', icon: '\u2600\ufe0f', description: 'Soft warm tones for comfortable daytime viewing' },
];

interface ThemeSectionProps {
  themeMode: ThemeMode;
  accentColor: string;
  onThemeModeChange: (mode: ThemeMode) => void;
  onAccentColorChange: (color: string) => void;
}

export function ThemeSection({ themeMode, accentColor, onThemeModeChange, onAccentColorChange }: ThemeSectionProps) {
  return (
    <SettingsSectionCard title="Theme" icon="\ud83c\udfa8">
      <div className="theme-options">
        {themeOptions.map(opt => (
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
      <div className="accent-color-picker">
        <label className="setting-label"><span className="setting-title">Accent Color</span></label>
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
