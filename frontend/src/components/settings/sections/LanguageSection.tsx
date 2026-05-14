import { useTranslation } from 'react-i18next';
import { SettingsSectionCard } from '../SettingsComponents';
import { LanguageSelector } from '@/components/LanguageSelector';

export function LanguageSection() {
  const { t, i18n } = useTranslation();

  return (
    <SettingsSectionCard title={t('settings.languageSelector')} icon="\ud83c\udf10">
      <div className="setting-row">
        <label className="setting-label">{t('settings.language')}</label>
        <LanguageSelector value={i18n.language} />
      </div>
    </SettingsSectionCard>
  );
}
