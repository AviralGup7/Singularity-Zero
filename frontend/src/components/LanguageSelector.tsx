import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui-shadcn/select';
import { useTranslation } from 'react-i18next';
import { supportedLanguages, languageNames, type SupportedLanguage } from '@/i18n';

interface LanguageSelectorProps {
  value?: string;
  onChange?: (lang: string) => void;
}

export function LanguageSelector({ value, onChange }: LanguageSelectorProps) {
  const { i18n } = useTranslation();

  const currentLang = value || i18n.language;

  const handleLanguageChange = (lang: string) => {
    void i18n.changeLanguage(lang);
    onChange?.(lang);
  };

  return (
    <Select value={currentLang} onValueChange={handleLanguageChange}>
      <SelectTrigger aria-label="Select language">
        <SelectValue placeholder="Select language" />
      </SelectTrigger>
      <SelectContent>
        {supportedLanguages.map((lang) => (
          <SelectItem key={lang} value={lang}>
  // eslint-disable-next-line security/detect-object-injection
            {languageNames[lang as SupportedLanguage]}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
