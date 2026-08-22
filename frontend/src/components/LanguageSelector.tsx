import { Globe } from 'lucide-react';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui-shadcn/select';
import { useTranslation } from 'react-i18next';
import { supportedLanguages, languageNames  } from '@/i18n';
import type {SupportedLanguage} from '@/i18n';

export function normalizeLanguage(lang: string | undefined, fallback = 'en'): string {
  const base = String(lang ?? '').split('-')[0]?.toLowerCase() || fallback;
  return (supportedLanguages as readonly string[]).includes(base) ? base : fallback;
}

interface LanguageSelectorProps {
  value?: string;
  onChange?: (lang: string) => void;
}

export function LanguageSelector({ value, onChange }: LanguageSelectorProps) {
  const { i18n } = useTranslation();

  const currentLang = normalizeLanguage(value || i18n.language);

  const handleLanguageChange = (lang: string) => {
    void i18n.changeLanguage(lang);
    onChange?.(lang);
  };

  return (
    <Select value={currentLang} onValueChange={handleLanguageChange}>
      <SelectTrigger aria-label={`Language: ${languageNames[currentLang as SupportedLanguage] ?? currentLang}`}>
        <Globe size={14} className="text-muted shrink-0" aria-hidden="true" />
        <SelectValue placeholder="Select language" />
      </SelectTrigger>
      <SelectContent>
        {supportedLanguages.map((lang) => (
          <SelectItem key={lang} value={lang}>
            {languageNames[lang as SupportedLanguage]}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
