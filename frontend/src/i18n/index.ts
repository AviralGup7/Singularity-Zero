import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import enTranslation from './en/translation.json';

   
export const supportedLanguages = ['en'] as const;
   
export type SupportedLanguage = (typeof supportedLanguages)[number];

export const languageNames: Record<SupportedLanguage, string> = {
  en: 'English',
};

export const defaultLanguage: SupportedLanguage = 'en';

const i18nPromise = i18n.use(initReactI18next).init({
  resources: {
    en: { translation: enTranslation },
  },
  lng: defaultLanguage,
  fallbackLng: defaultLanguage,
  interpolation: {
    escapeValue: false,
  },
}).catch(err => {
   
  console.error('[i18n] Failed to initialize:', err);
});

export { i18nPromise };
export default i18n;
