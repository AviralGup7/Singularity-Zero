import { type ReactNode, Suspense } from 'react';
import { BrowserRouter } from 'react-router-dom';
import { I18nextProvider } from 'react-i18next';
import { LazyMotion, domAnimation } from 'framer-motion';
import i18n from '@/i18n';

import { ThemeProvider } from './ThemeContext';
import { DisplayProvider } from './DisplayContext';
import { SettingsProvider } from './SettingsContext';
import { AuthProvider } from './AuthContext';
import { VisualProvider } from './VisualContext';
import { ToastProvider } from '@/components/Toast';
import { ErrorBoundary } from '@/components/ErrorBoundary';

interface CoreProvidersProps {
  children: ReactNode;
}

export function CoreProviders({ children }: CoreProvidersProps) {
  return (
    <I18nextProvider i18n={i18n}>
      <ErrorBoundary>
        <Suspense fallback={
          <div className="flex flex-col items-center justify-center h-screen bg-bg gap-4">
            <div className="w-12 h-12 border-2 border-accent border-t-transparent rounded-full animate-spin" />
            <p className="font-mono text-[10px] text-accent uppercase tracking-[0.4em] animate-pulse">Syncing Neural Link...</p>
          </div>
        }>
          <LazyMotion features={domAnimation}>
            <BrowserRouter>
              <VisualProvider>
                <ThemeProvider>
                  <ToastProvider>
                    <SettingsProvider>
                      <AuthProvider>
                        <DisplayProvider>
                          {children}
                        </DisplayProvider>
                      </AuthProvider>
                    </SettingsProvider>
                  </ToastProvider>
                </ThemeProvider>
              </VisualProvider>
            </BrowserRouter>
          </LazyMotion>
        </Suspense>
      </ErrorBoundary>
    </I18nextProvider>
  );
}
