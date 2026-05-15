import { createContext, useContext } from 'react';

export interface AnnouncerContextType {
  announceAssertive: (message: string) => void;
  announcePolite: (message: string) => void;
}

export const AnnouncerContext = createContext<AnnouncerContextType | null>(null);

export function useAnnouncer(): AnnouncerContextType {
  const ctx = useContext(AnnouncerContext);
  if (!ctx) throw new Error('useAnnouncer must be used within LiveAnnouncer');
  return ctx;
}
