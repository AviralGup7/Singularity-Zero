import { useState, useCallback, useEffect, useRef, createContext, useContext, type ReactNode } from 'react';

interface AnnouncerContextType {
  announceAssertive: (message: string) => void;
  announcePolite: (message: string) => void;
}

const AnnouncerContext = createContext<AnnouncerContextType | null>(null);

export function useAnnouncer(): AnnouncerContextType {
  const ctx = useContext(AnnouncerContext);
  if (!ctx) throw new Error('useAnnouncer must be used within LiveAnnouncer');
  return ctx;
}

interface LiveAnnouncerProps {
  children: ReactNode;
}

export function LiveAnnouncer({ children }: LiveAnnouncerProps) {
  const [assertiveMessage, setAssertiveMessage] = useState('');
  const [politeMessage, setPoliteMessage] = useState('');
  // FIX: Track timeouts for cleanup on unmount
  const timeoutsRef = useRef<ReturnType<typeof setTimeout>[]>([]);

  const announceAssertive = useCallback((message: string) => {
    setAssertiveMessage('');
    const t = setTimeout(() => setAssertiveMessage(message), 100);
    timeoutsRef.current.push(t);
  }, []);

  const announcePolite = useCallback((message: string) => {
    setPoliteMessage('');
    const t = setTimeout(() => setPoliteMessage(message), 100);
    timeoutsRef.current.push(t);
  }, []);

  // FIX: Clean up all timeouts on unmount
  useEffect(() => {
    return () => {
      timeoutsRef.current.forEach(clearTimeout);
    };
  }, []);

  return (
    <AnnouncerContext.Provider value={{ announceAssertive, announcePolite }}>
      <div aria-live="assertive" aria-atomic="true" className="sr-only">
        {assertiveMessage}
      </div>
      <div aria-live="polite" aria-atomic="true" className="sr-only">
        {politeMessage}
      </div>
      {children}
    </AnnouncerContext.Provider>
  );
}
