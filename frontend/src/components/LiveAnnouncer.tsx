import { useState, useCallback, useEffect, useRef, type ReactNode } from 'react';
import { AnnouncerContext } from '@/hooks/useAnnouncer';

interface LiveAnnouncerProps {
  children: ReactNode;
}

export function LiveAnnouncer({ children }: LiveAnnouncerProps) {
  const [assertiveMessage, setAssertiveMessage] = useState('');
  const [politeMessage, setPoliteMessage] = useState('');
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

  useEffect(() => {
    const timeouts = timeoutsRef.current;
    return () => {
      timeouts.forEach(clearTimeout);
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
