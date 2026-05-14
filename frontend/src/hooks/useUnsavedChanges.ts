import { useState, useCallback, useEffect } from 'react';

interface UseUnsavedChangesOptions {
  enabled?: boolean;
  message?: string;
}

export function useUnsavedChanges({ enabled = true, message = 'You have unsaved changes. Are you sure you want to leave?' }: UseUnsavedChangesOptions = {}) {
  const [isDirty, setIsDirty] = useState(false);

  const markDirty = useCallback(() => setIsDirty(true), []);
  const markClean = useCallback(() => setIsDirty(false), []);

  useEffect(() => {
    if (!enabled || !isDirty) return;

    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = message;
      return message;
    };

    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => window.removeEventListener('beforeunload', handleBeforeUnload);
  }, [enabled, isDirty, message]);

  return { isDirty, markDirty, markClean };
}
