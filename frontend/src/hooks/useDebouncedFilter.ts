import { useState, useEffect } from 'react';

export function useDebouncedFilter(delay = 300) {
  const [filter, setFilter] = useState('');
  const [debouncedFilter, setDebouncedFilter] = useState('');

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedFilter(filter), delay);
    return () => clearTimeout(timer);
  }, [filter, delay]);

  return { filter, setFilter, debouncedFilter };
}
