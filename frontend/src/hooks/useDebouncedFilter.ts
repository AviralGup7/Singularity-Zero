import { useState, useEffect, useRef } from 'react';

export function useDebouncedFilter(delay = 300) {
  const [filter, setFilter] = useState('');
  const [debouncedFilter, setDebouncedFilter] = useState('');
  const filterRef = useRef(filter);
  filterRef.current = filter;

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedFilter(filter), delay);
    return () => clearTimeout(timer);
  }, [filter, delay]);

  useEffect(() => () => {
    setDebouncedFilter(filterRef.current);
  }, []);

  return { filter, setFilter, debouncedFilter };
}
