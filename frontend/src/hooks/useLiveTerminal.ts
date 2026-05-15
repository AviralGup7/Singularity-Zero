import { useEffect, useRef, useCallback, useState } from 'react';
import { getJobs, getJobLogs } from '../api/client';
import type { Job } from '../types/api';

export interface LiveTerminalLine {
  id: number;
  timestamp: string;
  level: 'info' | 'warn' | 'error' | 'success' | 'critical' | 'debug' | 'system';
  module: string;
  message: string;
  source?: string;
  jobId?: string;
}

const TOOL_REGEX = /(nuclei|nmap|masscan|sqlmap|nikto|gobuster|ffuf|dirb|subfinder|amass|httpx|whatweb|wafw00f|testssl|sslscan|metasploit|crackmapexec|bloodhound|responder|xsser|zaproxy|w3af|skipfish|hydra)/i;

/**
 * High-performance log classifier.
 */
function classifyLogLine(line: string): Omit<LiveTerminalLine, 'id'> {
  const ts = new Date().toLocaleTimeString('en-GB', { hour12: false }) + '.' + String(Date.now() % 1000).padStart(3, '0');
  const trimmed = line.trim();
  const lower = trimmed.toLowerCase();

  let module = 'CORE';
  let level: LiveTerminalLine['level'] = 'info';
  let message = trimmed;
  let source: string | undefined;

  // Nuclei deep-parsing
  const nucleiMatch = trimmed.match(/^\[(?<id>[a-z0-9-]+)\]\s+\[(?<sev>\w+)\]\s+(?<msg>.*)/i);
  if (nucleiMatch && nucleiMatch.groups) {
    module = 'NUCLEI';
    const sev = (nucleiMatch.groups.sev || '').toLowerCase();
    source = nucleiMatch.groups.id;
    message = nucleiMatch.groups.msg || '';
    if (sev === 'critical') level = 'critical';
    else if (sev === 'high') level = 'error';
    else if (sev === 'medium') level = 'warn';
    else if (sev === 'info') level = 'info';
    else level = 'debug';
  } else {
    // Dynamic Tool detection
    const toolMatch = trimmed.match(TOOL_REGEX);
    if (toolMatch) module = toolMatch[1].toUpperCase();

    if (lower.includes('!!!') || lower.includes('critical') || lower.includes('vulnerability found')) level = 'critical';
    else if (lower.includes('error') || lower.includes('failed') || lower.includes('exception')) level = 'error';
    else if (lower.includes('warn') || lower.includes('deprecated')) level = 'warn';
    else if (lower.includes('[+]') || lower.includes('success') || lower.includes('completed')) level = 'success';
    else if (lower.includes('debug') || lower.includes('trace')) level = 'debug';
  }

  // Cleanup aesthetic markers
  message = message.replace(/^\[[+*-]\]\s*/, '');

  return { timestamp: ts, level, module, message, source };
}

export function useLiveTerminal(options: {
  jobId?: string;
  pollInterval?: number;
  maxLines?: number;
  autoConnect?: boolean;
} = {}) {
  const { pollInterval = 3000, maxLines = 10000, autoConnect = true } = options;

  const [lines, setLines] = useState<LiveTerminalLine[]>([]);
  const [activeJobs, setActiveJobs] = useState<Job[]>([]);
  const [isRunning, setIsRunning] = useState(autoConnect);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [connectionMode, setConnectionMode] = useState<'sse' | 'polling' | 'none'>('none');
  const [currentJobId, setCurrentJobId] = useState<string | undefined>(options.jobId);

  const lineIdRef = useRef(0);
  const seenLogKeysRef = useRef<Set<string>>(new Set());
  const logBufferRef = useRef<string[]>([]);
  const flushTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const esRef = useRef<EventSource | null>(null);

  // --- High-Performance Batching ---
  const flushBuffer = useCallback(() => {
    if (logBufferRef.current.length === 0) return;
    
    const rawBatch = [...logBufferRef.current];
    logBufferRef.current = [];

    const newEntries: LiveTerminalLine[] = [];
    for (const raw of rawBatch) {
      const key = `${currentJobId || 'global'}:${raw}`;
      if (seenLogKeysRef.current.has(key)) continue;
      
      seenLogKeysRef.current.add(key);
      if (seenLogKeysRef.current.size > maxLines * 1.5) {
        const iter = seenLogKeysRef.current.values();
        for (let i = 0; i < maxLines * 0.5; i++) {
          const val = iter.next().value;
          if (val !== undefined) seenLogKeysRef.current.delete(val);
          else break;
        }
      }

      newEntries.push({ ...classifyLogLine(raw), id: lineIdRef.current++, jobId: currentJobId });
    }

    if (newEntries.length > 0) {
      setLines(prev => {
        const next = [...prev, ...newEntries];
        return next.length > maxLines ? next.slice(-maxLines) : next;
      });
    }
  }, [currentJobId, maxLines]);

  const addLinesToBuffer = useCallback((raw: string[]) => {
    logBufferRef.current.push(...raw);
  }, []);

  useEffect(() => {
    flushTimerRef.current = setInterval(flushBuffer, 150);
    return () => { if (flushTimerRef.current) clearInterval(flushTimerRef.current); };
  }, [flushBuffer]);

  // --- Data Fetching ---
  const fetchActiveJobs = useCallback(async () => {
    try {
      const jobs = await getJobs();
      const running = jobs.filter(j => j.status === 'running');
      setActiveJobs(running);
      if (!currentJobId && running.length > 0) setCurrentJobId(running[0].id);
      setIsLoading(false);
    } catch (_e) {
      setError('Failed to sync mesh workers');
    }
  }, [currentJobId]);

  const connectSSE = useCallback((id: string) => {
    if (esRef.current) esRef.current.close();
    
    const token = sessionStorage.getItem('auth_token');
    const url = `/api/jobs/${id}/logs/stream${token ? `?token=${encodeURIComponent(token)}` : ''}`;
    const es = new EventSource(url);
    esRef.current = es;

    es.addEventListener('log', (e: MessageEvent) => {
      try {
        const parsed = JSON.parse(e.data);
        if (parsed.data?.line) addLinesToBuffer([parsed.data.line]);
        setConnectionMode('sse');
      } catch (_e) {
        setConnectionMode('polling');
      }
    });

    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) {
        setConnectionMode('polling');
        if (esRef.current) {
          esRef.current.close();
          esRef.current = null;
        }
      }
    };
  }, [addLinesToBuffer]);

  useEffect(() => {
    if (isRunning && currentJobId) {
      connectSSE(currentJobId);
      const interval = setInterval(async () => {
        try {
          const logs = await getJobLogs(currentJobId);
          if (logs?.logs) addLinesToBuffer(logs.logs);
        } catch (_e) {
          addLinesToBuffer([]);
        }
      }, pollInterval);
      return () => {
        clearInterval(interval);
      };
    }
  }, [isRunning, currentJobId, connectSSE, pollInterval, addLinesToBuffer]);

  useEffect(() => {
    if (isRunning) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      void fetchActiveJobs();
      const interval = setInterval(fetchActiveJobs, 10000);
      return () => clearInterval(interval);
    }
  }, [isRunning, fetchActiveJobs]);

  return {
    lines, activeJobs, isRunning, isLoading, error, connectionMode, currentJobId,
    actions: {
      start: () => setIsRunning(true),
      stop: () => setIsRunning(false),
      clear: () => { setLines([]); seenLogKeysRef.current.clear(); },
      selectJob: (id: string) => { setLines([]); setCurrentJobId(id); },
    }
  };
}

export default useLiveTerminal;
