 1: import { useEffect, useRef, useState, useCallback } from 'react';
 2: import { captureException } from '@/utils/errorTracker';
 3: 
 4: export interface SseEventData {
 5:    
 6:   [key: string]: unknown;
 7:   message?: string;
 8:   progress?: number;
 9:   stage?: string;
10:   iteration?: number;
11:   finding_count?: number;
12: }
13: 
14: export type SSEConnectionState = 'connecting' | 'connected' | 'reconnecting' | 'failed' | 'closed';
15: 
16: export interface SseEvent<T = SseEventData> {
17:   id: string;
18:   event_type: string;
19:   job_id: string;
20:   timestamp: number;
21:   data: T;
22: }
23: 
24: interface UseSSEProgressOptions<T = SseEventData> {
25:   jobId: string | undefined;
26:   enabled?: boolean;
27:   onEvent?: (event: SseEvent<T>) => void;
28:   endpoint?: 'logs' | 'progress';
29: }
30: 
31: const MIN_DELAY = 1000;
32: const MAX_DELAY = 60000;
33: const HEARTBEAT_TIMEOUT = 35000;
34: 
35: export function useSSEProgress<T = SseEventData>({
36:   jobId,
37:   enabled = true,
38:   onEvent,
39:   endpoint = 'progress',
40: }: UseSSEProgressOptions<T>) {
41:    
42:   const [connectionState, setConnectionState] = useState<SSEConnectionState>('closed');
43:    
44:   const [isPollingFallback, setIsPollingFallback] = useState(false);
45: 
46:   const esRef = useRef<EventSource | null>(null);
47:   const backoffRef = useRef(MIN_DELAY);
48:   const mountedRef = useRef(true);
49:   const onEventRef = useRef(onEvent);
50:   const heartbeatRef = useRef<ReturnType<typeof setTimeout> | null>(null);
51:   const seenIdsRef = useRef<Set<string>>(new Set());
52: 
53:   // --- High-Performance Lifecycle Management ---
54:   useEffect(() => {
55:     onEventRef.current = onEvent;
56:    
57:   }, [onEvent]);
58: 
59:   const connectRef = useRef<() => void>(() => {});
60: 
61:   const resetHeartbeat = useCallback(() => {
62:     if (heartbeatRef.current) clearTimeout(heartbeatRef.current);
63:     heartbeatRef.current = setTimeout(() => {
64:       console.warn('SSE Heartbeat Timeout - Reconnecting...');
65:       connectRef.current();
66:     }, HEARTBEAT_TIMEOUT);
67:   }, []);
68: 
69:   const connect = useCallback(() => {
70:     if (!jobId || !enabled || !mountedRef.current) return;
71: 
72:     if (esRef.current) {
73:       esRef.current.close();
74:       esRef.current = null;
75:     }
76: 
77:     const token = sessionStorage.getItem('auth_token');
78:     // SECURITY: Passing token in query string is non-ideal but standard EventSource lacks header support.
79:     // Ensure the backend logs are configured to redact this parameter.
80:     const url = `/api/jobs/${jobId}/${endpoint}/stream${token ? `?token=${encodeURIComponent(token)}` : ''}`;
81: 
82:     setConnectionState('connecting');
83:     const es = new EventSource(url);
84:     esRef.current = es;
85: 
86:     es.onopen = () => {
87:       if (!mountedRef.current) return;
88:       setConnectionState('connected');
89:       setIsPollingFallback(false);
90:       backoffRef.current = MIN_DELAY;
91:       resetHeartbeat();
92:     };
93: 
94:     const handleMessage = (e: MessageEvent) => {
95:       if (!mountedRef.current) return;
96:       resetHeartbeat();
97:        
98:       try {
99:         const parsed = JSON.parse(e.data) as SseEvent<T>;
100:         const eventId = parsed.id || `${parsed.event_type}:${parsed.timestamp}`;
101:         
102:         if (seenIdsRef.current.has(eventId)) return;
103:         seenIdsRef.current.add(eventId);
104:         
105:         // Fast FIFO prune
106:         if (seenIdsRef.current.size > 2000) {
107:           const iter = seenIdsRef.current.values();
108:           for(let i=0; i<500; i++) {
109:             const val = iter.next().value;
110:             if (val !== undefined) seenIdsRef.current.delete(val);
111:           }
112:         }
113: 
114:         onEventRef.current?.(parsed);
115:       } catch (err) {
116:         captureException(err as Error, { component: 'useSSEProgress', action: 'parse' });
117:         console.warn('[SSE] parse error', err);
118:       }
119:     };
120: 
121:     es.onmessage = handleMessage;
122:    
123:     ['log', 'progress_update', 'stage_change', 'finding_batch', 'mesh_health_update', 'migration_event', 'completed', 'error'].forEach(type => {
124:       es.addEventListener(type, handleMessage);
125:     });
126: 
127:     es.onerror = () => {
128:       if (!mountedRef.current) return;
129:       setConnectionState('reconnecting');
130:       
131:       if (es.readyState === EventSource.CLOSED) {
132:         const delay = backoffRef.current;
133:         backoffRef.current = Math.min(backoffRef.current * 1.5, MAX_DELAY);
134:         setTimeout(connectRef.current, delay);
135:       }
136:     };
137:    
138:   }, [jobId, enabled, endpoint, resetHeartbeat]);
139: 
140:   useEffect(() => {
141:     connectRef.current = connect;
142:    
143:   }, [connect]);
144: 
145:   useEffect(() => {
146:     mountedRef.current = true;
147:     // eslint-disable-next-line react-hooks/set-state-in-effect
148:     if (enabled && jobId) connect();
149:     return () => {
150:       mountedRef.current = false;
151:       if (esRef.current) esRef.current.close();
152:       if (heartbeatRef.current) clearTimeout(heartbeatRef.current);
153:     };
154:    
155:   }, [jobId, enabled, connect]);
156: 
157:   return {
158:     connectionState,
159:     isPollingFallback,
160:     reconnect: connect,
161:     disconnect: () => { if (esRef.current) esRef.current.close(); setConnectionState('closed'); }
162:   };
163: }
164: 
