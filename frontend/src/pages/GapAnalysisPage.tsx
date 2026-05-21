import { useState, useMemo, useCallback, useEffect } from 'react';
import { getGapAnalysis, refreshGapAnalysis, getTargets } from '../api/client';
import type { DetectionGapResponse, Target } from '../types/api';
import { Skeleton } from '../components/ui/Skeleton';
import { EmptyState } from '../components/ui/EmptyState';
import { Icon } from '../components/Icon';
import { motion, AnimatePresence } from 'framer-motion';

type SortKey = 'module' | 'coverage_percent' | 'status';
type SortDir = 'asc' | 'desc';
type StatusFilter = 'all' | 'complete' | 'partial' | 'missing';

const STATUS_ORDER = { complete: 0, partial: 1, missing: 2 };

const CATEGORY_METADATA: Record<string, { name: string; desc: string; severity: 'critical' | 'high' | 'medium' | 'low'; remediation: string }> = {
  idor: {
    name: 'Insecure Direct Object Reference (IDOR)',
    desc: 'Occurs when an application uses user-supplied input to access objects directly without proper authorization checks.',
    severity: 'high',
    remediation: 'Implement indirect reference maps or strict row-level Access Control Lists (ACLs) verifying that the authenticated session owns the requested object identifier.',
  },
  ssrf: {
    name: 'Server-Side Request Forgery (SSRF)',
    desc: 'Allows an attacker to abuse server functionality to make requests to internal-only resources, cloud metadata APIs, or local network endpoints.',
    remediation: 'Implement strict IP/domain blocklists (blocking RFC1918 ranges) or, preferably, a strict whitelist of allowed destination endpoints. Resolve DNS queries and validate destination IPs before socket connection.',
    severity: 'critical',
  },
  xss: {
    name: 'Cross-Site Scripting (XSS)',
    desc: 'Allows execution of untrusted scripts in a user\'s browser session, facilitating session hijacking, DOM tampering, or phishing redirections.',
    remediation: 'Use context-aware HTML entity encoding on all user-supplied data in templates, enforce strong Content Security Policies (CSP), and utilize modern frameworks (React/Vue/Angular) which auto-encode outputs.',
    severity: 'high',
  },
  open_redirect: {
    name: 'Open Redirect',
    desc: 'Enables attackers to leverage trusted domains to redirect users to malicious landing pages, often used to bypass email security filter checks.',
    remediation: 'Avoid accepting absolute redirect paths as parameters. Use relative paths only, or validate redirect destinations against a strict domain whitelist.',
    severity: 'medium',
  },
  token_leak: {
    name: 'Token & Session Exposure',
    desc: 'Unauthorized disclosure of authorization credentials, bearer tokens, or session identifiers in HTTP responses, scripts, or application logs.',
    remediation: 'Strip high-entropy security tokens from logging buffers, store session identifiers in secure HttpOnly cookies, and never transmit sensitive keys via query parameters.',
    severity: 'high',
  },
  access_control: {
    name: 'Broken Access Control',
    desc: 'Failure to restrict access permissions across vertical (admin vs user) or horizontal (tenant vs tenant) structural boundaries.',
    remediation: 'Adopt a default-deny routing policy, perform centralized authorization checks on every endpoint, and enforce parameter-level ownership verification.',
    severity: 'high',
  },
  authentication_bypass: {
    name: 'Authentication Bypass',
    desc: 'Mechanisms or endpoints that let an attacker access protected logic without proving identity or validating signatures.',
    remediation: 'Centralize routing authentication checks using trusted middleware, validate cryptographically signed tokens (JWTs) using secure algorithms, and reject methods overrides.',
    severity: 'critical',
  },
  broken_authentication: {
    name: 'Broken Authentication',
    desc: 'Weaknesses in session management or credential validation allowing credential brute forcing or token fixation.',
    remediation: 'Enforce high password complexity, apply strict rate limiting on authentication routes, and invalidate previous sessions upon logout or password reset.',
    severity: 'high',
  },
  business_logic: {
    name: 'Business Logic Flaws',
    desc: 'Bypassing operational constraints or transaction workflows by mutating schemas, parameter payloads, or sequencing steps.',
    remediation: 'Enforce transactional state machine validation on the backend, run mathematical sanity checks on quantities (preventing negative values), and avoid relying on client-side state parameters.',
    severity: 'high',
  },
  payment: {
    name: 'Payment Flow Weaknesses',
    desc: 'Bypassing financial checkout flows, callback signature validations, or transaction amounts.',
    remediation: 'Validate payment webhooks using cryptographic signature checks, check unit prices against internal database tables during checkout rather than accepting client-provided prices, and enforce single-use tokens.',
    severity: 'high',
  },
  sensitive_data: {
    name: 'Sensitive Data Exposure',
    desc: 'Transmission of unencrypted personally identifiable information (PII), credentials, or system diagnostic messages.',
    remediation: 'Encrypt sensitive data both in transit (TLS 1.3) and at rest (AES-256), redact personal identifiers in output pipelines, and set strict security headers.',
    severity: 'high',
  },
  misconfiguration: {
    name: 'Security Misconfiguration',
    desc: 'Improperly hardened servers, loose CORS controls, missing cookie flags, or exposed development consoles.',
    remediation: 'Disable directory listing, strip production server signatures (Server, X-Powered-By), enforce secure Cookie flags (HttpOnly, Secure, SameSite=Lax), and restrict HTTP methods.',
    severity: 'medium',
  },
  cors: {
    name: 'CORS Misconfiguration',
    desc: 'Overly permissive Cross-Origin Resource Sharing rules allowing arbitrary web pages to read authenticated data.',
    remediation: 'Never reflect Origin headers directly alongside Access-Control-Allow-Credentials. Use a strict, static domain whitelist for cors cross-communication.',
    severity: 'medium',
  },
  session: {
    name: 'Session Management Issues',
    desc: 'Long session lifetimes, missing invalidation hooks, or session identifier predictability.',
    remediation: 'Generate high-entropy session identifiers, support backend token revocation, enforce maximum session timeouts, and regenerate tokens upon state change.',
    severity: 'high',
  },
  anomaly: {
    name: 'Telemetry Anomalies',
    desc: 'Atypical response payload lengths or latency variations which might indicate server fuzzing or information leak side channels.',
    remediation: 'Apply uniform latency padding where security checks occur, rate-limit excessive request variance, and monitor backend resource usage metrics.',
    severity: 'medium',
  },
  behavioral_deviation: {
    name: 'WAF / IPS Detection Bypasses',
    desc: 'Vulnerabilities exposed due to evasion techniques mapping behavioral limits.',
    remediation: 'Ensure consistent input validation irrespective of payload length, maintain dynamic IP blocklists, and evaluate heuristic threat patterns.',
    severity: 'medium',
  },
  redirect: {
    name: 'Redirect Chains & Loops',
    desc: 'Uncontrolled redirect patterns triggering authentication loops or cross-site referral leaks.',
    remediation: 'Restrict OAuth redirect URLs to precise whitelisted client routes and validate state parameters to prevent referral interception.',
    severity: 'medium',
  },
  server_side_injection: {
    name: 'Server-Side Injection (RCE/SQLi)',
    desc: 'Direct execution of arbitrary template expressions, SQL databases queries, or shell commands via unvalidated parameter entry.',
    remediation: 'Use parameterized queries / ORMs exclusively, sandbox template compiler runtimes, and never execute system shell strings using user parameters.',
    severity: 'critical',
  },
  race_condition: {
    name: 'Race Condition (Concurrency Flaws)',
    desc: 'Executing multiple overlapping parallel requests to double spend credits, duplicate account links, or bypass transaction locks.',
    remediation: 'Use transactional locks, atomic database transactions (e.g. SELECT FOR UPDATE), or distributed key locks (Redis/Redlock) to serialize access to highly sensitive resources.',
    severity: 'high',
  },
  csrf: {
    name: 'Cross-Site Request Forgery (CSRF)',
    desc: 'Inducing a user browser to perform actions on their behalf on an authenticated web app.',
    remediation: 'Use anti-CSRF token verification on state-changing requests, and configure cookies with Strict/Lax SameSite constraints.',
    severity: 'medium',
  },
  ssti: {
    name: 'Server-Side Template Injection (SSTI)',
    desc: 'Injecting expressions inside template engines which then run with full backend sandbox permissions.',
    remediation: 'Disable dynamic template rendering on user input, or use completely sandboxed templating environments with restricted modules access.',
    severity: 'critical',
  },
  ai_surface: {
    name: 'AI/ML Surface Exposure',
    desc: 'Abusing LLM models to leak system prompts, access sandboxed actions, or inject model weights commands.',
    remediation: 'Perform strict pre-prompt sanitization, isolate AI endpoints workflows, and treat LLM outputs as untrusted parameters.',
    severity: 'medium',
  },
  exposure: {
    name: 'Information Leakage & File Exposure',
    desc: 'Leaking raw environment parameters, backup volumes, active GraphQL schemas, or debug stack traces.',
    remediation: 'Block direct access to server directory backups (.bak, .git, .env), disable verbose stack traces in production environment, and restrict GraphQL introspection schemas.',
    severity: 'medium',
  },
};

export function GapAnalysisPage() {
  const [data, setData] = useState<DetectionGapResponse | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [selectedTarget, setSelectedTarget] = useState<string>('all');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sortKey, setSortKey] = useState<SortKey>('module');
  const [sortDir, setSortDir] = useState<SortDir>('asc');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());

  // Modal State for active mitigation
  const [activeMitigation, setActiveMitigation] = useState<{
    module: string;
    category: string;
    missing: string[];
  } | null>(null);
  const [copied, setCopied] = useState(false);

  // Fetch targets list
  useEffect(() => {
    async function loadTargets() {
      try {
        const res = await getTargets();
        if (res && res.targets) {
          setTargets(res.targets);
        }
      } catch (err) {
        console.error('Failed to load targets:', err);
      }
    }
    loadTargets();
  }, []);

  const loadData = useCallback(async (signal?: AbortSignal) => {
    try {
      setLoading(true);
      const targetParam = selectedTarget === 'all' ? null : selectedTarget;
      const result = await getGapAnalysis(targetParam, signal);
      setData(result);
      setError(null);
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') return;
      setError('Failed to load gap analysis data. Infrastructure mesh may be desynchronized.');
    } finally {
      setLoading(false);
    }
  }, [selectedTarget]);

  useEffect(() => {
    const controller = new AbortController();
    loadData(controller.signal);
    return () => controller.abort();
  }, [loadData]);

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await refreshGapAnalysis();
      await loadData();
    } catch {
      setError('Failed to trigger analysis refresh.');
    } finally {
      setRefreshing(false);
    }
  };

  const handleSort = (key: SortKey) => {
    setSortDir(prev => sortKey === key ? (prev === 'asc' ? 'desc' : 'asc') : 'asc');
    setSortKey(key);
  };

  const toggleExpand = (module: string) => {
    setExpandedRows(prev => {
      const next = new Set(prev);
      if (next.has(module)) next.delete(module);
      else next.add(module);
      return next;
    });
  };

  const handleCopyPatch = (patchText: string) => {
    navigator.clipboard.writeText(patchText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const filtered = useMemo(() => {
    if (!data || !data.results) return [];
   
    let result = [...data.results];
    
    if (statusFilter !== 'all') {
      result = result.filter(r => r && r.status === statusFilter);
    }
    
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter(r => 
        r && (
          (r.module || '').toLowerCase().includes(q) || 
          (r.category || '').toLowerCase().includes(q)
        )
      );
    }

    result.sort((a, b) => {
      if (!a || !b) return 0;
      let cmp = 0;
      if (sortKey === 'module') cmp = (a.module || '').localeCompare(b.module || '');
      else if (sortKey === 'coverage_percent') cmp = (a.coverage_percent || 0) - (b.coverage_percent || 0);
      else if (sortKey === 'status') cmp = (STATUS_ORDER[a.status] ?? 3) - (STATUS_ORDER[b.status] ?? 3);
      return sortDir === 'asc' ? cmp : -cmp;
    });
    
    return result;
  }, [data, statusFilter, searchQuery, sortKey, sortDir]);

  if (loading && !data) return (
    <div className="p-6 space-y-6">
      <Skeleton className="h-10 w-48" />
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Skeleton className="h-32" />
        <Skeleton className="h-32" />
        <Skeleton className="h-32" />
      </div>
      <Skeleton className="h-96" />
    </div>
  );

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-8 animate-in fade-in duration-500">
      <header className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold flex items-center gap-2">
            <Icon name="shieldCheck" size={24} className="text-accent" />
            Detection Gap Analysis
          </h2>
          <p className="text-muted text-sm mt-1">
            Compare active module capabilities against the global vulnerability registry.
          </p>
        </div>

        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <div className="flex items-center gap-2 bg-black/40 border border-white/10 rounded-lg px-3 py-1.5 focus-within:border-accent/50 transition-colors">
            <span className="text-[10px] text-muted font-bold uppercase tracking-wider whitespace-nowrap">Target Target:</span>
            <select
              value={selectedTarget}
              onChange={e => setSelectedTarget(e.target.value)}
              className="bg-transparent text-sm font-bold text-text focus:outline-none cursor-pointer pr-6 appearance-none"
              style={{
                backgroundImage: 'url("data:image/svg+xml,%3csvg xmlns=\'http://www.w3.org/2000/svg\' fill=\'none\' viewBox=\'0 0 20 20\'%3e%3cpath stroke=\'%23a3a3a3\' stroke-linecap=\'round\' stroke-linejoin=\'round\' stroke-width=\'1.5\' d=\'M6 8l4 4 4-4\'/%3e%3c/svg%3e")',
                backgroundPosition: 'right center',
                backgroundSize: '1.2em 1.2em',
                backgroundRepeat: 'no-repeat',
              }}
            >
              <option value="all" className="bg-panel text-text font-bold">All Targets (Aggregated)</option>
              {targets.map(t => (
                <option key={t.name} value={t.name} className="bg-panel text-text">
                  {t.name}
                </option>
              ))}
            </select>
          </div>

          <button 
            onClick={handleRefresh}
            disabled={refreshing}
            className={`btn btn-secondary flex items-center gap-2 ${refreshing ? 'animate-pulse' : ''}`}
          >
            <Icon name="refresh" size={16} className={refreshing ? 'animate-spin' : ''} />
            {refreshing ? 'Analyzing...' : 'Refresh Analysis'}
          </button>
        </div>
      </header>

      {error && (
        <div className="p-4 bg-bad/10 border border-bad/20 rounded-lg text-bad text-sm flex items-center gap-3">
          <Icon name="alertTriangle" size={18} />
          {error}
        </div>
      )}

      {data && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-panel border border-white/5 p-6 rounded-xl cyber-glow-sm"
          >
            <div className="text-muted text-xs uppercase tracking-widest font-bold mb-2">Overall Coverage</div>
            <div className={`text-4xl font-black ${
              data.overall_coverage > 80 ? 'text-ok' : data.overall_coverage > 50 ? 'text-warn' : 'text-bad'
            }`}>
              {data.overall_coverage}%
            </div>
            <div className="mt-4 h-1.5 w-full bg-white/5 rounded-full overflow-hidden">
              <div 
                className={`h-full transition-all duration-1000 ${
                  data.overall_coverage > 80 ? 'bg-ok' : data.overall_coverage > 50 ? 'bg-warn' : 'bg-bad'
                }`}
                style={{ width: `${data.overall_coverage}%` }}
              />
            </div>
          </motion.div>

          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="bg-panel border border-white/5 p-6 rounded-xl"
          >
            <div className="text-muted text-xs uppercase tracking-widest font-bold mb-2">Module Integrity</div>
            <div className="text-4xl font-black text-text">
              {data.total_modules - data.modules_with_gaps}<span className="text-lg text-muted font-normal ml-2">/ {data.total_modules} OK</span>
            </div>
            <div className="text-xs text-muted mt-2 italic">
              Modules meeting 100% of detection registry requirements.
            </div>
          </motion.div>

          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="bg-panel border border-white/5 p-6 rounded-xl"
          >
            <div className="text-muted text-xs uppercase tracking-widest font-bold mb-2">Identified Gaps</div>
            <div className={`text-4xl font-black ${data.modules_with_gaps > 0 ? 'text-warn' : 'text-ok'}`}>
              {data.modules_with_gaps}
            </div>
            <div className="text-xs text-muted mt-2">
              Requires immediate action to reach full security posture.
            </div>
          </motion.div>
        </div>
      )}

      <div className="bg-panel border border-white/5 rounded-xl overflow-hidden shadow-2xl">
        <div className="p-4 border-b border-white/5 bg-white/5 flex flex-col md:flex-row gap-4 justify-between items-center">
          <div className="relative w-full md:w-96">
            <Icon name="search" size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input 
              type="text" 
              placeholder="Filter by module or category..."
              className="w-full bg-black/40 border border-white/10 rounded-lg py-2 pl-10 pr-4 text-sm focus:outline-none focus:border-accent/50 transition-colors"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
            />
          </div>
          
          <div className="flex items-center gap-3 w-full md:w-auto">
            <label htmlFor="status-filter" className="text-xs text-muted font-bold uppercase whitespace-nowrap">Filter Status</label>
            <select 
              id="status-filter"
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value as StatusFilter)}
              className="bg-black/40 border border-white/10 rounded-lg py-2 px-4 text-xs focus:outline-none focus:border-accent/50 appearance-none cursor-pointer"
            >
              <option value="all">All Statuses</option>
              <option value="complete">Complete</option>
              <option value="partial">Partial</option>
              <option value="missing">Missing</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-white/5 text-[10px] uppercase tracking-tighter font-black text-muted border-b border-white/5">
                <th className="p-4 cursor-pointer hover:text-text transition-colors" onClick={() => handleSort('module')}>
                  Module {sortKey === 'module' && (sortDir === 'asc' ? '↑' : '↓')}
                </th>
                <th className="p-4">Category</th>
                <th className="p-4 cursor-pointer hover:text-text transition-colors" onClick={() => handleSort('coverage_percent')}>
                  Coverage {sortKey === 'coverage_percent' && (sortDir === 'asc' ? '↑' : '↓')}
                </th>
                <th className="p-4">Check Integrity</th>
                <th className="p-4 cursor-pointer hover:text-text transition-colors" onClick={() => handleSort('status')}>
                  Status {sortKey === 'status' && (sortDir === 'asc' ? '↑' : '↓')}
                </th>
                <th className="p-4"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {filtered.map((row) => (
                <tr key={row.module} className="group hover:bg-white/[0.02] transition-colors">
                  <td className="p-4">
                    <div className="font-bold text-sm text-text">{row.module}</div>
                  </td>
                  <td className="p-4">
                    <span className="text-[10px] font-mono text-accent bg-accent/10 px-2 py-0.5 rounded border border-accent/20">
                      {row.category}
                    </span>
                  </td>
                  <td className="p-4">
                    <div className={`text-sm font-black ${
                      row.coverage_percent === 100 ? 'text-ok' : row.coverage_percent > 0 ? 'text-warn' : 'text-bad'
                    }`}>
                      {row.coverage_percent}%
                    </div>
                  </td>
                  <td className="p-4 w-48">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-1 bg-white/5 rounded-full overflow-hidden">
                        <div 
                          className={`h-full rounded-full ${
                            row.coverage_percent === 100 ? 'bg-ok' : row.coverage_percent > 0 ? 'bg-warn' : 'bg-bad'
                          }`}
                          style={{ width: `${row.coverage_percent}%` }}
                        />
                      </div>
                      <span className="text-[9px] font-mono text-muted tabular-nums">
                        {row.covered_checks}/{row.total_checks}
                      </span>
                    </div>
                  </td>
                  <td className="p-4">
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                      row.status === 'complete' ? 'bg-ok/10 text-ok border border-ok/20' :
                      row.status === 'partial' ? 'bg-warn/10 text-warn border border-warn/20' :
                      'bg-bad/10 text-bad border border-bad/20'
                    }`}>
                      {row.status}
                    </span>
                  </td>
                  <td className="p-4 text-right">
                    {row.missing_checks > 0 && (
                      <button 
                        onClick={() => toggleExpand(row.module)}
                        className="p-1 hover:bg-white/10 rounded transition-colors text-muted hover:text-text"
                      >
                        <Icon name={expandedRows.has(row.module) ? 'chevronUp' : 'chevronDown'} size={16} />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          
          {filtered.length === 0 && (
            <div className="py-20">
              <EmptyState 
                title="No modules found" 
                description="Adjust your filters or search query to find specific detection modules." 
                icon="shield" 
              />
            </div>
          )}
        </div>
      </div>

      <AnimatePresence>
        {filtered.filter(r => r.missing_checks > 0 && expandedRows.has(r.module)).length > 0 && (
          <div className="space-y-4">
            <h3 className="text-lg font-bold flex items-center gap-2 px-2">
              <Icon name="alertTriangle" size={18} className="text-warn" />
              Critical Coverage Deficiencies
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {filtered.filter(r => r.missing_checks > 0 && expandedRows.has(r.module)).map(row => (
                <motion.div
                  key={row.module}
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  className="bg-panel border border-warn/20 p-4 rounded-xl relative overflow-hidden group"
                >
                  <div className="absolute top-0 right-0 w-32 h-32 bg-warn/5 -rotate-45 translate-x-16 -translate-y-16 pointer-events-none" />
                  <div className="flex justify-between items-start mb-4">
                    <div>
                      <h4 className="font-bold text-text">{row.module}</h4>
                      <p className="text-[10px] text-muted uppercase tracking-wider">Module deficiency report</p>
                    </div>
                    <div className="bg-warn/10 text-warn text-[10px] font-bold px-2 py-0.5 rounded border border-warn/20">
                      -{row.missing_checks} Checks
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    {row.missing_check_details && row.missing_check_details.length > 0 ? (
                      row.missing_check_details.map((check, i) => (
                        <div key={i} className="flex items-start gap-2 text-xs text-muted/80 font-mono bg-black/25 p-2 rounded border border-white/5">
                          <span className="text-warn mt-0.5">•</span>
                          <span className="text-left leading-relaxed">{check}</span>
                        </div>
                      ))
                    ) : (
                      Array.from({ length: row.missing_checks }).map((_, i) => (
                        <div key={i} className="flex items-center gap-2 text-xs text-muted/80 font-mono bg-black/25 p-2 rounded border border-white/5">
                          <span className="text-warn opacity-50">•</span>
                          <span>Missing capability validation check {i + 1}</span>
                        </div>
                      ))
                    )}
                  </div>
                  
                  <div className="mt-4 pt-4 border-t border-white/5">
                    <button 
                      onClick={() => setActiveMitigation({
                        module: row.module,
                        category: row.category,
                        missing: row.missing_check_details || []
                      })}
                      className="text-[10px] text-accent hover:underline font-bold uppercase tracking-widest flex items-center gap-1.5"
                    >
                      <Icon name="zap" size={10} />
                      View Mitigation Guide & Patch
                    </button>
                  </div>
                </motion.div>
              ))}
            </div>
          </div>
        )}
      </AnimatePresence>

      {/* MITIGATION DRAWER / MODAL */}
      <AnimatePresence>
        {activeMitigation && (() => {
          const meta = CATEGORY_METADATA[activeMitigation.category] || {
            name: activeMitigation.category.toUpperCase() + ' Vulnerability',
            desc: 'A detected security validation gap within the module scanning matrix.',
            remediation: 'Configure scanner rules or implement strict code validation logic.',
            severity: 'high',
          };
          const targetName = selectedTarget === 'all' ? 'target_name' : selectedTarget;
          const runCmd = `python -m src.pipeline.run --target ${targetName} --mode custom --modules ${activeMitigation.module}`;
          const patchJson = JSON.stringify({
            target: targetName,
            enabled_modules: [activeMitigation.module]
          }, null, 2);

          return (
            <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in duration-300">
              <motion.div
                initial={{ opacity: 0, y: 50, scale: 0.95 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: 50, scale: 0.95 }}
                className="relative w-full max-w-2xl bg-panel border border-white/10 rounded-2xl overflow-hidden shadow-2xl"
              >
                <div className="absolute top-0 right-0 w-48 h-48 bg-accent/5 -rotate-45 translate-x-24 -translate-y-24 pointer-events-none" />
                
                {/* Header */}
                <div className="p-6 border-b border-white/5 flex items-center justify-between">
                  <div>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                      meta.severity === 'critical' ? 'bg-bad/20 text-bad border border-bad/30' :
                      meta.severity === 'high' ? 'bg-warn/20 text-warn border border-warn/30' :
                      'bg-accent/20 text-accent border border-accent/30'
                    }`}>
                      {meta.severity} severity
                    </span>
                    <h3 className="text-xl font-bold text-text mt-2">{meta.name}</h3>
                  </div>
                  <button
                    onClick={() => {
                      setActiveMitigation(null);
                      setCopied(false);
                    }}
                    className="p-1.5 hover:bg-white/5 rounded-lg transition-colors text-muted hover:text-text"
                  >
                    <Icon name="x" size={20} />
                  </button>
                </div>

                {/* Body */}
                <div className="p-6 space-y-6 max-h-[70vh] overflow-y-auto">
                  {/* Category Description */}
                  <div className="space-y-2">
                    <div className="text-[10px] text-muted font-bold uppercase tracking-wider">Deficiency Analysis</div>
                    <p className="text-sm text-muted/90 leading-relaxed text-left">{meta.desc}</p>
                  </div>

                  {/* Missing checks details */}
                  {activeMitigation.missing.length > 0 && (
                    <div className="space-y-3 text-left">
                      <div className="text-[10px] text-muted font-bold uppercase tracking-wider">Unverified Edge Cases</div>
                      <div className="grid grid-cols-1 gap-2">
                        {activeMitigation.missing.map((check, i) => (
                          <div key={i} className="flex items-start gap-3 bg-black/40 border border-white/5 p-2.5 rounded-lg text-xs font-mono text-muted">
                            <span className="text-accent">•</span>
                            <span className="text-left">{check}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Remediation Advice */}
                  <div className="space-y-2 text-left">
                    <div className="text-[10px] text-muted font-bold uppercase tracking-wider">Secure Coding Remediation</div>
                    <div className="bg-accent/5 border border-accent/10 rounded-xl p-4 text-sm text-text leading-relaxed flex items-start gap-3">
                      <Icon name="info" size={18} className="text-accent mt-0.5 flex-shrink-0" />
                      <p className="text-left">{meta.remediation}</p>
                    </div>
                  </div>

                  {/* Run CLI command */}
                  <div className="space-y-2 text-left">
                    <div className="text-[10px] text-muted font-bold uppercase tracking-wider flex items-center gap-1.5">
                      <Icon name="terminal" size={12} className="text-muted" />
                      Ad-Hoc Execution Command
                    </div>
                    <div className="relative bg-black/60 rounded-lg p-3 border border-white/10 font-mono text-xs text-ok overflow-x-auto text-left select-all">
                      {runCmd}
                    </div>
                  </div>

                  {/* Config Patch Generator */}
                  <div className="space-y-2 text-left">
                    <div className="flex items-center justify-between">
                      <div className="text-[10px] text-muted font-bold uppercase tracking-wider">Orchestrator Config Patch</div>
                      <button
                        onClick={() => handleCopyPatch(patchJson)}
                        className="text-[10px] text-accent hover:underline font-bold uppercase tracking-wider flex items-center gap-1"
                      >
                        <Icon name="copy" size={12} />
                        {copied ? 'Copied!' : 'Copy Patch'}
                      </button>
                    </div>
                    <pre className="bg-black/60 rounded-lg p-3 border border-white/10 font-mono text-xs text-text overflow-x-auto text-left text-muted/95">
                      {patchJson}
                    </pre>
                  </div>
                </div>

                {/* Footer */}
                <div className="p-4 border-t border-white/5 bg-white/[0.01] flex justify-end gap-3">
                  <button
                    onClick={() => {
                      setActiveMitigation(null);
                      setCopied(false);
                    }}
                    className="btn btn-secondary px-4 py-2 text-xs font-bold uppercase tracking-wider"
                  >
                    Close Guide
                  </button>
                </div>
              </motion.div>
            </div>
          );
        })()}
      </AnimatePresence>
    </div>
  );
}
