import { useCallback, useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { KeyRound, Plus, RefreshCw, ShieldAlert, ShieldCheck, Trash2, Copy, Check, ChevronDown } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip as ChartTooltip } from 'recharts';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { PageSkeleton } from '@/components/ui/Skeleton';
import { EmptyState } from '@/components/ui/EmptyState';
import { PageHeader } from '@/components/ui/PageHeader';
import { GlassCard } from '@/components/ui/GlassCard';
import { AnimatedCounter } from '@/components/ui/AnimatedCounter';
import { SafeResponsiveContainer } from '@/components/ui/SafeResponsiveContainer';
import {
  generateApiKey,
  getApiKeys,
  getCspReports,
  getRateLimitStatus,
  getSecurityEvents,
  revokeApiKey,
  type ApiKeyRecord,
  type CspReport,
  type RateLimitStatus,
  type SecurityEvent,
} from '@/api/security';

function formatDate(value: string | null | undefined): string {
  if (!value) return 'Never';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function roleTone(role: ApiKeyRecord['role']): 'critical' | 'high' | 'medium' | 'info' {
  if (role === 'admin') return 'critical';
  if (role === 'worker') return 'high';
  if (role === 'read_only') return 'medium';
  return 'info';
}

function statusTone(status: number | null): 'critical' | 'high' | 'medium' | 'info' {
  if (!status) return 'info';
  if (status >= 500) return 'critical';
  if (status === 429 || status === 401 || status === 403) return 'high';
  if (status >= 400) return 'medium';
  return 'info';
}

const EASE_OUT = [0.16, 1, 0.3, 1] as const;

export function SecurityPage() {
  const [rateLimit, setRateLimit] = useState<RateLimitStatus | null>(null);
  const [apiKeys, setApiKeys] = useState<ApiKeyRecord[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [cspReports, setCspReports] = useState<CspReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [newRole, setNewRole] = useState<ApiKeyRecord['role']>('read_only');
  const [generatedKey, setGeneratedKey] = useState<string | null>(null);
  
  // Custom states for interactive features
  const [copied, setCopied] = useState(false);
  const [expandedReportId, setExpandedReportId] = useState<number | null>(null);

  const refresh = useCallback(async () => {
    const [rates, keys, eventRows, reports] = await Promise.all([
      getRateLimitStatus(),
      getApiKeys(),
      getSecurityEvents(),
      getCspReports(),
    ]);
    setRateLimit(rates);
    setApiKeys(keys);
    setEvents(eventRows);
    setCspReports(reports);
  }, []);

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      try {
        await refresh();
      } catch {
        if (mounted) setMessage('Security telemetry is unavailable');
      } finally {
        if (mounted) setLoading(false);
      }
    };
    load();
    const interval = window.setInterval(() => {
      refresh().catch(() => setMessage('Security telemetry refresh failed'));
    }, 5000);
    return () => {
      mounted = false;
      window.clearInterval(interval);
    };
  }, [refresh]);

  const activeKeys = useMemo(() => apiKeys.filter(key => key.active).length, [apiKeys]);
  const recentFailures = useMemo(
    () => events.filter(event => (event.status_code ?? 0) >= 400).length,
    [events]
  );

  const handleGenerate = async () => {
    try {
      const record = await generateApiKey(newRole);
      setGeneratedKey(record.api_key);
      setMessage(`Generated ${record.role} key`);
      await refresh();
    } catch {
      setMessage('Unable to generate API key');
    }
  };

  const handleRevoke = async (id: string) => {
    try {
      await revokeApiKey(id);
      setMessage('API key revoked');
      await refresh();
    } catch {
      setMessage('Unable to revoke API key');
    }
  };

  const handleCopy = async () => {
    if (!generatedKey) return;
    try {
      await navigator.clipboard.writeText(generatedKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy API key:', err);
    }
  };

  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: {
        staggerChildren: 0.08,
      },
    },
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 15 },
    show: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 100, damping: 15 } },
  };

  if (loading) {
    return <PageSkeleton />;
  }

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="show"
      className="security-page p-6 space-y-6"
    >
      <PageHeader
        icon={<ShieldCheck size={20} />}
        title="Security Monitor"
        subtitle="API limits, scoped keys, and enforcement events"
        actions={
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 bg-[var(--surface-2)] px-3 py-1.5 rounded-lg border border-[var(--border)]">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              <span className="text-[10px] text-[var(--text-secondary)] font-semibold font-mono tracking-wider">TELEMETRY LIVE</span>
            </div>
            <Button variant="secondary" onClick={() => refresh()} size="sm" className="flex items-center gap-1">
              <RefreshCw size={14} aria-hidden="true" />
              <span>Refresh</span>
            </Button>
          </div>
        }
      />

      {message && (
        <motion.div
          initial={{ height: 0, opacity: 0 }}
          animate={{ height: 'auto', opacity: 1 }}
          exit={{ height: 0, opacity: 0 }}
          className="banner info"
          role="status"
        >
          {message}
          <button type="button" className="ml-4 text-xs opacity-70 hover:opacity-100" onClick={() => setMessage(null)}>
            Dismiss
          </button>
        </motion.div>
      )}

      {generatedKey && (
        <motion.section
          variants={itemVariants}
          className="card p-4 border border-[var(--ok)]/40 relative bg-[var(--surface-2)]"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-[var(--ok)] font-bold">
              <KeyRound size={16} aria-hidden="true" />
              New API key
            </div>
            <button
              onClick={handleCopy}
              className="btn btn-xs btn-secondary flex items-center gap-1.5"
            >
              {copied ? <Check size={12} className="text-[var(--ok)]" /> : <Copy size={12} />}
              <span>{copied ? 'Copied' : 'Copy Key'}</span>
            </button>
          </div>
          <code className="mt-3 block overflow-x-auto border border-[var(--border)] bg-[var(--surface)] p-3 text-xs rounded font-mono text-[var(--accent)]">
            {generatedKey}
          </code>
        </motion.section>
      )}

      {/* KPI Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <GlassCard variant="glow" delay={0.05}>
          <div className="flex items-center gap-2 text-muted text-xs uppercase font-mono tracking-wider">
            <ShieldCheck size={14} aria-hidden="true" className="text-[var(--accent)]" />
            API Security
          </div>
          <p className="mt-2 text-2xl font-bold text-[var(--text-primary)]">
            {rateLimit?.enabled ? 'Enabled' : 'Disabled'}
          </p>
        </GlassCard>
        <GlassCard variant="glow" delay={0.1}>
          <div className="flex items-center gap-2 text-muted text-xs uppercase font-mono tracking-wider">
            <KeyRound size={14} aria-hidden="true" className="text-[var(--accent)]" />
            Active Keys
          </div>
          <p className="mt-2 text-2xl font-bold text-[var(--text-primary)]">
            <AnimatedCounter value={activeKeys} />
          </p>
        </GlassCard>
        <GlassCard variant="glow" delay={0.15}>
          <div className="flex items-center gap-2 text-muted text-xs uppercase font-mono tracking-wider">
            <ShieldAlert size={14} aria-hidden="true" className="text-[var(--bad)]" />
            Recent Events
          </div>
          <p className="mt-2 text-2xl font-bold text-[var(--bad)]">
            <AnimatedCounter value={recentFailures} />
          </p>
        </GlassCard>
      </div>

      {/* Rate Limiting section */}
      <motion.section variants={itemVariants} className="card p-4">
        <div className="flex items-center justify-between gap-4 mb-4">
          <h2 className="text-lg font-semibold">Rate Limiting Status</h2>
          <Badge variant={rateLimit?.enabled ? 'low' : 'info'}>{rateLimit?.enabled ? 'Active' : 'Opt-in off'}</Badge>
        </div>

        {/* Recharts Mini Sparkline visualization */}
        {rateLimit?.buckets && rateLimit.buckets.length > 0 && (
          <div className="h-32 w-full mt-2 mb-6 p-2 rounded-lg bg-[var(--surface-2)] border border-[var(--border)]">
            <SafeResponsiveContainer width="100%" height="100%">
              <AreaChart data={rateLimit.buckets} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorRequests" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--accent)" stopOpacity={0.25}/>
                    <stop offset="95%" stopColor="var(--accent)" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="endpoint" stroke="var(--text-tertiary)" fontSize={10} tickLine={false} />
                <YAxis stroke="var(--text-tertiary)" fontSize={10} tickLine={false} />
                <ChartTooltip
                  contentStyle={{
                    backgroundColor: 'var(--surface)',
                    borderColor: 'var(--border)',
                    borderRadius: '8px',
                    color: 'var(--text-primary)',
                    fontSize: '11px',
                  }}
                />
                <Area type="monotone" dataKey="requests_per_second" stroke="var(--accent)" fillOpacity={1} fill="url(#colorRequests)" name="Requests/sec" />
              </AreaChart>
            </SafeResponsiveContainer>
          </div>
        )}

        <div className="overflow-x-auto">
          <table className="w-full text-sm font-mono">
            <thead>
              <tr className="border-b border-[var(--border)] text-muted">
                <th className="py-2 text-left">Endpoint</th>
                <th className="py-2 text-right">Requests/sec</th>
                <th className="py-2 text-right">Recent Count</th>
                <th className="py-2 text-right">Limit/sec</th>
              </tr>
            </thead>
            <tbody>
              {(rateLimit?.buckets ?? []).map(bucket => (
                <tr key={bucket.endpoint} className="border-b border-[var(--border)] hover:bg-white/5 transition-colors">
                  <td className="py-2 text-[var(--text-primary)]">{bucket.endpoint}</td>
                  <td className="py-2 text-right text-[var(--accent)]">{bucket.requests_per_second.toFixed(2)}</td>
                  <td className="py-2 text-right">{bucket.recent_count}</td>
                  <td className="py-2 text-right text-[var(--text-secondary)]">{bucket.limit_per_second ?? 'Adaptive'}</td>
                </tr>
              ))}
              {(rateLimit?.buckets ?? []).length === 0 && (
                <tr><td className="py-4 text-muted" colSpan={4}>No recent traffic</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </motion.section>

      {/* API Keys section */}
      <motion.section variants={itemVariants} className="card p-4">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
          <h2 className="text-lg font-semibold">Scoped API Keys</h2>
          <div className="flex items-center gap-2">
            <select
              className="bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-primary)] focus:border-[var(--accent)] focus:shadow-[0_0_0_2px_var(--accent-soft)] transition-all duration-200 cursor-pointer"
              value={newRole}
              onChange={event => setNewRole(event.target.value as ApiKeyRecord['role'])}
            >
              <option value="read_only">read_only</option>
              <option value="worker">worker</option>
              <option value="admin">admin</option>
            </select>
            <Button onClick={handleGenerate} size="sm" className="flex items-center gap-1.5">
              <Plus size={14} aria-hidden="true" />
              <span>Generate</span>
            </Button>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm font-mono">
            <thead>
              <tr className="border-b border-[var(--border)] text-muted">
                <th className="py-2 text-left">Key</th>
                <th className="py-2 text-left">Role</th>
                <th className="py-2 text-left">Created</th>
                <th className="py-2 text-left">Last Used</th>
                <th className="py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {apiKeys.map(key => (
                <tr key={key.id} className="border-b border-[var(--border)] hover:bg-white/5 transition-colors">
                  <td className="py-2 text-[var(--text-primary)]">{key.masked_key}</td>
                  <td className="py-2"><Badge variant={roleTone(key.role)}>{key.role}</Badge></td>
                  <td className="py-2 text-[var(--text-secondary)]">{formatDate(key.created_at)}</td>
                  <td className="py-2 text-[var(--text-secondary)]">{formatDate(key.last_used_at)}</td>
                  <td className="py-2 text-right">
                    <Button variant="ghost" size="sm" disabled={!key.active} onClick={() => handleRevoke(key.id)} aria-label={`Revoke ${key.masked_key}`}>
                      <Trash2 size={14} aria-hidden="true" className="text-[var(--bad)]" />
                    </Button>
                  </td>
                </tr>
              ))}
              {apiKeys.length === 0 && (
                <tr>
                  <td className="py-8 text-center" colSpan={5}>
                    <EmptyState title="No active API keys found" description="Select a role above and generate a new secure API key." />
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </motion.section>

      {/* Security Event Log section */}
      <motion.section variants={itemVariants} className="card p-4">
        <h2 className="text-lg font-semibold mb-4">Security Event Log</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm font-mono">
            <thead>
              <tr className="border-b border-[var(--border)] text-muted">
                <th className="py-2 text-left">Time</th>
                <th className="py-2 text-left">Type</th>
                <th className="py-2 text-left">Status</th>
                <th className="py-2 text-left">Route</th>
                <th className="py-2 text-left">Detail</th>
              </tr>
            </thead>
            <tbody>
              {events.map(event => (
                <tr key={event.id} className="border-b border-[var(--border)] hover:bg-white/5 transition-colors align-top">
                  <td className="py-2 whitespace-nowrap text-[var(--text-secondary)]">{formatDate(event.timestamp)}</td>
                  <td className="py-2 text-[var(--text-primary)]">{event.event_type}</td>
                  <td className="py-2">
                    <Badge variant={statusTone(event.status_code)}>{event.status_code ?? 'n/a'}</Badge>
                  </td>
                  <td className="py-2 text-[var(--accent)]">{event.method ?? ''} {event.path ?? ''}</td>
                  <td className="py-2 max-w-[32rem] truncate" title={event.detail}>{event.detail}</td>
                </tr>
              ))}
              {events.length === 0 && (
                <tr>
                  <td className="py-8 text-center" colSpan={5}>
                    <EmptyState title="No security events recorded" description="Security enforcement logs and access events will be cataloged here." />
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </motion.section>

      {/* CSP Reports section with Radix-like Accordion collapsible */}
      <motion.section variants={itemVariants} className="card p-4">
        <h2 className="text-lg font-semibold mb-4">CSP Reports</h2>
        <div className="space-y-3">
          {cspReports.map(report => {
            const isExpanded = expandedReportId === report.id;
            return (
              <article
                key={report.id}
                className="border border-[var(--border)] rounded-lg bg-[var(--surface-2)] overflow-hidden transition-all duration-200 hover:border-[var(--border-hover)]"
              >
                <button
                  type="button"
                  onClick={() => setExpandedReportId(isExpanded ? null : report.id)}
                  className="w-full flex items-center justify-between p-3 text-left text-xs font-mono hover:bg-white/5 transition-colors"
                >
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
                    <span className="text-[var(--text-secondary)]">{formatDate(report.timestamp)}</span>
                    <span className="text-[var(--accent)] font-semibold">{report.client_ip ?? 'unknown'}</span>
                    <span className="text-[var(--text-tertiary)] max-w-xs truncate">
                      {(((report.report as Record<string, Record<string, unknown>>)['csp-report']?.['blocked-uri'] as string) || 'Violation').replace(/^javascript:/i, '[blocked]')}
                    </span>
                  </div>
                  <ChevronDown
                    size={14}
                    className={`transform transition-transform duration-200 text-[var(--text-secondary)] ${
                      isExpanded ? 'rotate-180 text-[var(--accent)]' : ''
                    }`}
                  />
                </button>
                <AnimatePresence initial={false}>
                  {isExpanded && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.25, ease: EASE_OUT }}
                    >
                      <div className="p-3 border-t border-[var(--border)] bg-[var(--surface)]">
                        <pre className="overflow-x-auto text-[11px] font-mono leading-relaxed text-[var(--text-secondary)]">
                          {JSON.stringify(report.report, null, 2)}
                        </pre>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </article>
            );
          })}
          {cspReports.length === 0 && <p className="text-sm text-muted">No CSP violations reported</p>}
        </div>
      </motion.section>
    </motion.div>
  );
}
