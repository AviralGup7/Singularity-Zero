import { useCallback, useEffect, useMemo, useState } from 'react';
import { KeyRound, Plus, RefreshCw, ShieldAlert, ShieldCheck, Trash2 } from 'lucide-react';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
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

export function SecurityPage() {
  const [rateLimit, setRateLimit] = useState<RateLimitStatus | null>(null);
  const [apiKeys, setApiKeys] = useState<ApiKeyRecord[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [cspReports, setCspReports] = useState<CspReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [newRole, setNewRole] = useState<ApiKeyRecord['role']>('read_only');
  const [generatedKey, setGeneratedKey] = useState<string | null>(null);

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

  if (loading) {
    return <div className="p-8 text-muted">Loading security monitor...</div>;
  }

  return (
    <div className="security-page p-6 space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold">Security Monitor</h1>
          <p className="text-sm text-muted">API limits, scoped keys, and enforcement events</p>
        </div>
        <Button variant="secondary" onClick={() => refresh()} size="sm">
          <RefreshCw size={14} aria-hidden="true" />
          Refresh
        </Button>
      </div>

      {message && (
        <div className="banner info" role="status">
          {message}
          <button type="button" className="ml-4 text-xs opacity-70 hover:opacity-100" onClick={() => setMessage(null)}>
            Dismiss
          </button>
        </div>
      )}

      {generatedKey && (
        <section className="card p-4 border border-[var(--ok)]/40">
          <div className="flex items-center gap-2 text-[var(--ok)] font-bold">
            <KeyRound size={16} aria-hidden="true" />
            New API key
          </div>
          <code className="mt-3 block overflow-x-auto border border-[var(--line)] bg-[var(--bg)] p-3 text-xs">
            {generatedKey}
          </code>
        </section>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <section className="card p-4">
          <div className="flex items-center gap-2 text-muted text-xs uppercase font-mono">
            <ShieldCheck size={14} aria-hidden="true" />
            API Security
          </div>
          <p className="mt-2 text-2xl font-bold">{rateLimit?.enabled ? 'Enabled' : 'Disabled'}</p>
        </section>
        <section className="card p-4">
          <div className="flex items-center gap-2 text-muted text-xs uppercase font-mono">
            <KeyRound size={14} aria-hidden="true" />
            Active Keys
          </div>
          <p className="mt-2 text-2xl font-bold">{activeKeys}</p>
        </section>
        <section className="card p-4">
          <div className="flex items-center gap-2 text-muted text-xs uppercase font-mono">
            <ShieldAlert size={14} aria-hidden="true" />
            Recent Events
          </div>
          <p className="mt-2 text-2xl font-bold">{recentFailures}</p>
        </section>
      </div>

      <section className="card p-4">
        <div className="flex items-center justify-between gap-4 mb-4">
          <h2 className="text-lg font-semibold">Rate Limiting</h2>
          <Badge variant={rateLimit?.enabled ? 'low' : 'info'}>{rateLimit?.enabled ? 'Active' : 'Opt-in off'}</Badge>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm font-mono">
            <thead>
              <tr className="border-b border-[var(--line)] text-muted">
                <th className="py-2 text-left">Endpoint</th>
                <th className="py-2 text-right">Requests/sec</th>
                <th className="py-2 text-right">Recent Count</th>
                <th className="py-2 text-right">Limit/sec</th>
              </tr>
            </thead>
            <tbody>
              {(rateLimit?.buckets ?? []).map(bucket => (
                <tr key={bucket.endpoint} className="border-b border-[var(--line)]">
                  <td className="py-2">{bucket.endpoint}</td>
                  <td className="py-2 text-right">{bucket.requests_per_second.toFixed(2)}</td>
                  <td className="py-2 text-right">{bucket.recent_count}</td>
                  <td className="py-2 text-right">{bucket.limit_per_second ?? 'Adaptive'}</td>
                </tr>
              ))}
              {(rateLimit?.buckets ?? []).length === 0 && (
                <tr><td className="py-4 text-muted" colSpan={4}>No recent traffic</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="card p-4">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
          <h2 className="text-lg font-semibold">API Keys</h2>
          <div className="flex items-center gap-2">
            <select className="form-input" value={newRole} onChange={event => setNewRole(event.target.value as ApiKeyRecord['role'])}>
              <option value="read_only">read_only</option>
              <option value="worker">worker</option>
              <option value="admin">admin</option>
            </select>
            <Button onClick={handleGenerate} size="sm">
              <Plus size={14} aria-hidden="true" />
              Generate
            </Button>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm font-mono">
            <thead>
              <tr className="border-b border-[var(--line)] text-muted">
                <th className="py-2 text-left">Key</th>
                <th className="py-2 text-left">Role</th>
                <th className="py-2 text-left">Created</th>
                <th className="py-2 text-left">Last Used</th>
                <th className="py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {apiKeys.map(key => (
                <tr key={key.id} className="border-b border-[var(--line)]">
                  <td className="py-2">{key.masked_key}</td>
                  <td className="py-2"><Badge variant={roleTone(key.role)}>{key.role}</Badge></td>
                  <td className="py-2">{formatDate(key.created_at)}</td>
                  <td className="py-2">{formatDate(key.last_used_at)}</td>
                  <td className="py-2 text-right">
                    <Button variant="ghost" size="sm" disabled={!key.active} onClick={() => handleRevoke(key.id)} aria-label={`Revoke ${key.masked_key}`}>
                      <Trash2 size={14} aria-hidden="true" />
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="card p-4">
        <h2 className="text-lg font-semibold mb-4">Security Event Log</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm font-mono">
            <thead>
              <tr className="border-b border-[var(--line)] text-muted">
                <th className="py-2 text-left">Time</th>
                <th className="py-2 text-left">Type</th>
                <th className="py-2 text-left">Status</th>
                <th className="py-2 text-left">Route</th>
                <th className="py-2 text-left">Detail</th>
              </tr>
            </thead>
            <tbody>
              {events.map(event => (
                <tr key={event.id} className="border-b border-[var(--line)] align-top">
                  <td className="py-2 whitespace-nowrap">{formatDate(event.timestamp)}</td>
                  <td className="py-2">{event.event_type}</td>
                  <td className="py-2">
                    <Badge variant={statusTone(event.status_code)}>{event.status_code ?? 'n/a'}</Badge>
                  </td>
                  <td className="py-2">{event.method ?? ''} {event.path ?? ''}</td>
                  <td className="py-2 max-w-[32rem] truncate" title={event.detail}>{event.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="card p-4">
        <h2 className="text-lg font-semibold mb-4">CSP Reports</h2>
        <div className="space-y-3">
          {cspReports.map(report => (
            <article key={report.id} className="border border-[var(--line)] p-3">
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted">
                <span>{formatDate(report.timestamp)}</span>
                <span>{report.client_ip ?? 'unknown'}</span>
              </div>
              <pre className="mt-2 overflow-x-auto text-xs">{JSON.stringify(report.report, null, 2)}</pre>
            </article>
          ))}
          {cspReports.length === 0 && <p className="text-sm text-muted">No CSP violations reported</p>}
        </div>
      </section>
    </div>
  );
}
