import { useState, useEffect, useCallback } from 'react';
import { Loader2, ShieldCheck, RefreshCcw, Plus, X } from 'lucide-react';

interface RiskAcceptance {
  acceptance_id: string;
  finding_id: string;
  asset_id?: string | null;
  accepted_until?: string | null;
  accepted_by: string;
  justification: string;
  scope: string;
  state: string;
  created_at?: string;
}

export function AcceptancePage() {
  const [rows, setRows] = useState<RiskAcceptance[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({
    finding_id: '',
    accepted_by: 'analyst',
    justification: '',
    accepted_until: '',
    scope: 'global',
  });

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/risk-domain/acceptances?limit=200');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const payload = (await res.json()) as RiskAcceptance[];
      setRows(Array.isArray(payload) ? payload : []);
    } catch (err) {
      setError(`Failed to load: ${(err as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const createAcceptance = useCallback(async () => {
    if (!form.finding_id || !form.justification) return;
    setCreating(true);
    setError(null);
    try {
      const res = await fetch('/api/risk-domain/acceptances', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          finding_id: form.finding_id,
          accepted_by: form.accepted_by,
          justification: form.justification,
          accepted_until: form.accepted_until || null,
          scope: form.scope,
        }),
      });
      if (!res.ok) {
        const detail = await res.text();
        throw new Error(`${res.status}: ${detail}`);
      }
      setForm({ finding_id: '', accepted_by: 'analyst', justification: '', accepted_until: '', scope: 'global' });
      await load();
    } catch (err) {
      setError(`Create failed: ${(err as Error).message}`);
    } finally {
      setCreating(false);
    }
  }, [form, load]);

  const revoke = useCallback(
    async (acceptanceId: string) => {
      try {
        const res = await fetch(`/api/risk-domain/acceptances/${encodeURIComponent(acceptanceId)}/revoke`, {
          method: 'POST',
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        await load();
      } catch (err) {
        setError(`Revoke failed: ${(err as Error).message}`);
      }
    },
    [load],
  );

  return (
    <div className="flex flex-col h-full bg-bg font-sans" data-testid="acceptance-page">
      <div className="px-8 py-6 border-b border-white/5 flex items-center justify-between glass-panel sticky top-0 z-20">
        <div className="flex items-center gap-4">
          <div className="p-2 bg-accent/10 rounded-lg border border-accent/20">
            <ShieldCheck size={20} className="text-accent" />
          </div>
          <div>
            <h2 className="text-xl font-black text-text uppercase tracking-tighter">Risk Acceptance</h2>
            <div className="text-[10px] text-muted font-mono uppercase tracking-widest">
              {rows.length} acceptance{rows.length === 1 ? '' : 's'} on file
            </div>
          </div>
        </div>
        <button
          type="button"
          onClick={load}
          className="btn-secondary btn-small flex items-center gap-2"
          aria-label="Refresh"
        >
          <RefreshCcw size={12} /> Refresh
        </button>
      </div>

      <div className="px-8 py-4 grid grid-cols-1 md:grid-cols-5 gap-3 bg-black/30 border-b border-white/5">
        <input
          type="text"
          placeholder="Finding ID"
          value={form.finding_id}
          onChange={(e) => setForm((f) => ({ ...f, finding_id: e.target.value }))}
          className="bg-white/5 border border-white/10 rounded px-2 py-1.5 text-[11px] font-mono text-text focus:border-accent/50 outline-none"
        />
        <input
          type="text"
          placeholder="Accepted by"
          value={form.accepted_by}
          onChange={(e) => setForm((f) => ({ ...f, accepted_by: e.target.value }))}
          className="bg-white/5 border border-white/10 rounded px-2 py-1.5 text-[11px] font-mono text-text focus:border-accent/50 outline-none"
        />
        <input
          type="date"
          value={form.accepted_until}
          onChange={(e) => setForm((f) => ({ ...f, accepted_until: e.target.value }))}
          className="bg-white/5 border border-white/10 rounded px-2 py-1.5 text-[11px] font-mono text-text focus:border-accent/50 outline-none"
        />
        <input
          type="text"
          placeholder="Justification (required)"
          value={form.justification}
          onChange={(e) => setForm((f) => ({ ...f, justification: e.target.value }))}
          className="md:col-span-1 bg-white/5 border border-white/10 rounded px-2 py-1.5 text-[11px] font-mono text-text focus:border-accent/50 outline-none"
        />
        <button
          type="button"
          disabled={creating || !form.finding_id || !form.justification}
          onClick={createAcceptance}
          className="btn-primary btn-small flex items-center justify-center gap-2"
        >
          {creating ? <Loader2 size={12} className="animate-spin" /> : <Plus size={12} />} Add
        </button>
      </div>

      {error && (
        <div className="px-8 py-2 text-[11px] font-mono text-critical" role="alert">
          {error}
        </div>
      )}

      <div className="flex-1 overflow-auto p-8">
        {loading ? (
          <div className="flex items-center gap-2 text-muted text-xs font-mono">
            <Loader2 size={14} className="animate-spin" /> Loading…
          </div>
        ) : rows.length === 0 ? (
          <div className="text-muted text-xs font-mono">No acceptances on file yet.</div>
        ) : (
          <div className="grid gap-3">
            {rows.map((row) => (
              <div key={row.acceptance_id} className="glass-panel border border-white/5 rounded-lg p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className="text-[10px] uppercase tracking-widest font-mono text-muted">
                      {row.acceptance_id}
                    </span>
                    <span
                      className={`text-[9px] font-black uppercase tracking-widest px-2 py-0.5 rounded ${
                        row.state === 'active'
                          ? 'bg-accent/20 text-accent'
                          : 'bg-muted/20 text-muted'
                      }`}
                    >
                      {row.state}
                    </span>
                  </div>
                  {row.state === 'active' && (
                    <button
                      type="button"
                      onClick={() => revoke(row.acceptance_id)}
                      className="text-[10px] font-black uppercase tracking-widest text-muted hover:text-critical flex items-center gap-1"
                      aria-label={`Revoke ${row.acceptance_id}`}
                    >
                      <X size={12} /> Revoke
                    </button>
                  )}
                </div>
                <div className="text-[11px] font-mono text-text">
                  <span className="text-muted">finding:</span> {row.finding_id} ·{' '}
                  <span className="text-muted">by:</span> {row.accepted_by} ·{' '}
                  <span className="text-muted">scope:</span> {row.scope}
                  {row.accepted_until && (
                    <>
                      {' · '}
                      <span className="text-muted">until:</span> {row.accepted_until}
                    </>
                  )}
                </div>
                <div className="text-[11px] font-mono text-text whitespace-pre-wrap">
                  {row.justification}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default AcceptancePage;
