import { useState, useEffect, useCallback } from 'react';
import { Loader2, Database, Trash2, Plus } from 'lucide-react';
import { apiClient } from '@/api/core';

interface AssetRecord {
  asset_id: string;
  name: string;
  host_pattern: string;
  path_prefix?: string | null;
  asset_type: string;
  entity_type: string;
  criticality: number;
  tier: string;
  business_value: number;
  compliance_requirements?: string | null;
  owner?: string | null;
  is_active: number;
}

const TIER_OPTIONS = [
  'tier_0_crown_jewel',
  'tier_1_critical',
  'tier_2_business_important',
  'tier_3_internal',
  'tier_4_external_public',
] as const;

export function AssetCriticalityPage() {
  const [rows, setRows] = useState<AssetRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({
    name: '',
    host_pattern: '',
    asset_type: 'api',
    entity_type: 'api_gateway',
    criticality: 1.0,
    tier: 'tier_3_internal',
    business_value: 1.0,
    owner: '',
  });

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const { data } = await apiClient.get<AssetRecord[]>('/api/risk-domain/assets', { params: { limit: 200 } });
      setRows(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(`Failed to load: ${(err as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const save = useCallback(async () => {
    if (!form.name || !form.host_pattern) return;
    setSaving(true);
    setError(null);
    try {
      await apiClient.post('/api/risk-domain/assets', form);
      setForm({
        name: '',
        host_pattern: '',
        asset_type: 'api',
        entity_type: 'api_gateway',
        criticality: 1.0,
        tier: 'tier_3_internal',
        business_value: 1.0,
        owner: '',
      });
      await load();
    } catch (err) {
      setError(`Save failed: ${(err as Error).message}`);
    } finally {
      setSaving(false);
    }
  }, [form, load]);

  const remove = useCallback(
    async (assetId: string) => {
      try {
        await apiClient.delete(`/api/risk-domain/assets/${encodeURIComponent(assetId)}`);
        await load();
      } catch (err) {
        setError(`Delete failed: ${(err as Error).message}`);
      }
    },
    [load],
  );

  return (
    <div className="flex flex-col h-full bg-bg font-sans" data-testid="asset-criticality-page">
      <div className="px-8 py-6 border-b border-white/5 flex items-center justify-between glass-panel sticky top-0 z-20">
        <div className="flex items-center gap-4">
          <div className="p-2 bg-accent/10 rounded-lg border border-accent/20">
            <Database size={20} className="text-accent" />
          </div>
          <div>
            <h2 className="text-xl font-black text-text uppercase tracking-tighter">Asset Criticality</h2>
            <div className="text-[10px] text-muted font-mono uppercase tracking-widest">
              {rows.length} asset{rows.length === 1 ? '' : 's'} registered
            </div>
          </div>
        </div>
      </div>

      <div className="px-8 py-4 grid grid-cols-1 md:grid-cols-7 gap-3 bg-black/30 border-b border-white/5">
        <input
          type="text"
          placeholder="Name"
          value={form.name}
          onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
          className="bg-white/5 border border-white/10 rounded px-2 py-1.5 text-[11px] font-mono text-text focus:border-accent/50 outline-none"
        />
        <input
          type="text"
          placeholder="Host pattern (e.g. *.payments.example.com)"
          value={form.host_pattern}
          onChange={(e) => setForm((f) => ({ ...f, host_pattern: e.target.value }))}
          className="md:col-span-2 bg-white/5 border border-white/10 rounded px-2 py-1.5 text-[11px] font-mono text-text focus:border-accent/50 outline-none"
        />
        <input
          type="text"
          placeholder="Asset type"
          value={form.asset_type}
          onChange={(e) => setForm((f) => ({ ...f, asset_type: e.target.value }))}
          className="bg-white/5 border border-white/10 rounded px-2 py-1.5 text-[11px] font-mono text-text focus:border-accent/50 outline-none"
        />
        <select
          value={form.tier}
          onChange={(e) => setForm((f) => ({ ...f, tier: e.target.value }))}
          className="bg-white/5 border border-white/10 rounded px-2 py-1.5 text-[11px] font-mono text-text focus:border-accent/50 outline-none"
        >
          {TIER_OPTIONS.map((tier) => (
            <option key={tier} value={tier}>
              {tier}
            </option>
          ))}
        </select>
        <input
          type="number"
          step="0.05"
          min="0.5"
          max="2.0"
          placeholder="Criticality"
          value={form.criticality}
          onChange={(e) => setForm((f) => ({ ...f, criticality: Number(e.target.value) }))}
          className="bg-white/5 border border-white/10 rounded px-2 py-1.5 text-[11px] font-mono text-text focus:border-accent/50 outline-none"
        />
        <button
          type="button"
          disabled={saving || !form.name || !form.host_pattern}
          onClick={save}
          className="btn-primary btn-small flex items-center justify-center gap-2"
        >
          {saving ? <Loader2 size={12} className="animate-spin" /> : <Plus size={12} />} Save
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
          <div className="text-muted text-xs font-mono">
            No assets registered. Use the form above to add one.
          </div>
        ) : (
          <div className="grid gap-3">
            {rows.map((row) => (
              <div key={row.asset_id} className="glass-panel border border-white/5 rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-text font-bold">{row.name}</div>
                    <div className="text-[10px] font-mono text-muted">
                      {row.asset_id} · {row.host_pattern}
                      {row.path_prefix ? ` · ${row.path_prefix}` : ''}
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <span
                      className={`text-[9px] font-black uppercase tracking-widest px-2 py-0.5 rounded ${
                        row.tier === 'tier_0_crown_jewel'
                          ? 'bg-critical/20 text-critical'
                          : row.tier === 'tier_1_critical'
                          ? 'bg-warn/20 text-warn'
                          : 'bg-muted/20 text-muted'
                      }`}
                    >
                      {row.tier}
                    </span>
                    <span className="text-[10px] font-mono text-text">
                      crit {row.criticality.toFixed(2)}
                    </span>
                    <button
                      type="button"
                      onClick={() => remove(row.asset_id)}
                      className="text-muted hover:text-critical"
                      aria-label={`Delete ${row.asset_id}`}
                    >
                      <Trash2 size={12} />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default AssetCriticalityPage;
