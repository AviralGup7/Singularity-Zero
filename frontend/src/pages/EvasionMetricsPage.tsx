import { useEffect, useState } from 'react';
import { RefreshCw, ShieldAlert, Trash2 } from 'lucide-react';
import { getEvasionMetrics, resetEvasionMetrics, type EvasionMetricsResponse } from '@/api/evasion';
import { useToast } from '@/hooks/useToast';

export function EvasionMetricsPage() {
  const [data, setData] = useState<EvasionMetricsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [resetting, setResetting] = useState(false);
  const toast = useToast();

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const response = await getEvasionMetrics();
      setData(response);
    } catch {
      toast.error('Failed to load evasion metrics');
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleReset = async () => {
    if (!window.confirm('Are you sure you want to reset all evasion metrics?')) return;
    setResetting(true);
    try {
      await resetEvasionMetrics();
      toast.success('Metrics reset successfully');
      await loadData();
    } catch {
      toast.error('Failed to reset metrics');
    } finally {
      setResetting(false);
    }
  };

  const metricsArray = data ? Object.entries(data.metrics) : [];

  return (
    <div className="p-6 md:p-8 bg-bg min-h-full">
      <header className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div className="flex items-center gap-3">
          <div className="h-11 w-11 rounded-lg border border-accent/30 bg-accent/10 grid place-items-center text-accent">
            <ShieldAlert size={23} />
          </div>
          <div>
            <h1 className="text-xl font-bold text-text uppercase tracking-widest">Evasion Telemetry</h1>
            <p className="text-xs text-muted">Chameleon WAF evasion benchmarks and success rates</p>
          </div>
        </div>
        <div className="flex gap-2">
          <button className="btn btn-secondary flex items-center gap-2" onClick={loadData} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
          <button className="btn btn-secondary flex items-center gap-2 text-bad border-bad/50 hover:bg-bad/10" onClick={handleReset} disabled={resetting || loading}>
            <Trash2 size={14} /> Reset
          </button>
        </div>
      </header>

      {loading && !data ? (
        <div className="p-8 text-center animate-pulse text-muted">Loading Evasion Metrics...</div>
      ) : metricsArray.length === 0 ? (
        <div className="p-8 text-center text-muted italic bg-white/5 rounded-xl border border-white/5">
          No evasion metrics recorded yet. Run a pipeline with evasion enabled.
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {metricsArray.map(([target, metrics]) => (
            <div key={target} className="glass-panel p-6 rounded-2xl">
              <h3 className="text-sm font-bold uppercase tracking-widest text-text mb-4 truncate" title={target}>
                {target}
              </h3>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-[9px] font-black text-muted uppercase tracking-widest mb-1">Total Requests</div>
                  <div className="text-lg font-black text-white">{metrics.total_requests}</div>
                </div>
                <div>
                  <div className="text-[9px] font-black text-muted uppercase tracking-widest mb-1">Successes</div>
                  <div className="text-lg font-black text-ok">{metrics.successes}</div>
                </div>
                <div className="col-span-2">
                  <div className="text-[9px] font-black text-muted uppercase tracking-widest mb-1">Evasion Success Rate</div>
                  <div className="flex items-center gap-3">
                    <div className="text-2xl font-black text-accent">{metrics.evasion_success_rate.toFixed(1)}%</div>
                    <div className="flex-1 h-2 bg-black/40 rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-accent" 
                        style={{ width: `${Math.min(100, Math.max(0, metrics.evasion_success_rate))}%` }}
                      />
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
