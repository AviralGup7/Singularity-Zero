import { useEffect, useState } from 'react';
import { RefreshCw, Zap, AlertTriangle, Play, Settings } from 'lucide-react';
import { getSelfHealingSnapshot, evaluateSelfHealing, type SelfHealingSnapshot } from '@/api/selfHealing';
import { useToast } from '@/hooks/useToast';

export function SelfHealingPage() {
  const [snapshot, setSnapshot] = useState<SelfHealingSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [evaluating, setEvaluating] = useState(false);
  const toast = useToast();

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getSelfHealingSnapshot();
      setSnapshot(data);
    } catch {
      toast.error('Failed to load self-healing snapshot');
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleEvaluate = async () => {
    setEvaluating(true);
    try {
      const data = await evaluateSelfHealing();
      setSnapshot(data);
      toast.success('Self-healing evaluation triggered');
    } catch {
      toast.error('Failed to trigger evaluation');
    } finally {
      setEvaluating(false);
    }
  };

  if (loading && !snapshot) {
    return <div className="p-8 text-center animate-pulse text-muted">Loading Self-Healing Telemetry...</div>;
  }

  return (
    <div className="p-6 md:p-8 bg-bg min-h-full">
      <header className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div className="flex items-center gap-3">
          <div className="h-11 w-11 rounded-lg border border-accent/30 bg-accent/10 grid place-items-center text-accent">
            <Zap size={23} />
          </div>
          <div>
            <h1 className="text-xl font-bold text-text uppercase tracking-widest">Self-Healing Command</h1>
            <p className="text-xs text-muted">Autonomous recovery controller telemetry and evaluation</p>
          </div>
        </div>
        <div className="flex gap-2">
          <button className="btn btn-secondary flex items-center gap-2" onClick={loadData} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
          <button className="btn btn-primary flex items-center gap-2" onClick={handleEvaluate} disabled={evaluating}>
            <Play size={14} className={evaluating ? 'animate-pulse' : ''} /> Evaluate Now
          </button>
        </div>
      </header>

      {snapshot && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
            <div className="glass-panel p-4 rounded-xl">
              <div className="text-[9px] font-black text-muted uppercase mb-1 tracking-widest">Controller State</div>
              <div className="text-lg font-black text-white uppercase">{snapshot.controller || 'Unknown'}</div>
            </div>
            <div className="glass-panel p-4 rounded-xl">
              <div className="text-[9px] font-black text-muted uppercase mb-1 tracking-widest">System Status</div>
              <div className={`text-lg font-black uppercase ${snapshot.status === 'healthy' ? 'text-ok' : snapshot.status === 'degraded' ? 'text-warning' : 'text-bad'}`}>
                {snapshot.status}
              </div>
            </div>
            <div className="glass-panel p-4 rounded-xl">
              <div className="text-[9px] font-black text-muted uppercase mb-1 tracking-widest">Active Findings</div>
              <div className="text-lg font-black text-accent">{snapshot.findings?.length || 0}</div>
            </div>
            <div className="glass-panel p-4 rounded-xl">
              <div className="text-[9px] font-black text-muted uppercase mb-1 tracking-widest">Total Corrections</div>
              <div className="text-lg font-black text-white">{snapshot.corrections?.length || 0}</div>
            </div>
          </div>

          <div className="grid md:grid-cols-2 gap-6">
            <section className="glass-panel p-6 rounded-2xl">
              <h3 className="text-sm font-bold uppercase tracking-widest mb-4 flex items-center gap-2">
                <AlertTriangle size={16} className="text-warning" /> Active Health Findings
              </h3>
              {snapshot.findings && snapshot.findings.length > 0 ? (
                <div className="space-y-3">
                  {snapshot.findings.map((f: Record<string, unknown>, i: number) => (
                    <div key={i} className="bg-black/30 p-4 rounded-xl border border-white/5">
                      <div className="flex justify-between items-center mb-2">
                        <span className="text-[10px] font-black uppercase tracking-widest text-accent">{String(f.component)}</span>
                        <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded ${f.status === 'critical' ? 'bg-bad text-white' : 'bg-warning/20 text-warning'}`}>
                          {String(f.status)}
                        </span>
                      </div>
                      <p className="text-xs text-text/80">{String(f.reason)}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-muted italic">No active health findings.</p>
              )}
            </section>

            <section className="glass-panel p-6 rounded-2xl">
              <h3 className="text-sm font-bold uppercase tracking-widest mb-4 flex items-center gap-2">
                <Settings size={16} className="text-accent" /> Recent Corrections
              </h3>
              {snapshot.corrections && snapshot.corrections.length > 0 ? (
                <div className="space-y-3 max-h-[400px] overflow-y-auto scrollbar-cyber pr-2">
                  {snapshot.corrections.map((c: Record<string, unknown>, i: number) => (
                    <div key={i} className="bg-black/30 p-4 rounded-xl border border-white/5">
                      <div className="flex justify-between items-center mb-2">
                        <span className="text-[10px] font-black uppercase tracking-widest text-white">{String(c.action)}</span>
                        <span className={`text-[10px] uppercase font-bold ${c.success ? 'text-ok' : 'text-bad'}`}>
                          {c.success ? 'SUCCESS' : 'FAILED'}
                        </span>
                      </div>
                      <p className="text-xs text-text/80 mb-2">{String(c.message)}</p>
                      <div className="text-[9px] font-mono text-muted">{new Date(Number(c.executed_at) * 1000).toLocaleString()}</div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-muted italic">No corrections executed recently.</p>
              )}
            </section>
          </div>
        </>
      )}
    </div>
  );
}
