import { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { getFindingsSummary } from '../api/client';
import type { FindingsSummary } from '@/types/api';
import { Shield, Target, Activity, Zap } from 'lucide-react';

export default function FindingsOverview() {
  const navigate = useNavigate();
  const [summary, setSummary] = useState<FindingsSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    async function fetchSummary() {
      try {
        const data = await getFindingsSummary(controller.signal);
        setSummary(data);
        setError(null);
      } catch (_err) {
        if (!controller.signal.aborted) setError('Telemetry sync failed');
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }
    fetchSummary();
    return () => controller.abort();
  }, []);

  const metrics = useMemo(() => {
    if (!summary) return null;
    const totals = summary.severity_totals || {};
    const critical = totals.critical || 0;
    const high = totals.high || 0;
    const medium = totals.medium || 0;
    
    // Advanced risk algorithm (Weighted)
    const riskScore = Math.min(100, (critical * 25) + (high * 10) + (medium * 4));
    const securityScore = 100 - riskScore;
    
    return {
      total: summary.total_findings ?? 0,
      coverage: `${summary.targets_with_findings ?? 0}/${summary.total_targets ?? 0}`,
      securityScore: Math.round(securityScore),
      posture: securityScore > 80 ? 'Fortified' : securityScore > 50 ? 'Compromised' : 'Critical',
      color: securityScore > 80 ? 'text-ok' : securityScore > 50 ? 'text-warn' : 'text-bad',
      glow: securityScore > 80 ? 'cyber-glow-green' : 'cyber-glow-red'
    };
  }, [summary]);

  const handleSeverityClick = (sev: string) => {
    navigate(`/findings?severity=${sev}`);
  };

  if (loading) return <div className="h-48 flex items-center justify-center text-xs uppercase tracking-widest text-muted animate-pulse">Initializing Data Stream...</div>;
  if (error) return <div className="p-4 bg-bad/10 border border-bad/20 rounded-lg text-bad text-xs font-mono">{error}</div>;
  if (!summary || !metrics) return null;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Total Findings */}
        <div 
          className="glass-panel p-6 rounded-2xl relative overflow-hidden group cursor-pointer hover:border-accent/30 transition-all"
          onClick={() => navigate('/findings')}
        >
          <Shield className="absolute -right-4 -bottom-4 w-24 h-24 text-white/5 group-hover:text-white/10 transition-all" />
          <div className="flex items-center gap-2 text-muted text-[10px] font-black uppercase tracking-widest mb-1">
            <Zap size={12} className="text-accent" /> Findings
          </div>
          <div className="text-3xl font-black text-white">{metrics.total}</div>
          <div className="text-[10px] text-muted mt-1 uppercase tracking-tighter">Verified intelligence points</div>
        </div>

        {/* Coverage */}
        <div 
          className="glass-panel p-6 rounded-2xl relative overflow-hidden group cursor-pointer hover:border-accent/30 transition-all"
          onClick={() => navigate('/targets')}
        >
          <Target className="absolute -right-4 -bottom-4 w-24 h-24 text-white/5 group-hover:text-white/10 transition-all" />
          <div className="flex items-center gap-2 text-muted text-[10px] font-black uppercase tracking-widest mb-1">
            <Activity size={12} className="text-accent" /> Scan Coverage
          </div>
          <div className="text-3xl font-black text-white">{metrics.coverage}</div>
          <div className="text-[10px] text-muted mt-1 uppercase tracking-tighter">Targets with active findings</div>
        </div>

        {/* Security Score */}
        <div 
          className={`glass-panel p-6 rounded-2xl border-l-4 border-l-accent ${metrics.glow} transition-all cursor-pointer hover:scale-[1.02]`}
          onClick={() => navigate('/risk-score')}
        >
          <div className="flex items-center gap-2 text-muted text-[10px] font-black uppercase tracking-widest mb-1">
            <Shield size={12} className="text-accent" /> Security Score
          </div>
          <div className={`text-4xl font-black ${metrics.color}`}>{metrics.securityScore}</div>
          <div className="text-[10px] text-muted mt-1 uppercase tracking-tighter">Weighted resilience index</div>
        </div>

        {/* Posture */}
        <div className="glass-panel p-6 rounded-2xl cursor-default">
          <div className="flex items-center gap-2 text-muted text-[10px] font-black uppercase tracking-widest mb-1">
             Posture Status
          </div>
          <div className={`text-2xl font-black uppercase tracking-tighter ${metrics.color}`}>{metrics.posture}</div>
          <div className="mt-3 h-1.5 w-full bg-white/5 rounded-full overflow-hidden">
            <div className={`h-full transition-all duration-1000 ${metrics.securityScore > 80 ? 'bg-ok' : metrics.securityScore > 50 ? 'bg-warn' : 'bg-bad'}`} 
                 style={{ width: `${metrics.securityScore}%` }} />
          </div>
        </div>
      </div>

      {/* Severity Breakdown */}
      <div className="glass-panel p-8 rounded-2xl border border-white/5">
        <h4 className="text-[10px] font-black text-muted uppercase tracking-[0.3em] mb-8">Severity Distribution Matrix</h4>
        <div className="flex items-end h-32 gap-4">
          {['critical', 'high', 'medium', 'low', 'info'].map(sev => {
            const count = (summary.severity_totals?.[sev]) || 0;
            const maxCount = Math.max(...Object.values(summary.severity_totals || {}), 1);
            const height = (count / maxCount) * 100;
            const colors = {
              critical: 'bg-critical shadow-[0_0_15px_rgba(255,0,85,0.3)]',
              high: 'bg-high shadow-[0_0_15px_rgba(239,68,68,0.2)]',
              medium: 'bg-medium shadow-[0_0_15px_rgba(245,158,11,0.2)]',
              low: 'bg-low shadow-[0_0_15px_rgba(59,130,246,0.2)]',
              info: 'bg-info shadow-[0_0_15px_rgba(6,182,212,0.2)]'
            };
            return (
              <div 
                key={sev} 
                className="flex-1 flex flex-col items-center gap-3 group cursor-pointer"
                onClick={() => handleSeverityClick(sev)}
              >
                <div className="relative w-full flex flex-col justify-end h-full">
                  <div className={`w-full rounded-t-lg transition-all duration-700 group-hover:scale-x-110 ${colors[sev as keyof typeof colors]}`} 
                       style={{ height: `${Math.max(5, height)}%` }}>
                    <div className="opacity-0 group-hover:opacity-100 absolute -top-6 left-1/2 -translate-x-1/2 text-[10px] font-bold text-white transition-opacity">
                      {count}
                    </div>
                  </div>
                </div>
                <span className="text-[9px] font-black text-muted uppercase tracking-widest group-hover:text-white transition-colors">{sev}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
