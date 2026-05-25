import { useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import {
  ShieldCheck,
  FileText,
  Download,
  ChevronDown,
  ChevronUp,
  ExternalLink,
} from 'lucide-react';
import { useTargets } from '@/hooks';
import { getComplianceReport, getAttestationUrl, type ComplianceReport } from '@/api/compliance';

export function ComplianceDashboard() {
  const { data: targetsData } = useTargets();
  const [selectedTarget, setSelectedTarget] = useState<string>('');
  const [report, setComplianceReport] = useState<ComplianceReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedControls, setExpandedControls] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (targetsData?.targets && targetsData.targets.length > 0 && !selectedTarget) {
      setSelectedTarget(targetsData.targets[0].name);
    }
  }, [targetsData, selectedTarget]);

  useEffect(() => {
    if (!selectedTarget) return;

    const fetchReport = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await getComplianceReport(selectedTarget);
        setComplianceReport(data);
      } catch (err: unknown) {
        if (err instanceof Error) {
          setError(err.message || 'Failed to load compliance report');
        } else {
          setError('An unexpected error occurred');
        }
        setComplianceReport(null);
      } finally {
        setLoading(false);
      }
    };

    fetchReport();
  }, [selectedTarget]);

  const toggleControl = (id: string) => {
    setExpandedControls(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const getMaturityColor = (maturity: string) => {
    switch (maturity) {
      case 'PASS': return 'text-[var(--ok)] border-[var(--ok)]/30 bg-[var(--ok)]/5';
      case 'PARTIAL': return 'text-[var(--warn)] border-[var(--warn)]/30 bg-[var(--warn)]/5';
      case 'AT_RISK': return 'text-orange-400 border-orange-500/30 bg-orange-500/5';
      case 'FAIL': return 'text-[var(--bad)] border-[var(--bad)]/30 bg-[var(--bad)]/5';
      default: return 'text-muted border-border bg-surface-1';
    }
  };

  const frameworkStats = useMemo(() => {
    if (!report) return [];
    return Object.entries(report.framework_coverage).map(([name, controls]) => {
      const total = Object.keys(controls).length;
      const passed = Object.values(controls).filter(c => c.maturity === 'PASS').length;
      const failed = Object.values(controls).filter(c => c.maturity === 'FAIL').length;
      const atRisk = Object.values(controls).filter(c => c.maturity === 'AT_RISK').length;
      return { name, total, passed, failed, atRisk, score: Math.round((passed / total) * 100) };
    });
  }, [report]);

  return (
    <motion.div 
      className="compliance-dashboard space-y-6"
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
    >
      <section className="page-header flex justify-between items-center">
        <div>
          <h2 className="flex items-center gap-2">
            <ShieldCheck className="text-[var(--accent)]" />
            Compliance & Regulatory Reporting
          </h2>
          <p className="page-subtitle">Automated GRC mapping against SOC 2, PCI DSS, and NIST frameworks.</p>
        </div>
        <div className="flex gap-3">
          <select 
            className="form-select text-sm min-w-[200px]"
            value={selectedTarget}
            onChange={(e) => setSelectedTarget(e.target.value)}
          >
            {targetsData?.targets.map(t => (
              <option key={t.name} value={t.name}>{t.name}</option>
            ))}
          </select>
          {selectedTarget && (
            <a 
              href={getAttestationUrl(selectedTarget)} 
              target="_blank" 
              rel="noreferrer"
              className="btn btn-primary"
            >
              <Download size={14} />
              Export Attestation
            </a>
          )}
        </div>
      </section>

      {loading && <div className="card p-12 text-center text-muted">Analyzing regulatory artifacts...</div>}
      {error && <div className="card p-4 border-[var(--bad)]/30 bg-[var(--bad)]/5 text-[var(--bad)]">{error}</div>}

      {report && !loading && (
        <>
          {/* Framework Overview Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {frameworkStats.map(stat => (
              <div key={stat.name} className="card p-4 space-y-3">
                <div className="flex justify-between items-start">
                  <h3 className="text-xs font-bold uppercase tracking-tight text-muted">{stat.name}</h3>
                  <span className={`text-lg font-mono font-bold ${stat.score > 80 ? 'text-[var(--ok)]' : stat.score > 50 ? 'text-[var(--warn)]' : 'text-[var(--bad)]'}`}>
                    {stat.score}%
                  </span>
                </div>
                <div className="h-1.5 w-full bg-surface-2 rounded-full overflow-hidden">
                  <div 
                    className={`h-full transition-all duration-500 ${stat.score > 80 ? 'bg-[var(--ok)]' : stat.score > 50 ? 'bg-[var(--warn)]' : 'bg-[var(--bad)]'}`}
                    style={{ width: `${stat.score}%` }}
                  />
                </div>
                <div className="flex justify-between text-[10px] font-mono">
                  <span className="text-[var(--ok)]">{stat.passed} PASS</span>
                  <span className="text-[var(--bad)]">{stat.failed} FAIL</span>
                  <span className="text-muted">{stat.total} TOTAL</span>
                </div>
              </div>
            ))}
          </div>

          {/* Framework Detail Sections */}
          <div className="space-y-8">
            {Object.entries(report.framework_coverage).map(([framework, controls]) => (
              <div key={framework} className="space-y-4">
                <h3 className="text-sm font-bold flex items-center gap-2 px-1">
                  <FileText size={16} className="text-accent" />
                  {framework} Controls
                </h3>
                <div className="grid gap-2">
                  {Object.entries(controls).map(([cid, data]) => (
                    <div 
                      key={cid} 
                      className={`card overflow-hidden transition-all border ${data.maturity !== 'PASS' ? 'border-l-4' : ''} ${
                        data.maturity === 'FAIL' ? 'border-l-[var(--bad)]' : 
                        data.maturity === 'AT_RISK' ? 'border-l-orange-500' : 
                        data.maturity === 'PARTIAL' ? 'border-l-[var(--warn)]' : 'border-border'
                      }`}
                    >
                      <div 
                        className="p-4 flex items-center justify-between cursor-pointer hover:bg-white/5"
                        onClick={() => toggleControl(cid)}
                        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') toggleControl(cid); }}
                        role="button"
                        tabIndex={0}
                        aria-expanded={expandedControls.has(cid)}
                      >
                        <div className="flex items-center gap-4">
                          <span className="text-xs font-mono font-bold text-accent w-20">{cid}</span>
                          <span className={`status-pill text-[10px] border px-2 py-0.5 rounded font-bold ${getMaturityColor(data.maturity)}`}>
                            {data.maturity}
                          </span>
                        </div>
                        {expandedControls.has(cid) ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                      </div>

                      {expandedControls.has(cid) && (
                        <div className="p-4 pt-0 border-t border-border/50 bg-black/20 space-y-4">
                          <div className="mt-4">
                            <h4 className="text-[10px] uppercase text-muted font-bold mb-1">Recommendation</h4>
                            <p className="text-xs italic text-text/80">{data.recommendation}</p>
                          </div>
                          
                          {data.findings.length > 0 && (
                            <div>
                              <h4 className="text-[10px] uppercase text-muted font-bold mb-2">Evidence ({data.findings.length})</h4>
                              <div className="space-y-2">
                                {data.findings.map(f => (
                                  <div key={f.id} className="text-xs flex items-center justify-between bg-surface-1 p-2 rounded border border-border/30">
                                    <div className="flex items-center gap-2">
                                      <span className={`w-2 h-2 rounded-full ${
                                        f.severity === 'critical' ? 'bg-[var(--bad)]' : 
                                        f.severity === 'high' ? 'bg-orange-500' : 'bg-[var(--warn)]'
                                      }`} />
                                      <span className="font-bold">{f.title}</span>
                                      <span className="text-muted truncate max-w-[300px]">{f.url}</span>
                                    </div>
                                    <a href={`/findings?finding=${encodeURIComponent(f.id)}`} className="text-accent hover:underline flex items-center gap-1">
                                      View <ExternalLink size={10} />
                                    </a>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {report && report.total_findings === 0 && !loading && (
        <div className="card p-12 text-center space-y-4">
          <ShieldCheck size={48} className="mx-auto text-[var(--ok)] opacity-50" />
          <div>
            <h3 className="text-lg font-bold">Compliant Posture</h3>
            <p className="text-sm text-muted">No security findings were detected for this target across the evaluated frameworks.</p>
          </div>
        </div>
      )}
    </motion.div>
  );
}
