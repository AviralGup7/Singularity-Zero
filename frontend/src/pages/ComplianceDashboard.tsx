import { useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip as ChartTooltip } from 'recharts';
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
import { PageHeader, GlassCard, AnimatedCounter, GlowProgress } from '@/components/ui';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;

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

  const donutData = useMemo(() => {
    if (!report) return [];
    let pass = 0;
    let fail = 0;
    let partial = 0;
    let atRisk = 0;

    Object.values(report.framework_coverage).forEach(controls => {
      Object.values(controls).forEach(c => {
        if (c.maturity === 'PASS') pass++;
        else if (c.maturity === 'FAIL') fail++;
        else if (c.maturity === 'PARTIAL') partial++;
        else if (c.maturity === 'AT_RISK') atRisk++;
      });
    });

    return [
      { name: 'Pass', value: pass, color: 'var(--ok)' },
      { name: 'Partial', value: partial, color: 'var(--warn)' },
      { name: 'At Risk', value: atRisk, color: '#f97316' },
      { name: 'Fail', value: fail, color: 'var(--bad)' },
    ].filter(item => item.value > 0);
  }, [report]);

  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.08 }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 15 },
    show: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 100, damping: 15 } }
  };

  return (
    <motion.div 
      className="compliance-dashboard space-y-6"
      variants={containerVariants}
      initial="hidden"
      animate="show"
    >
      <PageHeader
        icon={<ShieldCheck size={20} />}
        title="Compliance & Regulatory Reporting"
        subtitle="Automated GRC mapping against SOC 2, PCI DSS, and NIST frameworks."
        actions={
          <div className="flex items-center gap-3">
            <select 
              className="bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] focus:border-[var(--accent)] focus:shadow-[0_0_0_2px_var(--accent-soft)] transition-all duration-200 cursor-pointer min-w-[200px]"
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
                className="btn btn-primary flex items-center gap-1.5"
              >
                <Download size={14} />
                <span>Export Attestation</span>
              </a>
            )}
          </div>
        }
      />

      {loading && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <GlassCard key={i} className="animate-pulse p-4 space-y-3">
              <div className="h-3 w-1/3 bg-[var(--surface-3)] rounded" />
              <div className="h-6 w-1/4 bg-[var(--surface-3)] rounded" />
              <div className="h-1.5 w-full bg-[var(--surface-3)] rounded" />
              <div className="h-3 w-2/3 bg-[var(--surface-3)] rounded" />
            </GlassCard>
          ))}
        </div>
      )}

      {error && <div className="card p-4 border-[var(--bad)]/30 bg-[var(--bad)]/5 text-[var(--bad)]">{error}</div>}

      {report && !loading && (
        <>
          {/* Framework Overview Cards with Pie/Donut Chart */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 grid grid-cols-1 md:grid-cols-2 gap-4">
              {frameworkStats.map((stat, i) => (
                <GlassCard key={stat.name} variant="glow" delay={i * 0.05} className="space-y-3 flex flex-col justify-between">
                  <div className="space-y-2">
                    <div className="flex justify-between items-start">
                      <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">{stat.name}</h3>
                      <span className={`text-lg font-mono font-bold ${stat.score > 80 ? 'text-[var(--ok)]' : stat.score > 50 ? 'text-[var(--warn)]' : 'text-[var(--bad)]'}`}>
                        <AnimatedCounter value={stat.score} suffix="%" />
                      </span>
                    </div>
                    <GlowProgress
                      value={stat.score}
                      variant={stat.score > 80 ? 'success' : stat.score > 50 ? 'warning' : 'danger'}
                      animated
                      size="sm"
                    />
                  </div>
                  <div className="flex justify-between text-[10px] font-mono border-t border-[var(--border)] pt-2 mt-1">
                    <span className="text-[var(--ok)] font-semibold">{stat.passed} PASS</span>
                    <span className="text-[var(--bad)] font-semibold">{stat.failed} FAIL</span>
                    <span className="text-[var(--text-tertiary)]">{stat.total} TOTAL</span>
                  </div>
                </GlassCard>
              ))}
            </div>
            
            <GlassCard variant="glow" delay={0.2} className="flex flex-col items-center justify-center p-4">
              <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)] mb-2 w-full text-left">Control Status Distribution</h3>
              <div className="h-44 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={donutData}
                      cx="50%"
                      cy="50%"
                      innerRadius={45}
                      outerRadius={65}
                      paddingAngle={4}
                      dataKey="value"
                    >
                      {donutData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <ChartTooltip
                      contentStyle={{
                        backgroundColor: 'var(--surface)',
                        borderColor: 'var(--border)',
                        borderRadius: '8px',
                        color: 'var(--text-primary)',
                        fontSize: '11px',
                      }}
                    />
                    <Legend verticalAlign="bottom" height={36} iconType="circle" iconSize={8} wrapperStyle={{ fontSize: '10px' }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </GlassCard>
          </div>

          {/* Framework Detail Sections */}
          <div className="space-y-8">
            {Object.entries(report.framework_coverage).map(([framework, controls]) => (
              <motion.div variants={itemVariants} key={framework} className="space-y-4">
                <h3 className="text-sm font-bold flex items-center gap-2 px-1">
                  <FileText size={16} className="text-[var(--accent)]" />
                  <span>{framework} Controls</span>
                </h3>
                <div className="grid gap-2">
                  {Object.entries(controls).map(([cid, data]) => (
                    <div 
                      key={cid} 
                      className={`card overflow-hidden transition-all border ${data.maturity !== 'PASS' ? 'border-l-4' : ''} ${
                        data.maturity === 'FAIL' ? 'border-l-[var(--bad)]' : 
                        data.maturity === 'AT_RISK' ? 'border-l-orange-500' : 
                        data.maturity === 'PARTIAL' ? 'border-l-[var(--warn)]' : 'border-border'
                      } bg-[var(--surface-2)]`}
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
                          <span className="text-xs font-mono font-bold text-[var(--accent)] w-20">{cid}</span>
                          <span className={`status-pill text-[10px] border px-2 py-0.5 rounded font-bold ${getMaturityColor(data.maturity)}`}>
                            {data.maturity}
                          </span>
                        </div>
                        {expandedControls.has(cid) ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                      </div>

                      <AnimatePresence initial={false}>
                        {expandedControls.has(cid) && (
                          <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: 'auto', opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            transition={{ duration: 0.25, ease: EASE_OUT }}
                            className="overflow-hidden"
                          >
                            <div className="p-4 pt-0 border-t border-[var(--border)]/50 bg-black/20 space-y-4">
                              <div className="mt-4">
                                <h4 className="text-[10px] uppercase text-[var(--text-tertiary)] font-bold mb-1">Recommendation</h4>
                                <p className="text-xs italic text-[var(--text-secondary)]">{data.recommendation}</p>
                              </div>
                              
                              {data.findings.length > 0 && (
                                <div>
                                  <h4 className="text-[10px] uppercase text-[var(--text-tertiary)] font-bold mb-2">Evidence ({data.findings.length})</h4>
                                  <div className="space-y-2">
                                    {data.findings.map(f => (
                                      <div key={f.id} className="text-xs flex items-center justify-between bg-[var(--surface)] p-2 rounded border border-[var(--border)]">
                                        <div className="flex items-center gap-2">
                                          <span className={`w-2 h-2 rounded-full ${
                                            f.severity === 'critical' ? 'bg-[var(--bad)]' : 
                                            f.severity === 'high' ? 'bg-orange-500' : 'bg-[var(--warn)]'
                                          }`} />
                                          <span className="font-bold text-[var(--text-primary)]">{f.title}</span>
                                          <span className="text-[var(--text-tertiary)] truncate max-w-[300px]">{f.url}</span>
                                        </div>
                                        <a href={`/findings?finding=${encodeURIComponent(f.id)}`} className="text-[var(--accent)] hover:underline flex items-center gap-1">
                                          <span>View</span>
                                          <ExternalLink size={10} />
                                        </a>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  ))}
                </div>
              </motion.div>
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
