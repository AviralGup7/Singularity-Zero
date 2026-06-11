import { useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import { ExternalLink, FileText, ShieldCheck, RefreshCw, Library, Package, Shield, Plus, Sparkles, TrendingUp } from 'lucide-react';

import { getReportLibrary, type ReportLibraryItem, getAiExecutiveSummary, type AiExecutiveSummary, getSlaTrending, type SlaTrendingResponse } from '@/api/reports';
import { ApiError } from '@/api/core';
import { GlassCard } from '@/components/ui/GlassCard';
import { AnimatedCounter } from '@/components/ui/AnimatedCounter';
import { PageHeader } from '@/components/ui/PageHeader';
import { SkeletonTable } from '@/components/ui/Skeleton';

function shortHash(value: string): string {
  if (!value) return 'pending';
  return value.length > 16 ? `${value.slice(0, 12)}...${value.slice(-6)}` : value;
}

function formatGeneratedAt(value: string): string {
  if (!value) return 'unknown';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

const EASE_OUT = [0.16, 1, 0.3, 1] as const;

export function ReportLibraryPage() {
  const [reports, setReports] = useState<ReportLibraryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [aiSummary, setAiSummary] = useState<AiExecutiveSummary | null>(null);
  const [aiTarget, setAiTarget] = useState('');
  const [aiLoading, setAiLoading] = useState(false);
  const [slaData, setSlaData] = useState<SlaTrendingResponse | null>(null);

  const loadReports = async (signal?: AbortSignal) => {
    setLoading(true);
    setError('');
    try {
      const response = await getReportLibrary(signal);
      setReports(response.reports);
    } catch (err) {
      if (err instanceof DOMException && err.name === 'AbortError') return;
      setError(err instanceof ApiError ? err.message : 'Unable to load report library');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const controller = new AbortController();
    void loadReports(controller.signal);
    // Load SLA trending data in parallel
    getSlaTrending(controller.signal)
      .then(setSlaData)
      .catch(() => {});
    return () => controller.abort();
  }, []);

  const handleLoadAiSummary = async () => {
    if (!aiTarget.trim()) return;
    setAiLoading(true);
    try {
      const result = await getAiExecutiveSummary(aiTarget.trim());
      setAiSummary(result);
    } catch {
      setAiSummary(null);
    } finally {
      setAiLoading(false);
    }
  };

  const stats = useMemo(() => {
    const signed = reports.filter(report => report.signature_valid).length;
    const targets = new Set(reports.map(report => report.target)).size;
    return { signed, targets };
  }, [reports]);

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<Library size={20} />}
        title="Report Library"
        subtitle="Signed compliance artefacts"
        actions={
          <div className="flex items-center gap-2">
            <Link to="/reports/builder" className="btn btn-primary btn-sm inline-flex items-center gap-1">
              <Plus size={14} aria-hidden="true" />
              Build report
            </Link>
            <button type="button" className="btn btn-secondary btn-sm" onClick={() => void loadReports()}>
              <RefreshCw size={14} aria-hidden="true" />
              Refresh
            </button>
          </div>
        }
      />

      {/* ── KPI Cards ──────────────────────────────────────────── */}
      <div className="grid gap-4 md:grid-cols-3">
        <GlassCard variant="glow" delay={0} hoverable>
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs uppercase tracking-wider text-muted">Reports</span>
            <FileText size={16} className="text-accent" />
          </div>
          <AnimatedCounter value={reports.length} className="text-2xl font-semibold text-[var(--text-primary)]" />
        </GlassCard>

        <GlassCard variant="success" delay={0.1} hoverable>
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs uppercase tracking-wider text-muted">Valid Signatures</span>
            <ShieldCheck size={16} className="text-ok" />
          </div>
          <AnimatedCounter value={stats.signed} className="text-2xl font-semibold text-ok" />
        </GlassCard>

        <GlassCard variant="glow" delay={0.2} hoverable>
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs uppercase tracking-wider text-muted">Targets</span>
            <Shield size={16} className="text-accent" />
          </div>
          <AnimatedCounter value={stats.targets} className="text-2xl font-semibold text-[var(--text-primary)]" />
        </GlassCard>
      </div>

      {/* ── SLA Trending Card ──────────────────────────────────── */}
      {slaData && (
        <motion.section
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35, delay: 0.15 }}
        >
          <GlassCard variant="glow" hoverable={false}>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <TrendingUp size={16} className="text-accent" />
                <h3 className="text-xs font-black uppercase tracking-widest text-[var(--text-primary)]">SLA Compliance Trending</h3>
              </div>
              <span className="text-[10px] font-mono text-muted uppercase">{slaData.sla_compliance_rate}% compliant</span>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-[11px]">
              <div className="p-2 rounded-lg bg-white/5 border border-white/5">
                <span className="text-[9px] font-black uppercase tracking-widest text-muted block mb-0.5">MTTR</span>
                <span className="font-mono font-bold text-[var(--text-primary)]">{slaData.mttr_days}d</span>
              </div>
              <div className="p-2 rounded-lg bg-white/5 border border-white/5">
                <span className="text-[9px] font-black uppercase tracking-widest text-muted block mb-0.5">Active Breaches</span>
                <span className={`font-mono font-bold ${slaData.active_breaches > 0 ? 'text-bad' : 'text-ok'}`}>{slaData.active_breaches}</span>
              </div>
              <div className="p-2 rounded-lg bg-white/5 border border-white/5">
                <span className="text-[9px] font-black uppercase tracking-widest text-muted block mb-0.5">Open</span>
                <span className="font-mono font-bold text-warn">{slaData.open_findings_count}</span>
              </div>
              <div className="p-2 rounded-lg bg-white/5 border border-white/5">
                <span className="text-[9px] font-black uppercase tracking-widest text-muted block mb-0.5">Remediated</span>
                <span className="font-mono font-bold text-ok">{slaData.remediated_findings_count}</span>
              </div>
            </div>
          </GlassCard>
        </motion.section>
      )}

      {/* ── AI Executive Summary ──────────────────────────────── */}
      <motion.section
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35, delay: 0.25 }}
      >
        <GlassCard variant="glow" hoverable={false}>
          <div className="flex items-center gap-2 mb-3">
            <Sparkles size={16} className="text-accent" />
            <h3 className="text-xs font-black uppercase tracking-widest text-[var(--text-primary)]">AI Executive Summary</h3>
          </div>
          <div className="flex items-center gap-2 mb-3">
            <input
              type="text"
              placeholder="Enter target name..."
              value={aiTarget}
              onChange={e => setAiTarget(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') handleLoadAiSummary(); }}
              className="flex-1 bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-[11px] font-mono text-text focus:border-accent/50 outline-none"
            />
            <button
              type="button"
              onClick={handleLoadAiSummary}
              disabled={aiLoading || !aiTarget.trim()}
              className="btn btn-primary btn-sm text-[10px] uppercase tracking-wider"
            >
              {aiLoading ? 'Generating...' : 'Generate'}
            </button>
          </div>
          {aiSummary && (
            <div className="p-4 rounded-xl bg-black/30 border border-white/5 text-xs text-muted/80 font-mono leading-relaxed whitespace-pre-wrap max-h-64 overflow-y-auto scrollbar-cyber">
              <div className="text-[9px] text-accent uppercase tracking-widest mb-2">
                Target: {aiSummary.target} · Run: {aiSummary.run_id}
              </div>
              {aiSummary.summary}
            </div>
          )}
        </GlassCard>
      </motion.section>

      {/* ── Error Banner ───────────────────────────────────────── */}
      {error && (
        <GlassCard variant="error" hoverable={false}>
          <p className="text-sm text-bad">{error}</p>
        </GlassCard>
      )}

      {/* ── Reports Table ──────────────────────────────────────── */}
      <motion.section
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.2, ease: EASE_OUT }}
      >
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Target</th>
                <th>Run</th>
                <th>Generated</th>
                <th>Signature</th>
                <th>Manifest</th>
                <th>Artefacts</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr>
                  <td colSpan={6} className="p-0">
                    <SkeletonTable />
                  </td>
                </tr>
              )}
              {!loading && reports.length === 0 && (
                <tr>
                  <td colSpan={6} className="text-center py-12 text-[var(--text-secondary)]">
                    No signed reports have been generated yet.
                  </td>
                </tr>
              )}
              {!loading && reports.map((report, idx) => (
                <motion.tr
                  key={`${report.target}-${report.run_id}`}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: idx * 0.03, duration: 0.25 }}
                  className="transition-all duration-200 hover:bg-white/5"
                >
                  <td>
                    <div className="font-medium">{report.target}</div>
                    <div className="text-xs text-muted">{report.finding_count} reportable findings</div>
                  </td>
                  <td>
                    <code>{report.run_id}</code>
                    <div className="text-xs text-muted">{report.version}</div>
                  </td>
                  <td>{formatGeneratedAt(report.generated_at)}</td>
                  <td>
                    <span
                      className={`status-badge ${report.signature_valid ? 'status-completed' : 'status-stopped'}`}
                      style={report.signature_valid ? { boxShadow: '0 0 8px rgba(16,185,129,0.3)' } : undefined}
                    >
                      <ShieldCheck size={12} aria-hidden="true" />
                      {report.signature_valid ? 'Verified' : 'Review'}
                    </span>
                  </td>
                  <td><code title={report.manifest_sha256}>{shortHash(report.manifest_sha256)}</code></td>
                  <td>
                    <div className="flex flex-wrap gap-2">
                      <a className="btn btn-small inline-flex items-center gap-1" href={report.links.html} target="_blank" rel="noopener noreferrer">
                        <ExternalLink size={12} aria-hidden="true" />
                        HTML
                      </a>
                      <a className="btn btn-small inline-flex items-center gap-1" href={report.links.attestation_pdf} download>
                        <FileText size={12} aria-hidden="true" />
                        PDF
                      </a>
                      <a className="btn btn-small inline-flex items-center gap-1" href={report.links.sbom} download>
                        <Shield size={12} aria-hidden="true" />
                        SBOM
                      </a>
                      <a className="btn btn-small inline-flex items-center gap-1" href={report.links.manifest} download>
                        <Package size={12} aria-hidden="true" />
                        Manifest
                      </a>
                    </div>
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>
      </motion.section>
    </div>
  );
}
