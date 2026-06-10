import { useState, useEffect, useMemo, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, DollarSign, Send, CheckCircle2, HelpCircle, 
  AlertCircle, Filter, Search, ArrowUpRight, Lock, 
  RefreshCw, Edit2, TrendingUp, AlertOctagon 
} from 'lucide-react';

import { getFindings, updateFinding } from '@/api/findings';
import type { Finding } from '@/types/api';
import { GlassCard, PageHeader, EmptyState } from '@/components/ui';
import { SubmitToPlatformDialog } from '@/pages/findings/components/SubmitToPlatformDialog';
import { useToast } from '@/hooks/useToast';
import { useDebouncedFilter } from '@/hooks/useDebouncedFilter';

function getCVSSScore(f: Finding): number {
  return (f.cvss_v4_score ?? f.cvss_score ?? (typeof f.cvss === 'number' ? f.cvss : parseFloat(String(f.cvss)))) || 0;
}

function calculateEstimatedBounty(f: Finding): number {
  if (f.bounty_value) return f.bounty_value;
  const score = getCVSSScore(f);
  if (score >= 9.0) return 2000;
  if (score >= 7.0) return 750;
  if (score >= 4.0) return 250;
  if (score > 0) return 50;
  return 0;
}

export function BugBountyDashboardPage() {
  const toast = useToast();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { filter: searchQuery, setFilter: setSearchQuery, debouncedFilter: debouncedSearch } = useDebouncedFilter(300);
  const [selectedPlatform, setSelectedPlatform] = useState<string>('all');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  
  // Submit Dialog state
  const [submitDialogOpen, setSubmitDialogOpen] = useState(false);
  const [activeFinding, setActiveFinding] = useState<Finding | null>(null);

  // Edit Bounty Value state
  const [editingFinding, setEditingFinding] = useState<Finding | null>(null);
  const [editBountyVal, setEditBountyVal] = useState<number>(0);
  const [editSource, setEditSource] = useState<'hackerone' | 'bugcrowd' | 'intigriti' | 'manual' | 'estimate'>('estimate');

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getFindings();
      setFindings(data);
    } catch {
      toast.error('Failed to load findings data');
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Statistics calculations
  const stats = useMemo(() => {
    let earned = 0;
    let potential = 0;
    let reported = 0;
    let pending = 0;

    findings.forEach(f => {
      const val = calculateEstimatedBounty(f);
      if (f.already_reported) {
        earned += f.bounty_value || val;
        reported += 1;
      } else {
        potential += val;
        if (f.severity === 'critical' || f.severity === 'high' || f.severity === 'medium') {
          pending += 1;
        }
      }
    });

    return { earned, potential, reported, pending };
  }, [findings]);

  // Platform distribution
  const platformStats = useMemo(() => {
    const distribution: Record<string, { count: number; value: number }> = {
      hackerone: { count: 0, value: 0 },
      bugcrowd: { count: 0, value: 0 },
      intigriti: { count: 0, value: 0 },
      synack: { count: 0, value: 0 },
      estimate: { count: 0, value: 0 },
    };

    findings.forEach(f => {
      const source = f.bounty_source || 'estimate';
      const val = calculateEstimatedBounty(f);
      // eslint-disable-next-line security/detect-object-injection
      if (source in distribution) {
        // eslint-disable-next-line security/detect-object-injection
        distribution[source].count += 1;
        // eslint-disable-next-line security/detect-object-injection
        distribution[source].value += f.bounty_value || val;
      }
    });

    return distribution;
  }, [findings]);

  // Filtered findings for triage
  const filteredFindings = useMemo(() => {
    return findings.filter(f => {
      const q = debouncedSearch.toLowerCase().trim();
      if (q) {
        const titleMatch = (f.title || '').toLowerCase().includes(q);
        const targetMatch = (f.target || '').toLowerCase().includes(q);
        const typeMatch = (f.type || '').toLowerCase().includes(q);
        if (!titleMatch && !targetMatch && !typeMatch) return false;
      }

      if (selectedPlatform !== 'all') {
        const source = f.bounty_source || 'estimate';
        if (source !== selectedPlatform) return false;
      }

      if (selectedSeverity !== 'all' && f.severity !== selectedSeverity) return false;

      if (selectedStatus !== 'all') {
        const isReported = !!f.already_reported;
        if (selectedStatus === 'reported' && !isReported) return false;
        if (selectedStatus === 'unreported' && isReported) return false;
      }

      return true;
    });
  }, [findings, debouncedSearch, selectedPlatform, selectedSeverity, selectedStatus]);

  const handleToggleReported = async (f: Finding) => {
    const nextVal = !f.already_reported;
    try {
      await updateFinding(f.id, { already_reported: nextVal });
      setFindings(prev => prev.map(item => item.id === f.id ? { ...item, already_reported: nextVal } : item));
      toast.success(nextVal ? 'Finding marked as submitted' : 'Finding marked as pending');
    } catch {
      toast.error('Unable to update reporting status');
    }
  };

  const handleOpenSubmitDialog = (f: Finding) => {
    setActiveFinding(f);
    setSubmitDialogOpen(true);
  };

  const handleOpenEditBounty = (f: Finding) => {
    setEditingFinding(f);
    setEditBountyVal(f.bounty_value || calculateEstimatedBounty(f));
    setEditSource(f.bounty_source || 'estimate');
  };

  const handleSaveBountyEdit = async () => {
    if (!editingFinding) return;
    try {
      await updateFinding(editingFinding.id, {
        bounty_value: editBountyVal,
        bounty_source: editSource,
      });
      setFindings(prev => prev.map(item => item.id === editingFinding.id ? { ...item, bounty_value: editBountyVal, bounty_source: editSource } : item));
      toast.success('Bounty details updated');
      setEditingFinding(null);
    } catch {
      toast.error('Failed to update bounty details');
    }
  };

  return (
    <div className="space-y-6 p-8 font-sans bg-bg min-h-screen text-text">
      <PageHeader 
        icon={<DollarSign size={20} className="text-accent" />}
        title="Bounty Lead Dashboard"
        subtitle="Operational economics dashboard and submission pipeline for bug bounty researchers."
        actions={
          <button 
            type="button" 
            onClick={loadData}
            className="btn btn-secondary btn-sm flex items-center gap-1.5"
            disabled={loading}
          >
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
            <span>Resync</span>
          </button>
        }
      />

      {/* Stats Cards HUD */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <GlassCard variant="glow" hoverable={false} className="p-6 relative overflow-hidden">
          <div className="text-[10px] font-black text-muted uppercase tracking-wider mb-2">Total Potential Payouts</div>
          <div className="text-3xl font-black text-accent">${stats.potential.toLocaleString()}</div>
          <p className="text-[9px] text-muted mt-2 font-mono uppercase">Estimated from open findings</p>
        </GlassCard>

        <GlassCard variant="default" hoverable={false} className="p-6">
          <div className="text-[10px] font-black text-muted uppercase tracking-wider mb-2">Total Earned/Reported</div>
          <div className="text-3xl font-black text-text">${stats.earned.toLocaleString()}</div>
          <p className="text-[9px] text-muted mt-2 font-mono uppercase">{stats.reported} submitted reports</p>
        </GlassCard>

        <GlassCard variant="default" hoverable={false} className="p-6">
          <div className="text-[10px] font-black text-muted uppercase tracking-wider mb-2">Triage Queue Length</div>
          <div className="text-3xl font-black text-white">{stats.pending}</div>
          <p className="text-[9px] text-muted mt-2 font-mono uppercase">High-impact unreported leads</p>
        </GlassCard>

        <GlassCard variant="default" hoverable={false} className="p-6">
          <div className="text-[10px] font-black text-muted uppercase tracking-wider mb-2">Reporting Conversion</div>
          <div className="text-3xl font-black text-accent-dim">
            {stats.reported + stats.pending > 0 
              ? `${Math.round((stats.reported / (stats.reported + stats.pending)) * 100)}%` 
              : '0%'}
          </div>
          <p className="text-[9px] text-muted mt-2 font-mono uppercase">Yield rate vs potential leads</p>
        </GlassCard>
      </div>

      {/* Platform Breakdown & Info */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Platform Share Widget */}
        <GlassCard variant="default" hoverable={false} className="lg:col-span-2 p-6">
          <h3 className="text-sm font-bold uppercase tracking-wider mb-4 text-white">Platform Allocation & Yields</h3>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {Object.entries(platformStats).map(([platform, pStat]) => (
              <div key={platform} className="bg-black/30 border border-white/5 rounded-xl p-3 flex flex-col justify-between">
                <div className="text-[9px] font-black uppercase tracking-widest text-muted">{platform}</div>
                <div className="mt-3">
                  <div className="text-lg font-bold text-text">${pStat.value.toLocaleString()}</div>
                  <div className="text-[9px] text-muted font-mono">{pStat.count} findings</div>
                </div>
              </div>
            ))}
          </div>
        </GlassCard>

        {/* Integration Credentials Alert */}
        <GlassCard variant="glow" hoverable={false} className="p-6 flex flex-col justify-between border-cyan-500/20">
          <div>
            <h3 className="text-sm font-bold uppercase tracking-wider mb-2 text-accent">Active Integrations</h3>
            <p className="text-xs text-muted leading-relaxed">
              Submission triggers communicate directly with HackerOne, Bugcrowd, Intigriti and Synack APIs when configured in your environment context.
            </p>
          </div>
          <div className="mt-4 flex items-center gap-2 text-[9px] font-mono text-muted uppercase">
            <Lock size={12} className="text-accent-dim" />
            <span>Secure TLS Client Token Session</span>
          </div>
        </GlassCard>
      </div>

      {/* Triage Queue Table */}
      <GlassCard variant="default" hoverable={false} className="p-6">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between mb-6">
          <h3 className="text-sm font-bold uppercase tracking-wider text-white">Active Triage Queue</h3>
          
          <div className="flex flex-wrap items-center gap-2 flex-1 max-w-2xl justify-end">
            {/* Search */}
            <div className="relative flex-1 max-w-xs">
              <Search size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
              <input
                type="text"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="Search leads..."
                className="form-input pl-8 w-full text-xs font-mono"
                aria-label="Search leads"
              />
            </div>

            {/* Platform Select */}
            <select
              value={selectedPlatform}
              onChange={e => setSelectedPlatform(e.target.value)}
              className="form-input text-xs font-mono bg-[#151515]"
              aria-label="Filter by platform"
            >
              <option value="all">Platform: All</option>
              <option value="hackerone">HackerOne</option>
              <option value="bugcrowd">Bugcrowd</option>
              <option value="intigriti">Intigriti</option>
              <option value="synack">Synack</option>
              <option value="estimate">Estimates</option>
            </select>

            {/* Severity Select */}
            <select
              value={selectedSeverity}
              onChange={e => setSelectedSeverity(e.target.value)}
              className="form-input text-xs font-mono bg-[#151515]"
              aria-label="Filter by severity"
            >
              <option value="all">Severity: All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            {/* Status Select */}
            <select
              value={selectedStatus}
              onChange={e => setSelectedStatus(e.target.value)}
              className="form-input text-xs font-mono bg-[#151515]"
              aria-label="Filter by submission status"
            >
              <option value="all">Status: All</option>
              <option value="unreported">Not Reported</option>
              <option value="reported">Reported</option>
            </select>
          </div>
        </div>

        {/* Table list */}
        <div className="table-container" role="region" aria-label="Triage findings">
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Title</th>
                <th>Target</th>
                <th>CVSS / EPSS</th>
                <th>Bounty Estimate</th>
                <th>Platform</th>
                <th>Status</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={8} className="text-center py-12 text-muted">Synchronizing bounty database...</td>
                </tr>
              ) : filteredFindings.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center py-12">
                    <EmptyState
                      title="No bounty leads match your filters"
                      description="Try adjusting your search query, platform, severity, or status filters."
                      icon="shield"
                    />
                  </td>
                </tr>
              ) : (
                filteredFindings.map(f => {
                  const estBounty = calculateEstimatedBounty(f);
                  const score = getCVSSScore(f);
                  const epss = f.threat_intel?.epss_score ?? f.epss_score ?? 0;
                  const isReported = !!f.already_reported;
                  const platformLabel = f.bounty_source || 'estimate';
                  
                  return (
                    <tr key={f.id} className="hover:bg-white/[0.02] transition-colors">
                      <td>
                        <span className={`status-badge status-${f.severity}`}>
                          {f.severity.toUpperCase()}
                        </span>
                      </td>
                      <td className="font-bold max-w-xs truncate">{f.title}</td>
                      <td className="text-muted text-xs font-mono max-w-xs truncate">{f.target || f.host || '—'}</td>
                      <td>
                        <div className="text-xs font-mono">
                          CVSS: <span className="text-text font-bold">{score.toFixed(1)}</span> <br />
                          EPSS: <span className="text-muted">{(epss * 100).toFixed(1)}%</span>
                        </div>
                      </td>
                      <td>
                        <div className="flex items-center gap-1.5 group">
                          <span className="font-mono text-accent font-bold">${(f.bounty_value || estBounty).toLocaleString()}</span>
                          <button 
                            type="button" 
                            onClick={() => handleOpenEditBounty(f)}
                            className="opacity-0 group-hover:opacity-100 p-1 rounded hover:bg-white/5 transition-all text-muted hover:text-white cursor-pointer"
                          >
                            <Edit2 size={10} />
                          </button>
                        </div>
                      </td>
                      <td>
                        <span className="text-[10px] font-mono uppercase bg-white/5 border border-white/10 px-1.5 py-0.5 rounded text-muted">
                          {platformLabel}
                        </span>
                      </td>
                      <td>
                        {isReported ? (
                          <span className="text-[9px] font-black uppercase text-ok flex items-center gap-1">
                            <CheckCircle2 size={10} /> Submitted
                          </span>
                        ) : (
                          <span className="text-[9px] font-black uppercase text-warn flex items-center gap-1 animate-pulse">
                            <AlertCircle size={10} /> Pending Triage
                          </span>
                        )}
                      </td>
                      <td className="text-right">
                        <div className="flex justify-end gap-2">
                          <button
                            type="button"
                            onClick={() => handleToggleReported(f)}
                            className="btn btn-secondary btn-xs font-mono uppercase text-[9px]"
                            title={isReported ? 'Mark as unreported' : 'Mark as reported'}
                          >
                            {isReported ? 'Unmark' : 'Mark Reported'}
                          </button>
                          
                          <button
                            type="button"
                            onClick={() => handleOpenSubmitDialog(f)}
                            disabled={isReported}
                            className="btn btn-primary btn-xs uppercase text-[9px] font-black flex items-center gap-1 shadow-[0_0_10px_rgba(0,255,65,0.1)]"
                          >
                            <Send size={10} /> Submit
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </GlassCard>

      {/* Edit Bounty Modal */}
      <AnimatePresence>
        {editingFinding && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
            <motion.div 
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-sm rounded-2xl border border-white/10 bg-bg p-6 shadow-xl space-y-4"
            >
              <h3 className="text-sm font-bold uppercase tracking-wider text-white">Edit Bounty Lead</h3>
              <p className="text-xs text-muted max-w-xs truncate">{editingFinding.title}</p>
              
              <div className="space-y-3 pt-2">
                <label className="block text-xs text-muted">
                  Bounty Value (USD)
                  <input
                    type="number"
                    value={editBountyVal}
                    onChange={e => setEditBountyVal(Number(e.target.value))}
                    className="w-full mt-1 bg-white/5 border border-white/10 rounded-lg py-2 px-3 text-xs font-mono text-text focus:border-accent/50 outline-none"
                  />
                </label>

                <label className="block text-xs text-muted">
                  Platform / Source
                  <select
                    value={editSource}
                    onChange={e => setEditSource(e.target.value)}
                    className="w-full mt-1 bg-[#151515] border border-white/10 rounded-lg py-2 px-3 text-xs font-mono text-text focus:border-accent/50 outline-none"
                  >
                    <option value="estimate">Estimate</option>
                    <option value="hackerone">HackerOne</option>
                    <option value="bugcrowd">Bugcrowd</option>
                    <option value="intigriti">Intigriti</option>
                    <option value="synack">Synack</option>
                    <option value="manual">Manual</option>
                  </select>
                </label>
              </div>

              <div className="pt-4 flex justify-end gap-2 border-t border-white/5">
                <button
                  type="button"
                  onClick={() => setEditingFinding(null)}
                  className="rounded border border-white/10 px-3.5 py-2 text-xs text-text hover:bg-white/5 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleSaveBountyEdit}
                  className="rounded bg-accent px-3.5 py-2 text-xs font-black text-black hover:bg-accent-dim transition-all cursor-pointer"
                >
                  Save Changes
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Submission Dialog */}
      {activeFinding && (
        <SubmitToPlatformDialog
          runId={String(activeFinding.metadata?.run_name || activeFinding.metadata?.job_id || activeFinding.target || 'global')}
          findingId={activeFinding.id}
          findingTitle={activeFinding.title}
          open={submitDialogOpen}
          onClose={() => { setSubmitDialogOpen(false); setActiveFinding(null); }}
          onSubmitted={(res) => {
            if (res.submitted) {
              setFindings(prev => prev.map(item => item.id === activeFinding.id ? { ...item, already_reported: true, bounty_source: res.platform as any } : item));
              toast.success(`Successfully submitted to ${res.platform}`);
            } else {
              toast.error(`Submission failed: ${res.error}`);
            }
            setSubmitDialogOpen(false);
            setActiveFinding(null);
          }}
        />
      )}
    </div>
  );
}

export default BugBountyDashboardPage;
