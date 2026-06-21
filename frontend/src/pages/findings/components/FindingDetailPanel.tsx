import React, { useEffect, useState, useRef, useCallback } from 'react';
import { Shield, X, Zap, FileDown, GitMerge, GitBranch, XCircle, Send } from 'lucide-react';
import { motion } from 'framer-motion';
import type { Finding, RemediationSuggestion, EvidenceItem, AttackChain } from '../../../types/api';
import { getFindingRemediation, getFindingById } from '../../../api/client';
import { useToast } from '../../../hooks/useToast';
import { EvidenceDisplay } from '../../../components/findings/EvidenceDisplay';
import { AttackChainVisualizer } from '../../../components/AttackChainVisualizer';
import { FindingComments } from '../../../components/findings/FindingComments';
import { RequestResponseViewer } from '../../../components/RequestResponseViewer';
import { EvidenceCustodyViewer } from '../../../components/common/EvidenceCustodyViewer';
import { useTriageCollaboration } from '@/hooks/useTriageCollaboration';
import { exportFinding, type ReportFormat } from '@/utils/findingExport';
import { SubmitToPlatformDialog } from './SubmitToPlatformDialog';
import { FindingBountyPanel } from './FindingBountyPanel';
import { FindingRiskPanel } from './FindingRiskPanel';



// eslint-disable-next-line react-refresh/only-export-components
export const remediationCache = new Map<string, RemediationSuggestion[]>();

// eslint-disable-next-line react-refresh/only-export-components
export function prefetchRemediation(id: string) {
  if (!id || remediationCache.has(id)) return;
  getFindingRemediation(id)
    .then((res) => {
      remediationCache.set(id, res.suggestions || []);
    })
    .catch(() => {});
}

export type DetailTab = 'cvss' | 'csi' | 'risk' | 'evidence' | 'custody' | 'simulation' | 'request' | 'logic' | 'comments' | 'activity' | 'bounty';

interface ExtendedEvidence {
  chain_simulation?: AttackChain;
  replay?: { id: string };
  [key: string]: unknown;
}

export function FindingDetailPanel({
  finding: initialFinding,
  onClose,
}: {
  finding: Finding;
  onClose: () => void;
}) {
  const [finding, setFinding] = useState<Finding>(initialFinding);
  const dialogRef = useRef<HTMLDivElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);

  // Re-fetch finding data on mount to avoid stale data
  useEffect(() => {
    let cancelled = false;
    getFindingById(initialFinding.id)
      .then((fresh) => {
        if (!cancelled && fresh) setFinding(fresh);
      })
      .catch(() => {
        // Keep initial data if fetch fails
      });
    return () => { cancelled = true; };
  }, [initialFinding.id]);

  // Focus trap: capture previous focus, focus dialog on mount, return on unmount
  useEffect(() => {
    previousFocusRef.current = document.activeElement as HTMLElement;
    const dialog = dialogRef.current;
    if (dialog) {
      // Focus the first focusable element inside the dialog
      const firstFocusable = dialog.querySelector<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      );
      firstFocusable?.focus();
    }
    return () => {
      previousFocusRef.current?.focus();
    };
  }, []);

  // Trap Tab key inside the dialog
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      onClose();
      return;
    }
    if (e.key !== 'Tab') return;
    const dialog = dialogRef.current;
    if (!dialog) return;
    const focusableElements = dialog.querySelectorAll<HTMLElement>(
      'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
    );
    if (focusableElements.length === 0) return;
    const first = focusableElements[0];
    const last = focusableElements[focusableElements.length - 1];
    if (e.shiftKey) {
      if (document.activeElement === first) {
        e.preventDefault();
        last.focus();
      }
    } else {
      if (document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  }, [onClose]);

  const [detailTab, setDetailTab] = useState<DetailTab>('csi');

  const handleUpdateFinding = useCallback((updated: Partial<Finding>) => {
    setFinding((prev) => ({ ...prev, ...updated }));
  }, []);
  const [reviewerId] = useState<string>(() => {
    try {
      return localStorage.getItem('analyst_reviewer_id') || 'analyst';
    } catch {
      return 'analyst';
    }
  });
   
  const [remediation, setRemediation] = useState<RemediationSuggestion[]>([]);
   
  const [loadingRemediation, setLoadingRemediation] = useState(false);
  const [submitDialogOpen, setSubmitDialogOpen] = useState(false);
  const toast = useToast();

  useEffect(() => {
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
   
  }, [onClose]);

  useEffect(() => {
    if (!finding.id) return;
    
    if (remediationCache.has(finding.id)) {
      setRemediation(remediationCache.get(finding.id) || []);
      setLoadingRemediation(false);
      return;
    }

    let mounted = true;
    
    // Defer the initial loading state update
    Promise.resolve().then(() => {
      if (mounted) setLoadingRemediation(true);
    });

    getFindingRemediation(finding.id)
      .then((res) => {
        if (mounted) {
          const suggestions = res.suggestions || [];
          remediationCache.set(finding.id, suggestions);
          setRemediation(suggestions);
          setLoadingRemediation(false);
        }
      })
      .catch(() => {
        if (mounted) {
          setRemediation([]);
          setLoadingRemediation(false);
        }
      });
      
    return () => { mounted = false; };
  }, [finding.id]);

  const isLogicBreach = finding.type?.startsWith('logic_breach');

  const evidence = finding.evidence as ExtendedEvidence | undefined;
  const runId = String(
    finding.metadata?.run_name
    || finding.metadata?.job_id
    || finding.target
    || 'global'
  );
  const triage = useTriageCollaboration(runId, finding.id);
  const triageStatus = triage.state?.status || finding.lifecycle_state || 'open';

  const recordWorkflowAction = async (
    action: 'finding_escalated' | 'finding_closed' | 'finding_reopened' | 'finding_false_positive',
    payload: Record<string, unknown>,
    successMessage: string,
    errorMessage: string,
  ) => {
    try {
      await triage.sendAction(action, payload);
      toast.success(successMessage);
    } catch {
      toast.error(errorMessage);
    }
  };

  const handleMergeDuplicates = async () => {
    const dupIds = (finding.duplicates || []).filter(Boolean);
    if (dupIds.length === 0) {
      toast.warning('No duplicates to merge');
      return;
    }
    const ok = typeof window !== 'undefined'
      ? window.confirm(`Merge ${dupIds.length} duplicate(s) into this finding? The duplicates will be marked as resolved duplicates.`)
      : true;
    if (!ok) return;
    const { updateFinding } = await import('../../../api/findings');
    let failed = 0;
    for (const dupId of dupIds) {
      try {
        await updateFinding(dupId, { falsePositive: true, fpStatus: 'approved', fpJustification: `Merged into primary ${finding.id}` });
      } catch {
        failed += 1;
      }
    }
    if (failed === 0) {
      toast.success(`Merged ${dupIds.length} duplicate(s) into this finding`);
    } else {
      toast.warning(`Merged ${dupIds.length - failed}; ${failed} failed`);
    }
  };

  const handleDismissAsDuplicate = async () => {
    if (!finding.id) return;
    const ok = typeof window !== 'undefined'
      ? window.confirm('Mark this finding as a duplicate and dismiss? It will be hidden from default triage queues.')
      : true;
    if (!ok) return;
    const { updateFinding } = await import('../../../api/findings');
    try {
      await updateFinding(finding.id, { falsePositive: true, fpStatus: 'approved', fpJustification: 'Marked as duplicate by analyst' });
      toast.success('Finding dismissed as duplicate');
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Unable to dismiss as duplicate');
    }
  };

  const handlePromoteToIndependent = async () => {
    if (!finding.id) return;
    const ok = typeof window !== 'undefined'
      ? window.confirm('Promote this finding to an independent (non-duplicate) entry? The link to its previous primary will be removed.')
      : true;
    if (!ok) return;
    const { updateFinding } = await import('../../../api/findings');
    try {
      await updateFinding(finding.id, { duplicates: [], kanbanStatus: 'new' });
      toast.success('Finding promoted to independent');
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Unable to promote finding');
    }
  };

  const handleExport = async (format: ReportFormat) => {
    try {
      exportFinding(finding, format);
      toast.success(`Exported as ${format.toUpperCase()}`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Export failed');
    }
  };

  const chainSimulation: AttackChain | null = (finding.metadata?.chain_simulation as AttackChain) ||
                                              evidence?.chain_simulation ||
                                              null;

  const evidenceItems: EvidenceItem[] = finding.evidence ? [{
    id: `ev-${finding.id}`,
    timestamp: typeof finding.timestamp === 'number' ? new Date(finding.timestamp * 1000).toISOString() : String(finding.timestamp),
    source: 'System Correlation Scanner',
    description: finding.title,
    raw_data: JSON.stringify(finding.evidence, null, 2),
    data_type: 'json'
  }] : [];

  return (
    <div
      className="fixed inset-0 z-[10000] flex items-center justify-center bg-black/60 backdrop-blur-md p-4"
      onClick={onClose}
      onKeyDown={(e) => { if (e.key === 'Escape') onClose(); }}
      role="presentation"
    >
      <motion.div
        ref={dialogRef}
        initial={{ opacity: 0, scale: 0.9, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        className="w-full max-w-4xl max-h-[90vh] bg-bg border border-white/10 rounded-3xl shadow-[0_0_50px_rgba(0,0,0,0.5)] overflow-hidden flex flex-col"
        onClick={(e: React.MouseEvent) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
        role="dialog"
        aria-modal="true"
        aria-labelledby="finding-detail-title"
      >
        {/* Header */}
        <div className="px-8 py-6 border-b border-white/5 flex items-center justify-between bg-white/5">
          <div className="flex items-center gap-4">
             <div className={`p-3 rounded-xl border ${
               finding.severity === 'critical' ? 'bg-bad/10 border-bad/20 text-bad' : 'bg-accent/10 border-accent/20 text-accent'
             }`}>
                <Shield size={24} />
             </div>
             <div>
                <h3 id="finding-detail-title" className="text-xl font-black text-text uppercase tracking-tighter">{finding.title}</h3>
                <div className="flex items-center gap-3 text-[10px] text-muted font-mono uppercase tracking-widest mt-1">
                   <span>ID: {finding.id}</span>
                   <span>•</span>
                   <span>Target: {finding.target}</span>
                </div>
             </div>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1 mr-2" role="group" aria-label="Export this finding">
              <button
                type="button"
                className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black flex items-center gap-1"
                onClick={() => handleExport('markdown')}
                aria-label="Export as Markdown"
              >
                <FileDown size={12} aria-hidden="true" /> MD
              </button>
              <button
                type="button"
                className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black flex items-center gap-1"
                onClick={() => handleExport('html')}
                aria-label="Export as HTML"
              >
                <FileDown size={12} aria-hidden="true" /> HTML
              </button>
              <button
                type="button"
                className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black flex items-center gap-1"
                onClick={() => handleExport('json')}
                aria-label="Export as JSON"
              >
                <FileDown size={12} aria-hidden="true" /> JSON
              </button>
            </div>
            <button
              type="button"
              className="btn-primary btn-small uppercase tracking-widest text-[9px] font-black flex items-center gap-1"
              onClick={() => setSubmitDialogOpen(true)}
              aria-label="Submit to bug-bounty platform"
              title="Submit to HackerOne / Bugcrowd / Intigriti / Synack"
            >
              <Send size={12} aria-hidden="true" /> Submit
            </button>
            <button className="text-muted hover:text-white transition-colors" onClick={onClose} aria-label="Close panel"><X size={20} /></button>
          </div>
        </div>

        {/* Info Grid */}
        <div className="flex-1 overflow-y-auto p-8 space-y-8 scrollbar-cyber">
           <div className="grid grid-cols-4 gap-4">
              <div className="glass-panel p-4 rounded-xl">
                 <div className="text-[9px] font-black text-muted uppercase mb-1 tracking-widest">CSI Index</div>
                 <div className="text-2xl font-black text-accent">{finding.csi_score || 'N/A'}</div>
              </div>
              <div className="glass-panel p-4 rounded-xl">
                 <div className="text-[9px] font-black text-muted uppercase mb-1 tracking-widest">Confidence</div>
                 <div className="text-2xl font-black text-white">{Math.round(finding.confidence * 100)}%</div>
              </div>
              <div className="glass-panel p-4 rounded-xl">
                 <div className="text-[9px] font-black text-muted uppercase mb-1 tracking-widest">State</div>
                 <div className="text-sm font-black text-text uppercase mt-2">{triageStatus}</div>
              </div>
              <div className="glass-panel p-4 rounded-xl">
                 <div className="text-[9px] font-black text-muted uppercase mb-1 tracking-widest">Severity</div>
                 <div className={`text-sm font-black uppercase mt-2 ${
                   finding.severity === 'critical' ? 'text-bad' : 'text-accent'
                 }`}>{finding.severity}</div>
              </div>
           </div>

            {/* Tabs */}
            <div className="flex gap-6 border-b border-white/5 overflow-x-auto" role="tablist" aria-label="Finding detail sections">
               {[
                 { id: 'csi', label: 'Analysis' },
                 { id: 'bounty', label: 'Bounty & Submission' },
                 { id: 'evidence', label: 'Evidence' },
                 { id: 'custody', label: 'Custody' },
                 { id: 'simulation', label: 'Simulation', hide: !chainSimulation },
                 { id: 'request', label: 'Payloads' },
                 { id: 'logic', label: 'Logic Diff', hide: !isLogicBreach },
                 { id: 'risk', label: 'Risk' },
                 { id: 'activity', label: 'Activity' },
                 { id: 'comments', label: 'Intelligence' },
               ].map(tab => !tab.hide && (
                 <button
                   key={tab.id}
                   type="button"
                   role="tab"
                   aria-selected={detailTab === tab.id}
                   onClick={() => setDetailTab(tab.id as DetailTab)}
                   className={`pb-4 text-[10px] font-black uppercase tracking-widest border-b-2 transition-all whitespace-nowrap ${
                     detailTab === tab.id ? 'border-accent text-white' : 'border-transparent text-muted hover:text-text'
                   }`}
                 >
                   {tab.label}
                 </button>
               ))}
            </div>

           <div className="min-h-[300px]">
              {detailTab === 'bounty' && (
                <FindingBountyPanel finding={finding} onUpdateFinding={handleUpdateFinding} />
              )}

              {detailTab === 'csi' && (
                <div className="space-y-6">
                   <p className="text-sm text-text/80 leading-relaxed italic border-l-2 border-accent/20 pl-4">
                     {finding.description}
                   </p>
                   {loadingRemediation ? (
   
                     <div className="flex items-center gap-2 text-[10px] text-accent animate-pulse uppercase tracking-widest">
                        <div className="w-2 h-2 rounded-full bg-accent" />
                        Fetching Remediation intelligence...
                     </div>
                   ) : remediation.length > 0 ? (
                     <div className="grid gap-2">
                       <div className="text-[9px] font-black text-muted uppercase tracking-widest">Remediation Signals</div>
                       {remediation.slice(0, 3).map((item) => (
                         <div key={item.id} className="p-3 bg-black/30 border border-white/5 rounded-xl">
                           <div className="text-xs font-bold text-text">{item.title}</div>
                           {item.rationale && <p className="text-[10px] text-muted mt-1">{item.rationale}</p>}
                         </div>
                       ))}
                     </div>
                   ) : null}
                </div>
              )}

              {detailTab === 'logic' && (

                 <div className="space-y-4 font-mono text-[11px]">
                    <div className="p-4 bg-bad/10 border border-bad/20 rounded-xl mb-4">
                       <p className="text-bad font-black uppercase mb-1">State Machine Divergence Detected</p>
                       <p className="text-text/70">Differential analysis revealed significant identical behavior across distinct contexts.</p>
                    </div>
                    <pre className="p-6 bg-black/60 rounded-2xl border border-white/5 text-accent overflow-x-auto whitespace-pre-wrap">
                       {finding.logic_diff || 'No structural diff recorded for this signal.'}
                    </pre>
                 </div>
               )}

               {detailTab === 'risk' && (
                 <FindingRiskPanel finding={finding} reviewerId={reviewerId} />
               )}
              
              {detailTab === 'evidence' && (
                <EvidenceDisplay evidence={evidenceItems} />
              )}

              {detailTab === 'custody' && (
                <div className="glass-panel p-6 rounded-2xl border border-white/5">
                  <EvidenceCustodyViewer evidenceId={finding.id} />
                </div>
              )}

              {detailTab === 'request' && (
                <RequestResponseViewer pairs={finding.request_response || []} />
              )}

              {detailTab === 'activity' && (
                <div className="space-y-4">
                  <div className="text-[10px] text-muted uppercase tracking-widest font-black">Triage Activity</div>
                  {triage.state?.chain && (
                    <div className="glass-panel p-4 rounded-xl border border-white/5 text-[10px] font-mono text-muted">
                      Audit chain: {triage.state.chain.valid ? 'verified' : 'invalid'} · {triage.state.chain.entries} entries · hash {triage.state.chain.latest_hash.slice(0, 16)}…
                    </div>
                  )}
                  {triage.presence.length === 0 ? (
                    <p className="text-[10px] text-muted">No other analysts currently viewing this finding.</p>
                  ) : (
                    <ul className="space-y-2">
                      {triage.presence.map(p => (
                        <li key={p.analyst_id} className="text-xs text-text/80 flex items-center gap-2">
                          <span className="pulse-dot" aria-hidden="true" />
                          <span className="font-mono">{p.analyst_id}</span>
                          <span className="text-muted">— {(p.cursor as { area?: string } | undefined)?.area || 'viewing'}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              {detailTab === 'comments' && (
                <div className="glass-panel p-6 rounded-2xl border border-white/5">
                  <FindingComments findingId={finding.id} targetName={finding.target} runId={runId} />
                </div>
              )}

              {detailTab === 'simulation' && chainSimulation && (
                <div className="space-y-6">
                   <div className="p-4 bg-accent/5 border border-accent/20 rounded-2xl flex items-center gap-4">
                      <div className="h-10 w-10 rounded-full bg-accent/10 grid place-items-center text-accent">
                         <Zap size={20} />
                      </div>
                      <div>
                         <h4 className="text-sm font-black uppercase tracking-widest">Automated Kill-Chain Simulation</h4>
                         <p className="text-[10px] text-muted leading-relaxed">
                            System correlation identified a potential multi-stage attack path based on this finding.
                         </p>
                      </div>
                   </div>
                   <AttackChainVisualizer chains={[chainSimulation]} />
                </div>
              )}
           </div>
        </div>

        {/* Footer Actions */}
        <div className="px-8 py-6 bg-white/5 border-t border-white/5 flex justify-between items-center">
           <div className="flex gap-4">
              <button 
                className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black"
                onClick={() => {
                  const runName = finding.metadata?.run_name || finding.metadata?.job_id || '';
                  const replayId = finding.metadata?.replay_id || evidence?.replay?.id || '';
                  window.location.href = `/replay?target=${finding.target}&run=${runName}&replay_id=${replayId}&finding=${finding.id}`;
                }}
              >
                Replay with Diff
              </button>
              <button 
                className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black"
                onClick={() => {
                  window.location.href = `/cockpit?target=${finding.target}&focus=${finding.id}`;
                }}
              >
                View in 3D Cockpit
              </button>
              <button 
                className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black"
                onClick={async () => {
                  if (!finding.target || !finding.url) {
                    toast.error('Missing target or URL for forensic probing');
                    return;
                  }
                  try {
                    const { cockpitApi } = await import('@/api/cockpit');
                    await cockpitApi.triggerProbe(finding.target, finding.url);
                    toast.success('Manual forensic probe launched');
                  } catch {
                    toast.error('Probe sequence failed');
                  }
                }}
              >
                Forensic Probe
              </button>
              <button
                className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black"
                onClick={() => recordWorkflowAction(
                  'finding_escalated',
                  {
                    severity: finding.severity,
                    confidence: finding.confidence,
                    reason: 'Manual analyst escalation',
                  },
                  'Finding escalated for review',
                  'Unable to escalate finding',
                )}
                disabled={triageStatus === 'escalated'}
              >
                Escalate
              </button>
              <button
                className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black"
                onClick={() => recordWorkflowAction(
                  'finding_closed',
                  {
                    resolution: 'Manual analyst closure',
                    previous_state: triageStatus,
                  },
                  'Finding closed for the team',
                  'Unable to close finding',
                )}
                disabled={triageStatus === 'closed'}
              >
                Close
              </button>
              <button
                className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black"
                onClick={() => recordWorkflowAction(
                  'finding_reopened',
                  {
                    previous_state: triageStatus,
                    reason: 'Manual analyst reopen',
                  },
                  'Finding reopened',
                  'Unable to reopen finding',
                )}
                disabled={triageStatus === 'open'}
              >
                Reopen
              </button>
              <button
                className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black"
                onClick={() => recordWorkflowAction(
                  'finding_false_positive',
                  {
                    category: String(finding.metadata?.category || finding.type || finding.metadata?.module || 'manual_triage'),
                    status_code: finding.metadata?.response_status || finding.metadata?.status_code,
                    description: finding.description,
                    evidence: JSON.stringify(finding.evidence || {}),
                  },
                  'False-positive pattern shared with the mesh',
                  'Unable to record false-positive triage',
                )}
                disabled={triageStatus === 'false_positive'}
              >
                Flag False Positive
              </button>
              {(finding.duplicates || []).length > 0 && (
                <button
                  type="button"
                  className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black flex items-center gap-1"
                  onClick={handleMergeDuplicates}
                  aria-label={`Merge ${(finding.duplicates || []).length} duplicate(s) into this finding`}
                  title="Mark all listed duplicates as merged into this primary finding"
                >
                  <GitMerge size={12} aria-hidden="true" />
                  Merge {(finding.duplicates || []).length} Dup{(finding.duplicates || []).length === 1 ? '' : 's'}
                </button>
              )}
              <button
                type="button"
                className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black flex items-center gap-1"
                onClick={handleDismissAsDuplicate}
                aria-label="Mark this finding as a duplicate and dismiss"
                title="Hide this finding from default triage as a duplicate"
              >
                <XCircle size={12} aria-hidden="true" />
                Dismiss as Dup
              </button>
              <button
                type="button"
                className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black flex items-center gap-1"
                onClick={handlePromoteToIndependent}
                aria-label="Promote this finding to an independent entry"
                title="Remove duplicate link and treat as standalone"
              >
                <GitBranch size={12} aria-hidden="true" />
                Promote
              </button>
           </div>
           <button className="btn-primary btn-small uppercase tracking-widest text-[9px] font-black" onClick={onClose}>Acknowledge</button>
        </div>
      </motion.div>
      <SubmitToPlatformDialog
        runId={runId}
        findingId={finding.id}
        findingTitle={finding.title}
        open={submitDialogOpen}
        onClose={() => setSubmitDialogOpen(false)}
        onSubmitted={(res) => {
          if (res.submitted && res.url) {
            toast.success(`Submitted to ${res.platform}: ${res.url}`);
          } else if (res.submitted) {
            toast.success(`Draft saved to ${res.platform}`);
          } else {
            toast.error(`Submission to ${res.platform} failed: ${res.error || 'unknown error'}`);
          }
        }}
      />
    </div>
  );
}
