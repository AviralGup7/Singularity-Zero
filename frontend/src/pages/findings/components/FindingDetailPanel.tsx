import React, { useEffect, useState } from 'react';
import { Shield, X, Zap } from 'lucide-react';
import { motion } from 'framer-motion';
import type { Finding, RemediationSuggestion, EvidenceItem, AttackChain } from '../../../types/api';
import { getFindingRemediation } from '../../../api/client';
import { useToast } from '../../../hooks/useToast';
import { EvidenceDisplay } from '../../../components/EvidenceDisplay';
import { AttackChainVisualizer } from '../../../components/AttackChainVisualizer';
import { FindingComments } from '../../../components/FindingComments';
import { RequestResponseViewer } from '../../../components/RequestResponseViewer';
import { useTriageCollaboration } from '@/hooks/useTriageCollaboration';

export type DetailTab = 'cvss' | 'csi' | 'evidence' | 'simulation' | 'request' | 'logic' | 'comments';

interface ExtendedEvidence {
  chain_simulation?: AttackChain;
  replay?: { id: string };
  [key: string]: unknown;
}

export function FindingDetailPanel({
  finding: detailFinding,
  onClose,
}: {
  finding: Finding;
  onClose: () => void;
}) {
   
  const [detailTab, setDetailTab] = useState<DetailTab>('csi');
   
  const [remediation, setRemediation] = useState<RemediationSuggestion[]>([]);
   
  const [loadingRemediation, setLoadingRemediation] = useState(false);
  const toast = useToast();

  useEffect(() => {
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
   
  }, [onClose]);

  useEffect(() => {
    if (!detailFinding.id) return;
    let mounted = true;
    
    // Defer the initial loading state update
    Promise.resolve().then(() => {
      if (mounted) setLoadingRemediation(true);
    });

    getFindingRemediation(detailFinding.id)
      .then((res) => {
        if (mounted) {
          setRemediation(res.suggestions || []);
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
   
  }, [detailFinding.id]);

  const isLogicBreach = detailFinding.type?.startsWith('logic_breach');

  const evidence = detailFinding.evidence as ExtendedEvidence | undefined;
  const runId = String(
    detailFinding.metadata?.run_name
    || detailFinding.metadata?.job_id
    || detailFinding.target
    || 'global'
  );
  const triage = useTriageCollaboration(runId, detailFinding.id);
  const triageStatus = triage.state?.status || detailFinding.lifecycle_state || 'open';

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

  const chainSimulation: AttackChain | null = (detailFinding.metadata?.chain_simulation as AttackChain) || 
                                              evidence?.chain_simulation || 
                                              null;

  const evidenceItems: EvidenceItem[] = detailFinding.evidence ? [{
    id: `ev-${detailFinding.id}`,
    timestamp: typeof detailFinding.timestamp === 'number' ? new Date(detailFinding.timestamp * 1000).toISOString() : String(detailFinding.timestamp),
    source: 'Neural-Mesh Detection',
    description: detailFinding.title,
    raw_data: JSON.stringify(detailFinding.evidence, null, 2),
    data_type: 'json'
  }] : [];

  return (
    <div 
      className="fixed inset-0 z-[10000] flex items-center justify-center bg-black/60 backdrop-blur-md p-4" 
      onClick={onClose}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') onClose(); }}
      tabIndex={0}
      role="button"
      aria-label="Close detail panel"
    >
      <motion.div 
        initial={{ opacity: 0, scale: 0.9, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        className="w-full max-w-4xl max-h-[90vh] bg-bg border border-white/10 rounded-3xl shadow-[0_0_50px_rgba(0,0,0,0.5)] overflow-hidden flex flex-col"
        onClick={(e: React.MouseEvent) => e.stopPropagation()}
        onKeyDown={(e: React.KeyboardEvent) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby="finding-detail-title"
      >
        {/* Header */}
        <div className="px-8 py-6 border-b border-white/5 flex items-center justify-between bg-white/5">
          <div className="flex items-center gap-4">
             <div className={`p-3 rounded-xl border ${
               detailFinding.severity === 'critical' ? 'bg-bad/10 border-bad/20 text-bad' : 'bg-accent/10 border-accent/20 text-accent'
             }`}>
                <Shield size={24} />
             </div>
             <div>
                <h3 id="finding-detail-title" className="text-xl font-black text-text uppercase tracking-tighter">{detailFinding.title}</h3>
                <div className="flex items-center gap-3 text-[10px] text-muted font-mono uppercase tracking-widest mt-1">
                   <span>ID: {detailFinding.id}</span>
                   <span>•</span>
                   <span>Target: {detailFinding.target}</span>
                </div>
             </div>
          </div>
          <button className="text-muted hover:text-white transition-colors" onClick={onClose} aria-label="Close panel"><X size={20} /></button>
        </div>

        {/* Info Grid */}
        <div className="flex-1 overflow-y-auto p-8 space-y-8 scrollbar-cyber">
           <div className="grid grid-cols-4 gap-4">
              <div className="glass-panel p-4 rounded-xl">
                 <div className="text-[9px] font-black text-muted uppercase mb-1 tracking-widest">CSI Index</div>
                 <div className="text-2xl font-black text-accent">{detailFinding.csi_score || 'N/A'}</div>
              </div>
              <div className="glass-panel p-4 rounded-xl">
                 <div className="text-[9px] font-black text-muted uppercase mb-1 tracking-widest">Confidence</div>
                 <div className="text-2xl font-black text-white">{Math.round(detailFinding.confidence * 100)}%</div>
              </div>
              <div className="glass-panel p-4 rounded-xl">
                 <div className="text-[9px] font-black text-muted uppercase mb-1 tracking-widest">State</div>
                 <div className="text-sm font-black text-text uppercase mt-2">{triageStatus}</div>
              </div>
              <div className="glass-panel p-4 rounded-xl">
                 <div className="text-[9px] font-black text-muted uppercase mb-1 tracking-widest">Severity</div>
                 <div className={`text-sm font-black uppercase mt-2 ${
                   detailFinding.severity === 'critical' ? 'text-bad' : 'text-accent'
                 }`}>{detailFinding.severity}</div>
              </div>
           </div>

           {/* Tabs */}
           <div className="flex gap-6 border-b border-white/5">
              {[
                { id: 'csi', label: 'Analysis' },
                { id: 'evidence', label: 'Evidence' },
                { id: 'simulation', label: 'Simulation', hide: !chainSimulation },
                { id: 'request', label: 'Payloads' },
                { id: 'logic', label: 'Logic Diff', hide: !isLogicBreach },
                { id: 'comments', label: 'Intelligence' },
              ].map(tab => !tab.hide && (
                <button 
                  key={tab.id}
                  onClick={() => setDetailTab(tab.id as DetailTab)}
   
                  className={`pb-4 text-[10px] font-black uppercase tracking-widest border-b-2 transition-all ${
                    detailTab === tab.id ? 'border-accent text-white' : 'border-transparent text-muted hover:text-text'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
           </div>

           <div className="min-h-[300px]">
              {detailTab === 'csi' && (
                <div className="space-y-6">
                   <p className="text-sm text-text/80 leading-relaxed italic border-l-2 border-accent/20 pl-4">
                     {detailFinding.description}
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
                      {detailFinding.logic_diff || 'No structural diff recorded for this signal.'}
                   </pre>
                </div>
              )}
              
              {detailTab === 'evidence' && (
                <EvidenceDisplay evidence={evidenceItems} />
              )}

              {detailTab === 'request' && (
                <RequestResponseViewer pairs={detailFinding.request_response || []} />
              )}

              {detailTab === 'comments' && (
                <div className="glass-panel p-6 rounded-2xl border border-white/5">
                  <FindingComments findingId={detailFinding.id} targetName={detailFinding.target} runId={runId} />
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
                            Neural-mesh correlation identified a potential multi-stage attack path based on this finding.
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
                  const runName = detailFinding.metadata?.run_name || detailFinding.metadata?.job_id || '';
                  const replayId = detailFinding.metadata?.replay_id || evidence?.replay?.id || '';
                  window.location.href = `/replay?target=${detailFinding.target}&run=${runName}&replay_id=${replayId}`;
                }}
              >
                Replay with Diff
              </button>
              <button 
                className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black"
                onClick={() => {
                  window.location.href = `/cockpit?target=${detailFinding.target}&focus=${detailFinding.id}`;
                }}
              >
                View in 3D Cockpit
              </button>
              <button 
                className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black"
                onClick={async () => {
                  if (!detailFinding.target || !detailFinding.url) {
                    toast.error('Missing target or URL for forensic probing');
                    return;
                  }
                  try {
                    const { cockpitApi } = await import('@/api/cockpit');
                    await cockpitApi.triggerProbe(detailFinding.target, detailFinding.url);
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
                    severity: detailFinding.severity,
                    confidence: detailFinding.confidence,
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
                    category: String(detailFinding.metadata?.category || detailFinding.type || detailFinding.metadata?.module || 'manual_triage'),
                    status_code: detailFinding.metadata?.response_status || detailFinding.metadata?.status_code,
                    description: detailFinding.description,
                    evidence: JSON.stringify(detailFinding.evidence || {}),
                  },
                  'False-positive pattern shared with the mesh',
                  'Unable to record false-positive triage',
                )}
                disabled={triageStatus === 'false_positive'}
              >
                Flag False Positive
              </button>
           </div>
           <button className="btn-primary btn-small uppercase tracking-widest text-[9px] font-black" onClick={onClose}>Acknowledge</button>
        </div>
      </motion.div>
    </div>
  );
}
