import { useEffect, useState } from 'react';
import { Shield, X } from 'lucide-react';
import { motion } from 'framer-motion';
import type { Finding, RemediationSuggestion, EvidenceItem } from '../../../types/api';
import { getFindingRemediation } from '../../../api/client';
import { EvidenceDisplay } from '../../../components/EvidenceDisplay';

export type DetailTab = 'cvss' | 'csi' | 'evidence' | 'request' | 'logic' | 'comments';

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

  useEffect(() => {
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [onClose]);

  useEffect(() => {
    if (!detailFinding.id) return;
    setLoadingRemediation(true);
    getFindingRemediation(detailFinding.id)
      .then((res) => {
        setRemediation(res.suggestions || []);
        setLoadingRemediation(false);
      })
      .catch(() => {
        setRemediation([]);
        setLoadingRemediation(false);
      });
  }, [detailFinding.id]);

  const isLogicBreach = detailFinding.type?.startsWith('logic_breach');

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
    >
      <motion.div 
        initial={{ opacity: 0, scale: 0.9, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        className="w-full max-w-4xl max-h-[90vh] bg-bg border border-white/10 rounded-3xl shadow-[0_0_50px_rgba(0,0,0,0.5)] overflow-hidden flex flex-col"
        onClick={e => e.stopPropagation()}
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
                 <div className="text-sm font-black text-text uppercase mt-2">{detailFinding.lifecycle_state}</div>
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
           </div>
        </div>

        {/* Footer Actions */}
        <div className="px-8 py-6 bg-white/5 border-t border-white/5 flex justify-between items-center">
           <div className="flex gap-4">
              <button className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black">Flag False Positive</button>
              <button className="btn-secondary btn-small uppercase tracking-widest text-[9px] font-black">Retest Link</button>
           </div>
           <button className="btn-primary btn-small uppercase tracking-widest text-[9px] font-black" onClick={onClose}>Acknowledge</button>
        </div>
      </motion.div>
    </div>
  );
}
