import { memo } from 'react';
import { Shield, ArrowRight, Zap, Target, AlertTriangle } from 'lucide-react';
import type { AttackChain } from '@/types/api';
import { motion } from 'framer-motion';

export const AttackChainVisualizer = memo(function AttackChainVisualizer({ 
  chains 
}: { 
  chains: AttackChain[] 
}) {
  if (chains.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-muted opacity-30 gap-4">
        <Shield size={48} strokeWidth={1} />
        <p className="text-xs uppercase tracking-[0.2em]">No Kill-Chains Identified</p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {chains.map((chain, idx) => (
        <motion.div 
          key={chain.id}
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: idx * 0.1 }}
          className="glass-panel p-6 rounded-2xl border-l-4 border-l-high relative overflow-hidden"
        >
          <div className="absolute top-0 right-0 p-4 opacity-10">
             <Target size={120} />
          </div>

          <div className="flex items-center justify-between mb-6 relative z-10">
            <div>
              <span className="text-[10px] font-black text-bad uppercase tracking-widest px-2 py-0.5 bg-bad/10 rounded mb-2 inline-block">
                Critical Attack Path
              </span>
              <h3 className="text-lg font-bold text-text uppercase tracking-tighter">{chain.description}</h3>
            </div>
            <div className="text-right">
               <div className="text-2xl font-black text-white">{Math.round(chain.confidence * 100)}%</div>
               <div className="text-[9px] text-muted uppercase font-bold tracking-widest">Confidence</div>
            </div>
          </div>

          <div className="flex items-center gap-4 overflow-x-auto pb-4 scrollbar-cyber relative z-10">
            {chain.steps.map((step, sIdx) => (
              <div key={sIdx} className="flex items-center gap-4 shrink-0">
                <div className="flex flex-col items-center gap-2">
                   <div className={`w-12 h-12 rounded-xl border flex items-center justify-center ${
                     step.severity === 'critical' ? 'bg-bad/10 border-bad/30 text-bad' : 'bg-high/10 border-high/30 text-high'
                   }`}>
                      <Zap size={20} />
                   </div>
                   <div className="text-[9px] font-mono text-muted truncate max-w-[80px]">{step.asset_id}</div>
                </div>
                
                {sIdx < chain.steps.length - 1 && (
                  <div className="flex flex-col items-center gap-1">
                    <ArrowRight size={16} className="text-muted" />
                    <span className="text-[8px] font-black text-accent uppercase tracking-tighter">Pivot</span>
                  </div>
                )}
              </div>
            ))}
          </div>

          <div className="mt-4 p-3 bg-black/40 rounded-lg border border-white/5 flex items-center gap-3">
             <AlertTriangle size={14} className="text-warn" />
             <p className="text-[10px] text-muted font-mono leading-relaxed">
               Tactical Warning: This path utilizes an authenticated logical breach on {chain.steps[0].asset_id} to gain deeper access.
             </p>
          </div>
        </motion.div>
      ))}
    </div>
  );
});
