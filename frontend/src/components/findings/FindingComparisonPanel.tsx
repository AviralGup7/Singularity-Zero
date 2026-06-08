import { useMemo } from 'react';
import { motion } from 'framer-motion';
import { X, ArrowUpDown, Bug, DollarSign, Shield, TrendingUp } from 'lucide-react';
import type { Finding } from '@/types/api';

interface FindingComparisonPanelProps {
  findingA: Finding;
  findingB: Finding;
  onClose: () => void;
}

function getCVSS(f: Finding): number {
  return f.cvss_v4_score ?? f.cvss_score ?? (typeof f.cvss === 'number' ? f.cvss : 0) || 0;
}

function getEpss(f: Finding): number {
  return f.threat_intel?.epss_score ?? f.epss_score ?? 0;
}

function getBounty(f: Finding): number {
  return f.bounty_value || 0;
}

export function FindingComparisonPanel({ findingA, findingB, onClose }: FindingComparisonPanelProps) {
  const diffFields = useMemo(() => {
    const fields: Array<{
      label: string;
      icon: React.ReactNode;
      a: string | number;
      b: string | number;
      diff: 'higher' | 'lower' | 'same';
    }> = [];

    const addField = (label: string, icon: React.ReactNode, valA: number, valB: number, fmt?: (v: number) => string) => {
      const fmtVal = (v: number) => fmt ? fmt(v) : String(v);
      fields.push({
        label,
        icon,
        a: fmtVal(valA),
        b: fmtVal(valB),
        diff: valA > valB ? 'higher' : valA < valB ? 'lower' : 'same',
      });
    };

    const sevOrder: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
    const sevA = sevOrder[findingA.severity] ?? 0;
    const sevB = sevOrder[findingB.severity] ?? 0;
    addField('Severity', <Shield size={14} />, sevA, sevB, (v) => Object.entries(sevOrder).find(([, o]) => o === v)?.[0] ?? 'unknown');
    addField('CVSS Score', <TrendingUp size={14} />, getCVSS(findingA), getCVSS(findingB), (v) => v.toFixed(1));
    addField('EPSS %', <Bug size={14} />, getEpss(findingA) * 100, getEpss(findingB) * 100, (v) => `${v.toFixed(1)}%`);
    addField('Bounty Value', <DollarSign size={14} />, getBounty(findingA), getBounty(findingB), (v) => `$${v.toLocaleString()}`);

    return fields;
  }, [findingA, findingB]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: 20 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
    >
      <div className="w-full max-w-4xl rounded-2xl border border-accent/20 bg-bg p-6 shadow-xl space-y-4 max-h-[80vh] overflow-y-auto">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold uppercase tracking-wider text-accent flex items-center gap-2">
            <ArrowUpDown size={16} /> Finding Comparison
          </h3>
          <button type="button" onClick={onClose} className="p-1 rounded hover:bg-white/5 text-muted hover:text-white transition-colors cursor-pointer">
            <X size={16} />
          </button>
        </div>

        <div className="grid grid-cols-[1fr_auto_1fr] gap-4">
          <div className="p-4 rounded-xl border border-white/10 bg-white/5 space-y-2">
            <div className="text-[10px] font-black uppercase tracking-widest text-muted">Finding A</div>
            <div className="text-sm font-bold text-text truncate">{findingA.title}</div>
            <div className="text-[10px] font-mono text-muted truncate">{findingA.target || findingA.host || '—'}</div>
            <div className="text-[10px] font-mono text-muted">CVE: {findingA.cve || 'N/A'} · CWE: {findingA.cwe || 'N/A'}</div>
          </div>

          <div className="flex items-center justify-center">
            <div className="p-2 rounded-full bg-accent/20 text-accent">
              <ArrowUpDown size={20} />
            </div>
          </div>

          <div className="p-4 rounded-xl border border-white/10 bg-white/5 space-y-2">
            <div className="text-[10px] font-black uppercase tracking-widest text-muted">Finding B</div>
            <div className="text-sm font-bold text-text truncate">{findingB.title}</div>
            <div className="text-[10px] font-mono text-muted truncate">{findingB.target || findingB.host || '—'}</div>
            <div className="text-[10px] font-mono text-muted">CVE: {findingB.cve || 'N/A'} · CWE: {findingB.cwe || 'N/A'}</div>
          </div>
        </div>

        <div className="space-y-2">
          {diffFields.map((field) => (
            <div key={field.label} className="grid grid-cols-[1fr_auto_1fr] gap-4 items-center p-3 rounded-lg bg-white/[0.02] border border-white/5">
              <div className={`text-center text-sm font-mono font-bold ${field.diff === 'higher' ? 'text-accent' : field.diff === 'lower' ? 'text-muted' : 'text-text'}`}>
                {field.a}
              </div>
              <div className="flex items-center gap-2 text-[10px] font-black uppercase tracking-widest text-muted justify-center">
                {field.icon}
                <span>{field.label}</span>
              </div>
              <div className={`text-center text-sm font-mono font-bold ${field.diff === 'lower' ? 'text-accent' : field.diff === 'higher' ? 'text-muted' : 'text-text'}`}>
                {field.b}
              </div>
            </div>
          ))}
        </div>

        {findingA.attack_chain || findingB.attack_chain ? (
          <div className="p-3 rounded-lg bg-accent/5 border border-accent/20">
            <div className="text-[10px] font-black uppercase tracking-widest text-accent mb-1">Attack Chain context</div>
            <div className="text-xs text-muted">
              {findingA.attack_chain ? `Finding A is part of chain ${findingA.attack_chain.chain_id} (${findingA.attack_chain.chain_kind})` : 'Finding A: No chain'}
              {' · '}
              {findingB.attack_chain ? `Finding B is part of chain ${findingB.attack_chain.chain_id} (${findingB.attack_chain.chain_kind})` : 'Finding B: No chain'}
            </div>
          </div>
        ) : null}
      </div>
    </motion.div>
  );
}
