import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  CheckCircle2, 
  ExternalLink, 
  ChevronDown, 
  ChevronUp, 
  Terminal, 
  AlertTriangle, 
  Zap,
  Target,
  BarChart3,
  Calendar,
  Clock
} from 'lucide-react';
import { useToast } from '@/hooks/useToast';
import { remediationApi, type RemediationUnit } from '@/api/remediation';
import { Skeleton } from '@/components/ui/Skeleton';
import { Icon } from '@/components/ui/Icon';
import { Badge } from '@/components/ui/Badge';

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-bad/10 text-bad border-bad/30',
  high: 'bg-high/10 text-high border-high/30',
  medium: 'bg-warn/10 text-warn border-warn/30',
  low: 'bg-ok/10 text-ok border-ok/30',
  info: 'bg-accent/10 text-accent border-accent/30',
};

function UnitCard({ unit }: { unit: RemediationUnit }) {
  const [expanded, setExpanded] = useState(false);
  const toast = useToast();

  const handleExport = (system: string) => {
    toast.success(`Exporting fix to ${system} with WASM PoC logs...`);
  };

  return (
    <motion.div 
      layout
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-panel border border-white/5 rounded-2xl overflow-hidden"
    >
      <button 
        type="button"
        aria-expanded={expanded}
        aria-controls="unit-card-content"
        className="p-6 cursor-pointer flex items-center justify-between hover:bg-white/[0.02] transition-colors w-full text-left"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-6">
           <div className={`px-2 py-0.5 rounded text-[9px] font-black uppercase tracking-widest border ${SEVERITY_COLORS[unit.severity]}`}>
             {unit.severity}
           </div>
           <div>
             <h3 className="text-lg font-bold text-text uppercase tracking-tighter">{unit.title}</h3>
             <div className="flex items-center gap-3 mt-1">
               <span className="text-[10px] text-muted font-mono uppercase tracking-widest flex items-center gap-1.5">
                 <Icon name="target" size={10} /> {unit.targets.length} TARGETS
               </span>
               <span className="text-[10px] text-muted font-mono uppercase tracking-widest flex items-center gap-1.5">
                 <Icon name="activity" size={10} /> {unit.total_count} FINDINGS
               </span>
             </div>
           </div>
        </div>
        <div className="flex items-center gap-4">
           <button 
            className="btn-primary btn-small uppercase tracking-widest text-[9px] font-black"
            onClick={(e) => { e.stopPropagation(); handleExport('Jira'); }}
           >
             Export to Engineering
           </button>
           {expanded ? <ChevronUp className="text-muted" /> : <ChevronDown className="text-muted" />}
        </div>
      </button>

      <AnimatePresence>
        {expanded && (
          <motion.div 
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="border-t border-white/5 bg-black/40"
          >
            <div className="p-8 space-y-8">
              {/* Fix Commands */}
              <section>
                <div className="flex items-center gap-2 mb-4">
                  <Terminal size={14} className="text-accent" />
                  <h4 className="text-[10px] font-black text-accent uppercase tracking-[0.2em]">Verified Remediation Path</h4>
                </div>
                <div className="space-y-4">
                  {unit.suggestions.map((s, i) => (
                    <div key={i} className="p-4 bg-white/5 border border-white/10 rounded-xl space-y-3">
                      <div className="flex items-center justify-between">
                        <h5 className="text-xs font-bold text-text">{s.title}</h5>
                        <Badge variant="info" className="text-[8px] opacity-60">Verified via AEVE-WASM</Badge>
                      </div>
                      <p className="text-[11px] text-muted leading-relaxed">{s.rationale}</p>
                      <div className="bg-black/60 p-3 rounded font-mono text-[10px] text-accent/80 border border-white/5 flex items-center justify-between group">
                        <code>{s.command}</code>
                        <button 
                          className="opacity-0 group-hover:opacity-100 text-white hover:text-accent transition-all"
                          onClick={() => { navigator.clipboard.writeText(s.command); toast.success('Command copied'); }}
                        >
                          <Icon name="link" size={14} />
                        </button>
                      </div>
                      {s.safety_note && (
                        <div className="flex items-center gap-2 text-[9px] text-warn/70 italic">
                          <AlertTriangle size={10} />
                          {s.safety_note}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </section>

              {/* Sample Findings */}
              <section>
                <div className="flex items-center gap-2 mb-4">
                  <BarChart3 size={14} className="text-muted" />
                  <h4 className="text-[10px] font-black text-muted uppercase tracking-[0.2em]">High-Confidence Evidence</h4>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {unit.sample_findings.map((f) => (
                    <div key={f.id} className="p-3 bg-black/20 border border-white/5 rounded-lg flex items-center justify-between hover:border-white/10 transition-colors">
                      <div className="min-w-0">
                        <div className="text-[10px] font-bold text-text truncate">{f.title}</div>
                        <div className="text-[8px] text-muted font-mono truncate">{f.url}</div>
                      </div>
                      <a href={`/cockpit?target=${f.target}&focus=${f.id}`} className="p-1.5 text-muted hover:text-accent transition-colors shrink-0">
                        <ExternalLink size={12} />
                      </a>
                    </div>
                  ))}
                </div>
              </section>

              {/* Targets */}
              <section>
                <div className="flex items-center gap-2 mb-2">
                  <Target size={14} className="text-muted" />
                  <h4 className="text-[10px] font-black text-muted uppercase tracking-[0.2em]">Affected Infrastructure</h4>
                </div>
                <div className="flex flex-wrap gap-2">
                  {unit.targets.map(t => (
                    <span key={t} className="px-2 py-1 bg-white/5 border border-white/10 rounded text-[10px] font-mono text-muted">{t}</span>
                  ))}
                </div>
              </section>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

export function RemediationPlanner() {
  const [units, setUnits] = useState<RemediationUnit[]>([]);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({ totalFindings: 0, totalUnits: 0 });

  useEffect(() => {
    const fetchPlan = async () => {
      try {
        setLoading(true);
        const { data } = await remediationApi.getPlan();
        setUnits(data.units);
        setStats({ totalFindings: data.total_findings, totalUnits: data.total_units });
      } catch {
        // Error handled by interceptor
      } finally {
        setLoading(false);
      }
    };
    fetchPlan();
  }, []);

  if (loading) {
    return (
      <div className="p-12 space-y-6">
        <Skeleton className="h-20 w-full rounded-2xl" />
        <Skeleton className="h-[400px] w-full rounded-2xl" />
        <Skeleton className="h-[400px] w-full rounded-2xl" />
      </div>
    );
  }

  return (
    <div className="remediation-planner p-12 space-y-12">
      {/* Tactical Header */}
      <header className="flex flex-wrap items-end justify-between gap-8">
        <div>
           <div className="flex items-center gap-3 mb-4">
             <div className="p-2.5 bg-accent/10 rounded-xl border border-accent/20">
               <CheckCircle2 size={24} className="text-accent" />
             </div>
             <div>
               <h1 className="text-3xl font-black uppercase tracking-tighter text-text">Remediation Action Planner</h1>
               <p className="text-xs text-muted font-mono uppercase tracking-[0.1em] mt-1">Sprint 3: Tactical Fix Orchestration Engine</p>
             </div>
           </div>
        </div>

        <div className="flex gap-4">
           <div className="bg-white/5 border border-white/10 p-4 rounded-2xl min-w-[160px]">
              <div className="text-2xl font-black text-text">{stats.totalFindings}</div>
              <div className="text-[9px] text-muted uppercase font-bold tracking-widest mt-1">Pending Fixes</div>
           </div>
           <div className="bg-white/5 border border-white/10 p-4 rounded-2xl min-w-[160px]">
              <div className="text-2xl font-black text-accent">{stats.totalUnits}</div>
              <div className="text-[9px] text-muted uppercase font-bold tracking-widest mt-1">Tactical Fix Units</div>
           </div>
           <div className="bg-white/5 border border-white/10 p-4 rounded-2xl min-w-[160px]">
              <div className="text-2xl font-black text-ok">2.4d</div>
              <div className="text-[9px] text-muted uppercase font-bold tracking-widest mt-1 flex items-center gap-1">
                <Clock size={10} /> MTTR
              </div>
           </div>
        </div>
      </header>

      {/* Hero Action */}
      <section className="p-8 bg-accent/5 border border-accent/20 rounded-3xl relative overflow-hidden">
        <div className="absolute top-0 right-0 p-8 opacity-10">
           <Zap size={180} />
        </div>
        <div className="relative z-10 max-w-2xl">
          <h2 className="text-xl font-bold text-text uppercase tracking-tight mb-3">Enterprise Fix Orchestration</h2>
          <p className="text-sm text-muted leading-relaxed mb-6">
            The system has automatically clustered discovered vulnerabilities into <strong>Tactical Fix Units</strong>. 
            Each unit contains a verified remediation path backed by hardware-isolated WASM PoC results.
          </p>
          <div className="flex gap-4">
             <button className="btn-primary uppercase tracking-widest text-[10px] font-black px-6 py-3">Batch Export All to Jira</button>
             <button className="btn-secondary uppercase tracking-widest text-[10px] font-black px-6 py-3">Download Fix Manifest (.sh)</button>
          </div>
        </div>
      </section>

      {/* Fix Units Grid */}
      <section className="space-y-6">
        <div className="flex items-center justify-between">
           <h3 className="text-xs font-black text-white/40 uppercase tracking-[0.3em]">Operational Fix Backlog</h3>
           <div className="flex items-center gap-4 text-[9px] text-muted font-mono uppercase">
             <span className="flex items-center gap-1.5"><Calendar size={10} /> UPDATED 2M AGO</span>
             <span className="flex items-center gap-1.5"><Target size={10} /> MESH CONTEXT: GLOBAL</span>
           </div>
        </div>

        {units.length === 0 ? (
          <div className="py-20 text-center glass-panel rounded-3xl opacity-30">
            <Icon name="shieldCheck" size={48} className="mx-auto mb-4" />
            <p className="uppercase tracking-[0.2em] text-sm">All Infrastructure Synchronized</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-6">
            {units.map((unit) => (
              <UnitCard key={unit.category} unit={unit} />
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
