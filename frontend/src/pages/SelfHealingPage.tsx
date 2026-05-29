import { useEffect, useState, useCallback, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  RefreshCw, 
  Zap, 
  AlertTriangle, 
  Play, 
  Settings, 
  CheckCircle, 
  XCircle, 
  ShieldCheck, 
  Heart, 
  Activity 
} from 'lucide-react';
import { getSelfHealingSnapshot, evaluateSelfHealing, type SelfHealingSnapshot } from '@/api/selfHealing';
import { useToast } from '@/hooks/useToast';

interface StatBlockProps {
  label: string;
  value: string | number;
  colorClass: string;
  icon: React.ReactNode;
}

function StatBlock({ label, value, colorClass, icon }: StatBlockProps) {
  return (
    <div className="glass-panel p-5 rounded-2xl relative overflow-hidden group cyber-glow-card">
      <div className="absolute top-0 right-0 w-20 h-20 bg-white/[0.01] rounded-bl-full pointer-events-none group-hover:bg-white/[0.02] transition-colors" />
      <div className="flex items-center justify-between">
        <div className="min-w-0">
          <span className="text-[10px] font-black text-muted uppercase tracking-widest block mb-1">{label}</span>
          <span className={`text-xl font-black ${colorClass} cyber-text-glow uppercase`}>{value}</span>
        </div>
        <div className={`p-2.5 rounded-xl bg-white/5 border border-white/10 ${colorClass}`}>
          {icon}
        </div>
      </div>
    </div>
  );
}

function RadarGraphic({ status }: { status: string }) {
  const isHealthy = status === 'healthy';
  const radarColor = isHealthy ? 'stroke-ok fill-ok' : status === 'degraded' ? 'stroke-warn fill-warn' : 'stroke-bad fill-bad';
  
  return (
    <div className="glass-panel p-6 rounded-2xl flex flex-col items-center justify-center relative overflow-hidden cyber-glow-card">
      <div className="absolute inset-0 cyber-grid-overlay opacity-30 pointer-events-none" />
      
      {/* Dynamic Animated Radar Screen */}
      <div className="relative w-48 h-48 rounded-full border border-white/5 bg-black/40 overflow-hidden flex items-center justify-center shadow-[inset_0_0_20px_rgba(0,0,0,0.8)]">
        {/* Radar grids */}
        <div className="absolute inset-0 rounded-full border border-white/10 scale-75" />
        <div className="absolute inset-0 rounded-full border border-white/10 scale-50" />
        <div className="absolute inset-0 rounded-full border border-white/15 scale-25" />
        
        {/* Crosshair lines */}
        <div className="absolute w-full h-[1px] bg-white/10" />
        <div className="absolute h-full w-[1px] bg-white/10" />
        
        {/* Rotating sweep */}
        <svg className="absolute inset-0 w-full h-full radar-sweep-indicator pointer-events-none">
          <defs>
            <linearGradient id="radarSweep" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor={isHealthy ? '#10B981' : status === 'degraded' ? '#F59E0B' : '#EF4444'} stopOpacity="0.4" />
              <stop offset="50%" stopColor={isHealthy ? '#10B981' : status === 'degraded' ? '#F59E0B' : '#EF4444'} stopOpacity="0.1" />
              <stop offset="100%" stopColor="transparent" stopOpacity="0" />
            </linearGradient>
          </defs>
          <path d="M 96,96 L 192,96 A 96,96 0 0,0 96,0 Z" fill="url(#radarSweep)" />
        </svg>

        {/* Dynamic scanning blips */}
        <div className={`absolute top-1/4 left-1/3 w-2.5 h-2.5 rounded-full ${radarColor} animate-ping`} />
        <div className={`absolute bottom-1/3 right-1/4 w-2 h-2 rounded-full ${radarColor} opacity-75`} />
        <div className={`absolute top-1/2 right-1/3 w-1.5 h-1.5 rounded-full ${radarColor} opacity-50`} />

        {/* Pulse center core */}
        <div className={`relative w-4 h-4 rounded-full border-2 border-white bg-black flex items-center justify-center shadow-lg ${
          isHealthy ? 'border-ok text-ok' : status === 'degraded' ? 'border-warn text-warn' : 'border-bad text-bad'
        }`}>
          <div className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" />
        </div>
      </div>

      <div className="mt-4 flex items-center gap-2">
        <Activity size={14} className={isHealthy ? 'text-ok animate-pulse' : 'text-warn'} />
        <span className="text-[10px] font-mono font-black uppercase tracking-widest text-muted">
          Active Scan Area Radar
        </span>
      </div>
    </div>
  );
}

export function SelfHealingPage() {
  const [snapshot, setSnapshot] = useState<SelfHealingSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [evaluating, setEvaluating] = useState(false);
  const toast = useToast();

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getSelfHealingSnapshot();
      setSnapshot(data);
    } catch (error) {
      console.error('Failed to load self-healing snapshot:', error);
      toast.error('Failed to load self-healing snapshot');
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleEvaluate = async () => {
    setEvaluating(true);
    try {
      const data = await evaluateSelfHealing();
      setSnapshot(data);
      toast.success('Self-healing evaluation completed successfully');
    } catch (error) {
      console.error('Failed to trigger evaluation:', error);
      toast.error('Failed to trigger evaluation');
    } finally {
      setEvaluating(false);
    }
  };

  const activeFindingsCount = useMemo(() => snapshot?.findings?.length || 0, [snapshot]);
  const isDegraded = snapshot?.status === 'degraded';
  const isHealthy = snapshot?.status === 'healthy';

  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.05 }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 15 },
    show: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 90 } }
  };

  if (loading && !snapshot) {
    return (
      <div className="flex flex-col items-center justify-center py-32 text-muted animate-pulse font-mono text-xs uppercase tracking-widest gap-3">
        <RefreshCw size={24} className="animate-spin text-accent" />
        Establishing Autonomous Link...
      </div>
    );
  }

  return (
    <div className="p-6 md:p-8 bg-bg min-h-full space-y-8 cyber-grid-overlay">
      <header className="flex flex-col md:flex-row md:items-center justify-between gap-6 pb-6 border-b border-white/5">
        <div className="flex items-center gap-4">
          <div className="h-12 w-12 rounded-xl border border-accent/30 bg-accent/10 flex items-center justify-center text-accent shadow-[0_0_15px_rgba(59,130,246,0.2)]">
            <Zap size={26} className="animate-bounce" />
          </div>
          <div>
            <h1 className="text-2xl font-black text-text uppercase tracking-widest mb-1 cyber-text-glow">Self-Healing Command</h1>
            <p className="text-xs text-muted font-mono uppercase tracking-wider flex items-center gap-2">
              <span className="pulse-dot" />
              Autonomous micro-posture recovery controller telemetry
            </p>
          </div>
        </div>
        <div className="flex gap-3">
          <button 
            className="btn btn-secondary flex items-center gap-2 px-4 py-2 text-xs font-bold uppercase tracking-wider bg-white/5 border border-white/10 rounded-lg hover:bg-white/10 hover:border-white/20 transition-all duration-200" 
            onClick={loadData} 
            disabled={loading}
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> 
            Sync Telemetry
          </button>
          <button 
            className="btn btn-primary flex items-center gap-2 px-4 py-2 text-xs font-bold uppercase tracking-wider bg-accent text-black rounded-lg hover:bg-white transition-all duration-200 shadow-[0_0_15px_rgba(59,130,246,0.25)]" 
            onClick={handleEvaluate} 
            disabled={evaluating}
          >
            <Play size={14} className={evaluating ? 'animate-pulse' : ''} /> 
            {evaluating ? 'Evaluating...' : 'Evaluate Now'}
          </button>
        </div>
      </header>

      {snapshot && (
        <motion.div 
          className="space-y-8"
          variants={containerVariants}
          initial="hidden"
          animate="show"
        >
          {/* --- KPI Grid & Radar --- */}
          <div className="grid grid-cols-1 lg:grid-cols-[1fr_240px] gap-6">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <StatBlock
                label="Self-Healing Agent"
                value={snapshot.controller || 'Guardian Core'}
                colorClass="text-accent"
                icon={<Settings size={18} />}
              />
              <StatBlock
                label="System Health Posture"
                value={snapshot.status}
                colorClass={isHealthy ? 'text-ok' : isDegraded ? 'text-warn' : 'text-bad'}
                icon={isHealthy ? <ShieldCheck size={18} /> : <AlertTriangle size={18} />}
              />
              <StatBlock
                label="Active Deficiencies"
                value={activeFindingsCount}
                colorClass={activeFindingsCount > 0 ? 'text-warn' : 'text-ok'}
                icon={<Heart size={18} />}
              />
              <StatBlock
                label="Historical Corrections"
                value={snapshot.corrections?.length || 0}
                colorClass="text-text"
                icon={<Zap size={18} />}
              />
            </div>
            <RadarGraphic status={snapshot.status} />
          </div>

          {/* --- Active Findings & Corrections Lists --- */}
          <div className="grid md:grid-cols-2 gap-8">
            {/* Active Health Findings Column */}
            <section className="glass-panel p-6 rounded-2xl relative overflow-hidden group cyber-glow-card border-l-3 border-l-warn/20">
              <div className="absolute top-0 right-0 w-24 h-24 bg-white/[0.01] -rotate-45 translate-x-12 -translate-y-12 pointer-events-none" />
              <h3 className="text-sm font-black uppercase tracking-widest mb-6 flex items-center gap-2 border-b border-white/5 pb-3 text-text">
                <AlertTriangle size={16} className="text-warn animate-pulse" /> 
                Active Posture Deficiencies
              </h3>
              
              <AnimatePresence mode="popLayout">
                {snapshot.findings && snapshot.findings.length > 0 ? (
                  <div className="space-y-4">
                    {snapshot.findings.map((f: Record<string, unknown>, i: number) => (
                      <motion.div 
                        key={i} 
                        variants={itemVariants}
                        layout
                        className="bg-black/30 p-4 rounded-xl border border-white/5 hover:border-white/10 transition-colors"
                      >
                        <div className="flex justify-between items-center mb-2">
                          <span className="text-[10px] font-mono font-black uppercase tracking-widest text-accent bg-accent/5 px-2 py-0.5 rounded border border-accent/10">
                            {String(f.component)}
                          </span>
                          <span className={`text-[9px] font-black uppercase px-2 py-0.5 rounded ${
                            String(f.status) === 'critical' ? 'bg-bad text-white' : 'bg-warn/10 text-warn border border-warn/25'
                          }`}>
                            {String(f.status)}
                          </span>
                        </div>
                        <p className="text-xs text-muted-foreground leading-relaxed text-left">{String(f.reason)}</p>
                      </motion.div>
                    ))}
                  </div>
                ) : (
                  <motion.div 
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 0.6 }}
                    className="py-12 text-center text-muted italic flex flex-col items-center gap-2"
                  >
                    <ShieldCheck size={28} className="text-ok" />
                    <span className="text-xs uppercase font-mono tracking-wider">All Systems Operational</span>
                  </motion.div>
                )}
              </AnimatePresence>
            </section>

            {/* Recent Corrections Column */}
            <section className="glass-panel p-6 rounded-2xl relative overflow-hidden group cyber-glow-card border-l-3 border-l-accent/20">
              <div className="absolute top-0 right-0 w-24 h-24 bg-white/[0.01] -rotate-45 translate-x-12 -translate-y-12 pointer-events-none" />
              <h3 className="text-sm font-black uppercase tracking-widest mb-6 flex items-center gap-2 border-b border-white/5 pb-3 text-text">
                <Settings size={16} className="text-accent animate-pulse" /> 
                Autonomous Corrections Journal
              </h3>
              
              <AnimatePresence mode="popLayout">
                {snapshot.corrections && snapshot.corrections.length > 0 ? (
                  <div className="space-y-4 max-h-[440px] overflow-y-auto scrollbar-cyber pr-2">
                    {snapshot.corrections.map((c: Record<string, unknown>, i: number) => (
                      <motion.div 
                        key={i} 
                        variants={itemVariants}
                        layout
                        className="bg-black/30 p-4 rounded-xl border border-white/5 hover:border-white/10 transition-colors"
                      >
                        <div className="flex justify-between items-center mb-2">
                          <span className="text-[10px] font-mono font-black uppercase tracking-wider text-text truncate max-w-[180px]" title={String(c.action)}>
                            {String(c.action)}
                          </span>
                          <span className={`text-[9px] font-black uppercase flex items-center gap-1 ${
                            c.success ? 'text-ok' : 'text-bad'
                          }`}>
                            {c.success ? (
                              <><CheckCircle size={10} /> SUCCESS</>
                            ) : (
                              <><XCircle size={10} /> FAILED</>
                            )}
                          </span>
                        </div>
                        <p className="text-xs text-muted-foreground leading-relaxed text-left mb-3">{String(c.message)}</p>
                        <div className="text-[9px] font-mono text-muted/60">{new Date(Number(c.executed_at) * 1000).toLocaleString()}</div>
                      </motion.div>
                    ))}
                  </div>
                ) : (
                  <motion.div 
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 0.6 }}
                    className="py-12 text-center text-muted italic flex flex-col items-center gap-2"
                  >
                    <Settings size={28} />
                    <span className="text-xs uppercase font-mono tracking-wider">No Corrections Logged</span>
                  </motion.div>
                )}
              </AnimatePresence>
            </section>
          </div>
        </motion.div>
      )}
    </div>
  );
}
