import { useEffect, useState, useCallback, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  RefreshCw, 
  ShieldAlert, 
  Trash2, 
  Target as TargetIcon, 
  Zap, 
  Shield, 
  TrendingUp, 
  CheckCircle,
  AlertTriangle 
} from 'lucide-react';
import { getEvasionMetrics, resetEvasionMetrics, type EvasionMetricsResponse } from '@/api/evasion';
import { useToast } from '@/hooks/useToast';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle: string;
  icon: React.ReactNode;
  colorClass: string;
}

function StatCard({ title, value, subtitle, icon, colorClass }: StatCardProps) {
  return (
    <div className="glass-panel p-5 rounded-2xl relative overflow-hidden group cyber-glow-card">
      <div className="absolute top-0 right-0 w-24 h-24 bg-white/[0.01] rounded-bl-full pointer-events-none group-hover:bg-white/[0.02] transition-colors" />
      <div className="flex justify-between items-start mb-3">
        <div>
          <span className="text-[10px] font-black text-muted uppercase tracking-widest block mb-1">{title}</span>
          <span className={`text-2xl font-black ${colorClass} cyber-text-glow`}>{value}</span>
        </div>
        <div className={`p-2 rounded-lg bg-white/5 border border-white/10 ${colorClass}`}>
          {icon}
        </div>
      </div>
      <p className="text-xs text-muted/70 leading-relaxed italic">{subtitle}</p>
    </div>
  );
}

export function EvasionMetricsPage() {
  const [data, setData] = useState<EvasionMetricsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [resetting, setResetting] = useState(false);
  const toast = useToast();

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const response = await getEvasionMetrics();
      setData(response);
    } catch {
      toast.error('Failed to load evasion metrics');
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleReset = async () => {
    if (!window.confirm('Are you sure you want to reset all evasion metrics?')) return;
    setResetting(true);
    try {
      await resetEvasionMetrics();
      toast.success('Metrics reset successfully');
      await loadData();
    } catch {
      toast.error('Failed to reset metrics');
    } finally {
      setResetting(false);
    }
  };

  const metricsArray = useMemo(() => (data ? Object.entries(data.metrics) : []), [data]);

  // Aggregate stats calculations
  const aggregates = useMemo(() => {
    if (metricsArray.length === 0) return { totalRequests: 0, totalSuccesses: 0, averageRate: 0 };
    const totalRequests = metricsArray.reduce((sum, [, m]) => sum + m.total_requests, 0);
    const totalSuccesses = metricsArray.reduce((sum, [, m]) => sum + m.successes, 0);
    const averageRate = totalRequests > 0 ? (totalSuccesses / totalRequests) * 100 : 0;
    return { totalRequests, totalSuccesses, averageRate };
  }, [metricsArray]);

  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.08 }
    }
  };

  const cardVariants = {
    hidden: { opacity: 0, y: 15 },
    show: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 80 } }
  };

  return (
    <div className="p-6 md:p-8 bg-bg min-h-full space-y-8 cyber-grid-overlay">
      <header className="flex flex-col md:flex-row md:items-center justify-between gap-6 pb-6 border-b border-white/5">
        <div className="flex items-center gap-4">
          <div className="h-12 w-12 rounded-xl border border-accent/30 bg-accent/10 flex items-center justify-center text-accent shadow-[0_0_15px_rgba(59,130,246,0.2)] animate-pulse">
            <ShieldAlert size={26} />
          </div>
          <div>
            <h1 className="text-2xl font-black text-text uppercase tracking-widest mb-1 cyber-text-glow">Evasion Telemetry</h1>
            <p className="text-xs text-muted font-mono uppercase tracking-wider flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-ok animate-ping" />
              Chameleon WAF evasion benchmarks and bypass indicators
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button 
            className="btn btn-secondary flex items-center gap-2 px-4 py-2 text-xs font-bold uppercase tracking-wider bg-white/5 border border-white/10 rounded-lg hover:bg-white/10 hover:border-white/20 transition-all duration-200" 
            onClick={loadData} 
            disabled={loading}
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> 
            Sync Telemetry
          </button>
          <button 
            className="btn btn-secondary flex items-center gap-2 px-4 py-2 text-xs font-bold uppercase tracking-wider text-bad border border-bad/30 bg-bad/5 rounded-lg hover:bg-bad/10 hover:border-bad/50 transition-all duration-200" 
            onClick={handleReset} 
            disabled={resetting || loading}
          >
            <Trash2 size={14} /> 
            Reset Database
          </button>
        </div>
      </header>

      {/* --- Aggregate Analytics Cards --- */}
      {metricsArray.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 animate-fadeIn">
          <StatCard
            title="Overall Evasion Bypass"
            value={`${aggregates.averageRate.toFixed(1)}%`}
            subtitle="Combined success rate across all registered active testing zones."
            icon={<TrendingUp size={18} />}
            colorClass={aggregates.averageRate >= 80 ? 'text-ok' : aggregates.averageRate >= 50 ? 'text-warn' : 'text-bad'}
          />
          <StatCard
            title="Total Deflections"
            value={aggregates.totalSuccesses}
            subtitle="Identified WAF bypass patterns successfully executed."
            icon={<Shield size={18} />}
            colorClass="text-accent"
          />
          <StatCard
            title="Total Payloads Dispatched"
            value={aggregates.totalRequests}
            subtitle="Global volume of adaptive mutations deployed."
            icon={<Zap size={18} />}
            colorClass="text-text"
          />
        </div>
      )}

      {/* --- Main Evasion Targets Grid --- */}
      {loading && !data ? (
        <div className="flex flex-col items-center justify-center py-24 text-muted animate-pulse font-mono text-xs uppercase tracking-widest gap-3">
          <RefreshCw size={24} className="animate-spin text-accent" />
          Synchronizing Chameleon Evasion Nodes...
        </div>
      ) : metricsArray.length === 0 ? (
        <div className="py-20 text-center text-muted italic bg-white/[0.02] rounded-2xl border border-white/5 p-8 max-w-2xl mx-auto flex flex-col items-center gap-4">
          <AlertTriangle size={36} className="text-warn animate-bounce" />
          <div>
            <h3 className="text-sm font-bold uppercase tracking-wider text-text mb-1">No Telemetry Recorded</h3>
            <p className="text-xs text-muted/70 max-w-sm leading-relaxed">
              No WAF bypass datasets are active. Trigger a scanner run with Chameleon Evasion mechanisms enabled.
            </p>
          </div>
        </div>
      ) : (
        <motion.div 
          className="grid gap-6 md:grid-cols-2 lg:grid-cols-3"
          variants={containerVariants}
          initial="hidden"
          animate="show"
        >
          <AnimatePresence mode="popLayout">
            {metricsArray.map(([target, metrics]) => {
              const rate = metrics.evasion_success_rate;
              const isOptimal = rate >= 80;
              const isPartial = rate >= 50 && rate < 80;
              
              const toneClass = isOptimal ? 'ok' : isPartial ? 'warn' : 'bad';
              const borderAccentColor = isOptimal ? 'rgba(16,185,129,0.2)' : isPartial ? 'rgba(245,158,11,0.2)' : 'rgba(239,68,68,0.2)';
              
              // Circle gauge calculations
              const radius = 36;
              const circumference = 2 * Math.PI * radius;
              const strokeOffset = circumference - (Math.min(100, Math.max(0, rate)) / 100) * circumference;

              return (
                <motion.div
                  key={target}
                  variants={cardVariants}
                  exit={{ scale: 0.9, opacity: 0 }}
                  className={`glass-panel p-6 rounded-2xl relative overflow-hidden cyber-glow-card cyber-glow-card-${toneClass}`}
                  style={{ borderLeft: `3px solid ${borderAccentColor}` }}
                >
                  <div className="absolute top-0 right-0 w-32 h-32 bg-white/[0.01] -rotate-45 translate-x-16 -translate-y-16 pointer-events-none" />
                  
                  {/* Card Header */}
                  <div className="flex justify-between items-start gap-4 mb-6">
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5 mb-1">
                        <TargetIcon size={12} className="text-muted flex-shrink-0" />
                        <span className="text-[10px] font-mono text-muted uppercase tracking-wider">Scope Address</span>
                      </div>
                      <h3 className="text-sm font-black text-text truncate uppercase font-mono" title={target}>
                        {target}
                      </h3>
                    </div>
                    <span className={`text-[9px] font-black tracking-widest px-2 py-0.5 rounded border ${
                      isOptimal ? 'bg-ok/10 text-ok border-ok/20' : 
                      isPartial ? 'bg-warn/10 text-warn border-warn/20' : 
                      'bg-bad/10 text-bad border-bad/20'
                    }`}>
                      {isOptimal ? 'OPTIMAL BYPASS' : isPartial ? 'PARTIAL EVASION' : 'HIGH DETECTION RISK'}
                    </span>
                  </div>

                  {/* Circular Progress & KPI Grid */}
                  <div className="grid grid-cols-[80px_1fr] gap-6 items-center">
                    {/* SVG Gauge */}
                    <div className="relative h-20 w-20 flex items-center justify-center">
                      <svg className="w-full h-full transform -rotate-90">
                        {/* Track circle */}
                        <circle 
                          cx="40" 
                          cy="40" 
                          r={radius} 
                          className="stroke-white/5 fill-transparent" 
                          strokeWidth="6" 
                        />
                        {/* Value circle */}
                        <circle 
                          cx="40" 
                          cy="40" 
                          r={radius} 
                          className={`fill-transparent transition-all duration-1000 ease-out ${
                            isOptimal ? 'stroke-ok' : isPartial ? 'stroke-warn' : 'stroke-bad'
                          }`} 
                          strokeWidth="6" 
                          strokeDasharray={circumference}
                          strokeDashoffset={strokeOffset}
                          strokeLinecap="round"
                        />
                      </svg>
                      {/* Inner Value Text */}
                      <div className="absolute inset-0 flex flex-col items-center justify-center font-mono">
                        <span className="text-xs font-black text-text">{Math.round(rate)}%</span>
                        <span className="text-[7px] text-muted font-bold uppercase tracking-tighter">Bypass</span>
                      </div>
                    </div>

                    {/* Breakdown Numbers */}
                    <div className="space-y-3">
                      <div className="flex justify-between items-center bg-black/20 p-2 rounded-lg border border-white/5">
                        <div className="flex items-center gap-1.5">
                          <CheckCircle size={10} className="text-ok" />
                          <span className="text-[9px] font-bold text-muted uppercase">Successful Bypasses</span>
                        </div>
                        <span className="text-xs font-mono font-black text-ok">{metrics.successes}</span>
                      </div>
                      
                      <div className="flex justify-between items-center bg-black/20 p-2 rounded-lg border border-white/5">
                        <div className="flex items-center gap-1.5">
                          <Zap size={10} className="text-accent" />
                          <span className="text-[9px] font-bold text-muted uppercase">Evasion Queries</span>
                        </div>
                        <span className="text-xs font-mono font-black text-text">{metrics.total_requests}</span>
                      </div>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </AnimatePresence>
        </motion.div>
      )}
    </div>
  );
}
