import type { DetectionGapResponse } from '@/types/api';
import { Skeleton } from '@/components/ui/Skeleton';
import { motion, AnimatePresence } from 'framer-motion';

interface GapAnalysisStatsProps {
  data: DetectionGapResponse;
}

export function GapAnalysisStats({ data }: GapAnalysisStatsProps) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-panel border border-white/5 p-6 rounded-xl cyber-glow-sm"
      >
        <div className="text-muted text-xs uppercase tracking-widest font-bold mb-2">Overall Coverage</div>
        <div
          className={`font-semibold ${
            data.overall_coverage > 80 ? 'text-ok' : data.overall_coverage > 50 ? 'text-warn' : 'text-bad'
          }`}
          style={{ fontSize: 'var(--text-card-value)' }}
        >
          {data.overall_coverage}%
        </div>
        <div className="mt-4 h-1.5 w-full bg-white/5 rounded-full overflow-hidden">
          <div
            className={`h-full transition-all duration-1000 ${
              data.overall_coverage > 80 ? 'bg-ok' : data.overall_coverage > 50 ? 'bg-warn' : 'text-bad'
            }`}
            style={{ width: `${data.overall_coverage}%` }}
          />
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="bg-panel border border-white/5 p-6 rounded-xl"
      >
        <div className="text-muted text-xs uppercase tracking-widest font-bold mb-2">Module Integrity</div>
        <div className="font-semibold text-text" style={{ fontSize: 'var(--text-card-value)' }}>
          {data.total_modules - data.modules_with_gaps}
          <span className="text-lg text-muted font-normal ml-2">
            / {data.total_modules} OK
          </span>
        </div>
        <div className="text-xs text-muted mt-2 italic">
          Modules meeting 100% of detection registry requirements.
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="bg-panel border border-white/5 p-6 rounded-xl"
      >
        <div className="text-muted text-xs uppercase tracking-widest font-bold mb-2">Identified Gaps</div>
        <div
          className={`font-semibold ${data.modules_with_gaps > 0 ? 'text-warn' : 'text-ok'}`}
          style={{ fontSize: 'var(--text-card-value)' }}
        >
          {data.modules_with_gaps}
        </div>
        <div className="text-xs text-muted mt-2">
          Requires immediate action to reach full security posture.
        </div>
      </motion.div>
    </div>
  );
}

interface GapAnalysisLoadingProps {
  loading: boolean;
}

export function GapAnalysisLoading({ loading }: GapAnalysisLoadingProps) {
  if (!loading) return null;
  return (
    <div className="p-6 space-y-6">
      <Skeleton className="h-10 w-48" />
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Skeleton className="h-32" />
        <Skeleton className="h-32" />
        <Skeleton className="h-32" />
      </div>
      <Skeleton className="h-96" />
    </div>
  );
}
