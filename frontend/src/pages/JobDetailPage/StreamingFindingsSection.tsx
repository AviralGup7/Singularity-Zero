import { motion, AnimatePresence } from 'framer-motion';
import { EASE_OUT, itemVariants } from './helpers';
import { ROUTES } from '@/config/paths';
import { Link } from 'react-router-dom';

interface StreamingFinding {
  id?: string;
  type?: string;
  target?: string;
  url?: string;
  severity: string;
}

interface StreamingFindingsSectionProps {
  findings: StreamingFinding[];
}

export function StreamingFindingsSection({ findings }: StreamingFindingsSectionProps) {
  return (
    <motion.div variants={itemVariants} className="card">
      <h3>Findings Discovered ({findings.length})</h3>
      <div className="streaming-findings space-y-2 mt-4">
        <AnimatePresence initial={false}>
          {findings.slice(-5).reverse().map((f, idx) => (
            <motion.div
              key={f.id || `${f.type}-${f.target}-${idx}`}
              initial={{ opacity: 0, x: -20, scale: 0.95 }}
              animate={{ opacity: 1, x: 0, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              transition={{ duration: 0.3, ease: EASE_OUT }}
              className={`finding-min-card sev-${f.severity} flex items-center gap-3 p-3 rounded-lg border`}
            >
              <span className={`sev-badge text-[10px] uppercase font-bold px-2 py-0.5 rounded ${
                f.severity === 'critical' ? 'bg-red-500/10 text-red-400 border border-red-500/20' :
                f.severity === 'high' ? 'bg-orange-500/10 text-orange-400 border border-orange-500/20' :
                'bg-amber-500/10 text-amber-400 border border-amber-500/20'
              }`}>{f.severity}</span>
              <span className="finding-min-title font-bold text-sm text-[var(--text-primary)] flex-1 truncate">{f.type || 'Unknown'}</span>
              <span className="finding-min-target text-xs text-[var(--text-tertiary)] truncate max-w-sm">{f.target || f.url?.substring(0, 50) || ''}</span>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
      <Link to={ROUTES.FINDINGS} className="view-all-findings-link text-xs text-[var(--accent)] hover:underline mt-3 block">View all findings</Link>
    </motion.div>
  );
}
