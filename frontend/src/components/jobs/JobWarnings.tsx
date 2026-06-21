import { memo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ChevronDown } from 'lucide-react';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;

interface JobWarningsProps {
  warnings: string[];
  expanded: boolean;
  onToggle: () => void;
}

function JobWarningsBase({ warnings, expanded, onToggle }: JobWarningsProps) {
  if (!warnings || warnings.length === 0) return null;

  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      className="card warning-card"
    >
      <button
        type="button"
        onClick={onToggle}
        className="w-full flex items-center justify-between text-left focus:outline-none"
      >
        <h3>Warnings ({warnings.length})</h3>
        <ChevronDown size={18} className={`transform transition-transform duration-200 text-[var(--text-secondary)] ${expanded ? 'rotate-180 text-[var(--bad)]' : ''}`} />
      </button>
      <AnimatePresence initial={false}>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease: EASE_OUT }}
            className="overflow-hidden"
          >
            <ul className="warnings-list mt-4 space-y-1.5">
              {warnings.map((w, idx) => (
                <li key={w.substring(0, 40) + idx}>{w}</li>
              ))}
            </ul>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

export const JobWarnings = memo(JobWarningsBase);
