import { memo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ChevronDown } from 'lucide-react';
import { JobLogViewer } from '@/components/jobs/JobLogViewer';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;

interface JobLogsCardProps {
  displayLines: string[];
  wsFailed: boolean;
  jobStatus: string;
  expanded: boolean;
  onToggle: () => void;
}

function JobLogsCardBase({ displayLines, wsFailed, jobStatus, expanded, onToggle }: JobLogsCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      className="card"
    >
      <button
        type="button"
        onClick={onToggle}
        className="w-full flex items-center justify-between text-left focus:outline-none"
      >
        <h3>Job Logs</h3>
        <ChevronDown size={18} className={`transform transition-transform duration-200 text-[var(--text-secondary)] ${expanded ? 'rotate-180 text-[var(--accent)]' : ''}`} />
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
            <div className="pt-4">
              <JobLogViewer
                displayLines={displayLines}
                wsFailed={wsFailed}
                jobStatus={jobStatus}
              />
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

export const JobLogsCard = memo(JobLogsCardBase);
