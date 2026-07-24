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
      role="region"
      aria-label="Job logs"
    >
      <button
        type="button"
        onClick={onToggle}
        className="w-full flex items-center justify-between text-left focus-visible:ring-2 focus-visible:ring-accent/50 focus-visible:outline-none rounded"
        aria-expanded={expanded}
        aria-controls="job-logs-panel"
      >
        <h3>Job Logs</h3>
        <ChevronDown size={18} className={`transform transition-transform duration-200 text-text-secondary ${expanded ? 'rotate-180 text-accent' : ''}`} aria-hidden="true" />
      </button>
      <AnimatePresence initial={false}>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease: EASE_OUT }}
            className="overflow-hidden"
            id="job-logs-panel"
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
