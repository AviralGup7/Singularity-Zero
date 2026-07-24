import { memo } from 'react';
import { motion } from 'framer-motion';
import { InfoItem } from '@/components/jobs/JobInfoItem';

interface JobInformationCardProps {
  job: {
    base_url?: string;
    hostname?: string;
    mode?: string;
    stage_label?: string;
    started_at?: string;
    status_message?: string;
    scope_entries?: string[];
    returncode?: number | null;
    finished_at_label?: string;
  };
}

function JobInformationCardBase({ job }: JobInformationCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      className="card"
      role="region"
      aria-label="Job information"
    >
      <h3>Job Information</h3>
      <div className="info-grid">
        <InfoItem label="Target" value={job.base_url} />
        <InfoItem label="Hostname" value={job.hostname} />
        <InfoItem label="Mode" value={job.mode} />
        <InfoItem label="Stage" value={job.stage_label} />
        <InfoItem label="Started" value={job.started_at} />
        <InfoItem label="Status Message" value={job.status_message} />
        <InfoItem label="Scope Entries" value={job.scope_entries?.join(', ')} />
        {job.returncode !== null && job.returncode !== undefined && (
          <InfoItem label="Exit Code" value={String(job.returncode)} />
        )}
        {job.finished_at_label && (
          <InfoItem label="Finished" value={job.finished_at_label} />
        )}
      </div>
    </motion.div>
  );
}

export const JobInformationCard = memo(JobInformationCardBase);
