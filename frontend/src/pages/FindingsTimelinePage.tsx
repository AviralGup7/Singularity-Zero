import { useMemo, useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { CalendarClock, Filter, RefreshCw } from 'lucide-react';
import { useFindingsTimeline, useMotionPolicy, useTargets } from '@/hooks';
import type { FindingTimelineEvent } from '@/types/extended';
import { EmptyState, SkeletonTable, PageHeader, GlassCard, AnimatedCounter } from '@/components/ui';

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low', 'info'];
const PAGE_SIZE = 30;

const EASE_OUT = [0.16, 1, 0.3, 1] as const;

function formatDateInput(date: Date): string {
  return date.toISOString().slice(0, 10);
}

function severityTone(severity: string): string {
  return `timeline-severity timeline-severity--${severity || 'info'}`;
}

function eventTimeLabel(timestamp: string): string {
  const parsed = new Date(timestamp);
  if (Number.isNaN(parsed.getTime())) return timestamp;
  return parsed.toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function FindingsTimelinePage() {
  const today = useMemo(() => new Date(), []);
  const defaultStart = useMemo(() => {
    const start = new Date(today);
    start.setDate(start.getDate() - 30);
    return start;
   
  }, [today]);

  const [severity, setSeverity] = useState('');
  const [target, setTarget] = useState('');
  const [jobId, setJobId] = useState('');
  const [startDate, setStartDate] = useState(formatDateInput(defaultStart));
  const [endDate, setEndDate] = useState(formatDateInput(today));
  const [offset, setOffset] = useState(0);
  const [events, setEvents] = useState<FindingTimelineEvent[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<FindingTimelineEvent | null>(null);

  const { policy, strategy } = useMotionPolicy('list');
  const { data: targetsData } = useTargets();
  const filterKey = `${severity}|${target}|${jobId}|${startDate}|${endDate}`;
  const timeline = useFindingsTimeline({
    severity,
    target,
    jobId,
    startDate,
    endDate,
    limit: PAGE_SIZE,
    offset,
  });

  // Reset pagination state when filters change
  useEffect(() => {
    /* eslint-disable react-hooks/set-state-in-effect */
    setOffset(0);
    setEvents([]);
    setSelectedEvent(null);
    /* eslint-enable react-hooks/set-state-in-effect */
  }, [filterKey]);

  // Append new events when timeline data arrives/changes
  useEffect(() => {
    if (timeline.data) {
      const incoming = timeline.events;
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setEvents((current) => {
        const merged = offset === 0 ? incoming : [...current, ...incoming];
        const seen = new Set<string>();
        return merged.filter((event) => {
          if (seen.has(event.id)) return false;
          seen.add(event.id);
          return true;
        });
      });
    }
  }, [timeline.data, timeline.events, offset]);

  const targetOptions = useMemo(() => {
    const names = new Set<string>();
    for (const item of targetsData?.targets ?? []) names.add(item.name);
    for (const event of events) names.add(event.target);
    return Array.from(names).sort();
   
  }, [events, targetsData?.targets]);

  const groupedEvents = useMemo(() => {
    const groups = new Map<string, FindingTimelineEvent[]>();
    for (const event of events) {
      const day = event.timestamp.slice(0, 10);
      groups.set(day, [...(groups.get(day) ?? []), event]);
    }
    return Array.from(groups.entries()).sort(([left], [right]) => right.localeCompare(left));
   
  }, [events]);

  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.05 }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 15 },
    show: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 100, damping: 15 } }
  };

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="show"
      className="findings-timeline-page space-y-6"
    >
      <PageHeader
        icon={<CalendarClock size={20} />}
        title="Findings Timeline"
        subtitle="Discovery chronology across jobs, targets, and severities."
        actions={
          <button type="button" className="btn btn-secondary flex items-center gap-1.5" onClick={() => void timeline.refetch()}>
            <RefreshCw size={14} aria-hidden="true" />
            <span>Refresh</span>
          </button>
        }
      />

      {/* Styled Input filter panel */}
      <motion.section variants={itemVariants} className="timeline-filter-bar card grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-4 p-4" aria-label="Timeline filters">
        <label className="flex flex-col gap-1">
          <span className="text-xs font-semibold uppercase tracking-wider text-[var(--text-secondary)] font-mono">Severity</span>
          <select className="bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] focus:border-[var(--accent)] focus:shadow-[0_0_0_2px_var(--accent-soft)] transition-all duration-200 cursor-pointer" value={severity} onChange={(event) => setSeverity(event.target.value)}>
            {SEVERITIES.map((value) => (
              <option key={value || 'all'} value={value}>{value ? value : 'All severities'}</option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-xs font-semibold uppercase tracking-wider text-[var(--text-secondary)] font-mono">Target</span>
          <select className="bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] focus:border-[var(--accent)] focus:shadow-[0_0_0_2px_var(--accent-soft)] transition-all duration-200 cursor-pointer" value={target} onChange={(event) => setTarget(event.target.value)}>
            <option value="">All targets</option>
            {targetOptions.map((name) => (
              <option key={name} value={name}>{name}</option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-xs font-semibold uppercase tracking-wider text-[var(--text-secondary)] font-mono">Job</span>
          <input className="bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] focus:border-[var(--accent)] focus:shadow-[0_0_0_2px_var(--accent-soft)] transition-all duration-200" value={jobId} onChange={(event) => setJobId(event.target.value)} placeholder="Job or run id" />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-xs font-semibold uppercase tracking-wider text-[var(--text-secondary)] font-mono">Start</span>
          <input className="bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] focus:border-[var(--accent)] focus:shadow-[0_0_0_2px_var(--accent-soft)] transition-all duration-200" type="date" value={startDate} onChange={(event) => setStartDate(event.target.value)} />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-xs font-semibold uppercase tracking-wider text-[var(--text-secondary)] font-mono">End</span>
          <input className="bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] focus:border-[var(--accent)] focus:shadow-[0_0_0_2px_var(--accent-soft)] transition-all duration-200" type="date" value={endDate} onChange={(event) => setEndDate(event.target.value)} />
        </label>
      </motion.section>

      {/* Overview stats cards */}
      <motion.div variants={itemVariants} className="timeline-summary-grid grid grid-cols-1 sm:grid-cols-2 gap-4">
        <GlassCard variant="glow" delay={0.05} className="timeline-summary-card flex items-center gap-3 p-4">
          <CalendarClock size={20} aria-hidden="true" className="text-[var(--accent)]" />
          <div className="flex flex-col">
            <span className="text-xs text-[var(--text-secondary)] uppercase font-semibold font-mono tracking-wider">Loaded Events</span>
            <span className="text-2xl font-bold mt-0.5">
              <AnimatedCounter value={events.length} />
            </span>
          </div>
        </GlassCard>
        
        <GlassCard variant="glow" delay={0.1} className="timeline-summary-card flex items-center gap-3 p-4">
          <Filter size={20} aria-hidden="true" className="text-[var(--accent)]" />
          <div className="flex flex-col">
            <span className="text-xs text-[var(--text-secondary)] uppercase font-semibold font-mono tracking-wider">Filter State</span>
            <span className="text-xl font-bold mt-0.5">
              {severity || target || jobId ? (
                <span className="text-[var(--warn)] font-semibold">Active Scope</span>
              ) : (
                <span className="text-[var(--text-secondary)] font-normal">Unscoped</span>
              )}
            </span>
          </div>
        </GlassCard>
      </motion.div>

      {timeline.error && <div className="card error">Unable to load timeline: {timeline.error.message}</div>}

      <div className="timeline-layout grid grid-cols-1 lg:grid-cols-3 gap-6">
        <section className="card timeline-panel lg:col-span-2 p-4" data-testid="findings-timeline">
          {timeline.loading && events.length === 0 && <SkeletonTable rows={5} />}
          {!timeline.loading && events.length === 0 && (
            <EmptyState title="No findings matched" description="Try selecting a different timeline range, severity, or target." />
          )}

          <div className="timeline-stack space-y-8">
            {groupedEvents.map(([day, dayEvents]) => (
              <div className="timeline-day space-y-4" key={day}>
                {/* Sticky day header with backdrop blur glass effect */}
                <div className="timeline-day-label sticky top-[60px] z-10 bg-[var(--surface)]/90 backdrop-blur-md py-2 border-b border-[var(--border)]/40 flex items-center justify-between px-2 rounded-t-lg">
                  <time className="font-bold text-sm text-[var(--text-primary)] font-mono">{day}</time>
                  <span className="text-xs text-[var(--text-secondary)] bg-[var(--surface-2)] px-2 py-0.5 rounded border border-[var(--border)]">{dayEvents.length} events</span>
                </div>
                
                {/* Vertical spine timeline day track */}
                <div className="timeline-day-track relative pl-6 border-l-2 border-[var(--border)]/60 ml-3.5 space-y-3 py-1">
                  {dayEvents.map((event, index) => {
                    const isSelected = selectedEvent?.id === event.id;
                    const isCriticalOrHigh = event.severity === 'critical' || event.severity === 'high';
                    const glowClass = isCriticalOrHigh ? 'shadow-[0_0_8px_currentColor] animate-pulse' : '';
                    
                    return (
                      <motion.article
                        key={event.id}
                        className={`timeline-event relative rounded-lg border border-[var(--border)] transition-all duration-200 overflow-hidden ${
                          isSelected ? 'bg-[var(--accent-soft)]/10 border-[var(--accent)]/50 shadow' : 'bg-[var(--surface-2)] hover:bg-white/5'
                        }`}
                        initial={policy.allowFramer ? { opacity: 0, y: strategy.distance } : false}
                        animate={policy.allowFramer ? { opacity: 1, y: 0 } : undefined}
                        transition={{ duration: strategy.duration, delay: Math.min(index * strategy.stagger, 0.18) }}
                      >
                        <button type="button" className="timeline-event-button flex items-center justify-between w-full p-3.5 text-left" onClick={() => setSelectedEvent(event)}>
                          {/* Pulsing outline severity indicator */}
                          <span className={`${severityTone(event.severity)} ${glowClass} shrink-0 w-3 h-3 rounded-full border border-current mr-3.5`} />
                          
                          <span className="timeline-event-copy flex-1 min-w-0 pr-4">
                            <strong className="block text-sm text-[var(--text-primary)] truncate font-semibold">{event.title}</strong>
                            <small className="block text-xs text-[var(--text-secondary)] font-mono mt-0.5 truncate">{event.target} &bull; {event.url || event.module || event.finding_id}</small>
                          </span>
                          <time className="text-xs text-[var(--text-secondary)] font-mono tabular-nums shrink-0">{eventTimeLabel(event.timestamp)}</time>
                        </button>
                      </motion.article>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>

          {events.length > 0 && (
            <div className="timeline-load-row flex justify-center mt-8">
              <button
                type="button"
                className="btn btn-secondary"
                disabled={timeline.loading || !timeline.hasMore}
                onClick={() => setOffset((current) => current + PAGE_SIZE)}
              >
                {timeline.hasMore ? 'Load more events' : 'End of timeline'}
              </button>
            </div>
          )}
        </section>

        {/* Dynamic sliding detail sidebar GlassCard panel */}
        <div className="lg:col-span-1">
          <GlassCard variant="default" className="timeline-detail-panel p-4 sticky top-[80px]" aria-label="Finding detail sidebar">
            <AnimatePresence mode="wait">
              {selectedEvent ? (
                <motion.div
                  key={selectedEvent.id}
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 20 }}
                  transition={{ duration: 0.25, ease: EASE_OUT }}
                  className="space-y-4"
                >
                  <div className="timeline-detail-head flex items-start gap-3 pb-3 border-b border-[var(--border)]">
                    <span className={`${severityTone(selectedEvent.severity)} shrink-0 w-3.5 h-3.5 rounded-full mt-1.5 border border-current shadow-[0_0_8px_currentColor]`} />
                    <div className="min-w-0">
                      <h3 className="font-bold text-base text-[var(--text-primary)] leading-snug">{selectedEvent.title}</h3>
                      <p className="text-xs text-[var(--text-secondary)] font-mono mt-1 truncate">{selectedEvent.target} &bull; {eventTimeLabel(selectedEvent.timestamp)}</p>
                    </div>
                  </div>
                  
                  <dl className="timeline-detail-list text-xs space-y-2 font-mono">
                    <div className="flex justify-between border-b border-[var(--border)]/30 pb-1"><dt className="text-[var(--text-secondary)]">Severity</dt><dd className="font-bold uppercase text-[var(--text-primary)]">{selectedEvent.severity}</dd></div>
                    <div className="flex justify-between border-b border-[var(--border)]/30 pb-1"><dt className="text-[var(--text-secondary)]">Finding ID</dt><dd className="text-[var(--text-primary)] truncate max-w-[150px]">{selectedEvent.finding_id}</dd></div>
                    <div className="flex justify-between border-b border-[var(--border)]/30 pb-1"><dt className="text-[var(--text-secondary)]">Job ID</dt><dd className="text-[var(--text-primary)] truncate max-w-[150px]">{selectedEvent.job_id || 'Unknown'}</dd></div>
                    <div className="flex justify-between border-b border-[var(--border)]/30 pb-1"><dt className="text-[var(--text-secondary)]">Module</dt><dd className="text-[var(--text-primary)]">{selectedEvent.module || 'Unknown'}</dd></div>
                    <div className="flex justify-between border-b border-[var(--border)]/30 pb-1"><dt className="text-[var(--text-secondary)]">Confidence</dt><dd className="text-[var(--text-primary)]">{selectedEvent.confidence ?? 'n/a'}</dd></div>
                    {selectedEvent.telemetry_event && (
                      <>
                        <div className="flex justify-between border-b border-[var(--border)]/30 pb-1"><dt className="text-[var(--text-secondary)]">Telemetry</dt><dd className="text-[var(--text-primary)]">{selectedEvent.telemetry_event.event_type}</dd></div>
                        <div className="flex justify-between border-b border-[var(--border)]/30 pb-1"><dt className="text-[var(--text-secondary)]">Event ID</dt><dd className="text-[var(--text-primary)] truncate max-w-[150px]">{selectedEvent.telemetry_event.event_id}</dd></div>
                        <div className="flex justify-between border-b border-[var(--border)]/30 pb-1"><dt className="text-[var(--text-secondary)]">Source</dt><dd className="text-[var(--text-primary)]">{selectedEvent.telemetry_event.source}</dd></div>
                        <div className="flex justify-between border-b border-[var(--border)]/30 pb-1"><dt className="text-[var(--text-secondary)]">Artifact</dt><dd className="text-[var(--text-primary)] truncate max-w-[150px]">{selectedEvent.telemetry_event.artifact_id || 'n/a'}</dd></div>
                      </>
                    )}
                  </dl>
                  
                  <div className="p-3 bg-[var(--surface-2)] border border-[var(--border)] rounded text-xs leading-relaxed text-[var(--text-secondary)] italic max-h-48 overflow-y-auto">
                    {selectedEvent.preview}
                  </div>
                  
                  <Link className="btn btn-primary w-full text-center py-2 flex items-center justify-center font-semibold" to={`/findings?finding=${encodeURIComponent(selectedEvent.finding_id)}`}>
                    Open Finding details
                  </Link>
                </motion.div>
              ) : (
                <motion.div
                  key="empty"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex flex-col items-center justify-center py-20 text-[var(--text-secondary)] text-center text-xs"
                >
                  <CalendarClock size={32} className="text-[var(--text-tertiary)] mb-2 opacity-50" />
                  <span>Select an event to inspect the finding context.</span>
                </motion.div>
              )}
            </AnimatePresence>
          </GlassCard>
        </div>
      </div>
    </motion.div>
  );
}
