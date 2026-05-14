import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { CalendarClock, Filter, RefreshCw } from 'lucide-react';
import { useFindingsTimeline, useMotionPolicy, useTargets } from '@/hooks';
import type { FindingTimelineEvent } from '@/types/extended';

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low', 'info'];
const PAGE_SIZE = 30;

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

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setOffset(0);
    setEvents([]);
    setSelectedEvent(null);
  }, [filterKey]);

  useEffect(() => {
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
  }, [offset, timeline.events]);

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

  return (
    <div className="findings-timeline-page">
      <section className="page-header">
        <div>
          <h2>Findings Timeline</h2>
          <p className="page-subtitle">Discovery chronology across jobs, targets, and severities.</p>
        </div>
        <button type="button" className="btn btn-secondary" onClick={() => void timeline.refetch()}>
          <RefreshCw size={14} aria-hidden="true" />
          Refresh
        </button>
      </section>

      <section className="timeline-filter-bar card" aria-label="Timeline filters">
        <label>
          <span>Severity</span>
          <select className="form-select" value={severity} onChange={(event) => setSeverity(event.target.value)}>
            {SEVERITIES.map((value) => (
              <option key={value || 'all'} value={value}>{value ? value : 'All severities'}</option>
            ))}
          </select>
        </label>
        <label>
          <span>Target</span>
          <select className="form-select" value={target} onChange={(event) => setTarget(event.target.value)}>
            <option value="">All targets</option>
            {targetOptions.map((name) => (
              <option key={name} value={name}>{name}</option>
            ))}
          </select>
        </label>
        <label>
          <span>Job</span>
          <input className="form-input" value={jobId} onChange={(event) => setJobId(event.target.value)} placeholder="Job or run id" />
        </label>
        <label>
          <span>Start</span>
          <input className="form-input" type="date" value={startDate} onChange={(event) => setStartDate(event.target.value)} />
        </label>
        <label>
          <span>End</span>
          <input className="form-input" type="date" value={endDate} onChange={(event) => setEndDate(event.target.value)} />
        </label>
      </section>

      <section className="timeline-summary-grid">
        <div className="card timeline-summary-card">
          <CalendarClock size={20} aria-hidden="true" />
          <span>Loaded events</span>
          <strong>{events.length}</strong>
        </div>
        <div className="card timeline-summary-card">
          <Filter size={20} aria-hidden="true" />
          <span>Active filter</span>
          <strong>{severity || target || jobId ? 'Scoped' : 'All'}</strong>
        </div>
      </section>

      {timeline.error && <div className="card error">Unable to load timeline: {timeline.error.message}</div>}

      <div className="timeline-layout">
        <section className="card timeline-panel" data-testid="findings-timeline">
          {timeline.loading && events.length === 0 && <div className="empty">Loading finding events...</div>}
          {!timeline.loading && events.length === 0 && <div className="empty">No findings matched this timeline range.</div>}

          <div className="timeline-stack">
            {groupedEvents.map(([day, dayEvents]) => (
              <div className="timeline-day" key={day}>
                <div className="timeline-day-label">
                  <time>{day}</time>
                  <span>{dayEvents.length} events</span>
                </div>
                <div className="timeline-day-track">
                  {dayEvents.map((event, index) => (
                    <motion.article
                      key={event.id}
                      className={`timeline-event ${selectedEvent?.id === event.id ? 'timeline-event--active' : ''}`}
                      initial={policy.allowFramer ? { opacity: 0, y: strategy.distance } : false}
                      animate={policy.allowFramer ? { opacity: 1, y: 0 } : undefined}
                      transition={{ duration: strategy.duration, delay: Math.min(index * strategy.stagger, 0.18) }}
                    >
                      <button type="button" className="timeline-event-button" onClick={() => setSelectedEvent(event)}>
                        <span className={severityTone(event.severity)} />
                        <span className="timeline-event-copy">
                          <strong>{event.title}</strong>
                          <small>{event.target} - {event.url || event.module || event.finding_id}</small>
                        </span>
                        <time>{eventTimeLabel(event.timestamp)}</time>
                      </button>
                      <div className="timeline-preview-card" role="tooltip">
                        <strong>{event.severity}</strong>
                        <span>{event.preview || event.module || 'No preview available'}</span>
                      </div>
                    </motion.article>
                  ))}
                </div>
              </div>
            ))}
          </div>

          {events.length > 0 && (
            <div className="timeline-load-row">
              <button
                type="button"
                className="btn btn-secondary"
                disabled={timeline.loading || !timeline.hasMore}
                onClick={() => setOffset((current) => current + PAGE_SIZE)}
              >
                {timeline.hasMore ? 'Load more' : 'End of timeline'}
              </button>
            </div>
          )}
        </section>

        <aside className="card timeline-detail-panel" aria-label="Finding detail sidebar">
          {selectedEvent ? (
            <>
              <div className="timeline-detail-head">
                <span className={severityTone(selectedEvent.severity)} />
                <div>
                  <h3>{selectedEvent.title}</h3>
                  <p>{selectedEvent.target} - {eventTimeLabel(selectedEvent.timestamp)}</p>
                </div>
              </div>
              <dl className="timeline-detail-list">
                <div><dt>Severity</dt><dd>{selectedEvent.severity}</dd></div>
                <div><dt>Finding</dt><dd>{selectedEvent.finding_id}</dd></div>
                <div><dt>Job</dt><dd>{selectedEvent.job_id || 'Unknown'}</dd></div>
                <div><dt>Module</dt><dd>{selectedEvent.module || 'Unknown'}</dd></div>
                <div><dt>Confidence</dt><dd>{selectedEvent.confidence ?? 'n/a'}</dd></div>
              </dl>
              <p className="timeline-detail-preview">{selectedEvent.preview}</p>
              <Link className="btn btn-primary" to={`/findings?finding=${encodeURIComponent(selectedEvent.finding_id)}`}>
                Open finding
              </Link>
            </>
          ) : (
            <div className="empty">Select an event to inspect the finding context.</div>
          )}
        </aside>
      </div>
    </div>
  );
}
