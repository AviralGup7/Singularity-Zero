import { useState, Suspense, lazy } from 'react';
import { useSearchParams } from 'react-router-dom';
import { motion } from 'framer-motion';
import { CalendarClock, ArrowLeftRight, GitCompareArrows, ShieldAlert, Server, Activity } from 'lucide-react';
import { PageHeader } from '@/components/ui/PageHeader';
import { TabFallback } from '@/components/ui/TabFallback';

const FindingsTimelinePage = lazy(() =>
  import('./FindingsTimelinePage').then(m => ({ default: m.FindingsTimelinePage }))
);
const TargetComparison = lazy(() =>
  import('./TargetComparison').then(m => ({ default: m.TargetComparison }))
);
const ScanDiffPage = lazy(() =>
  import('./ScanDiffPage').then(m => ({ default: m.ScanDiffPage }))
);
const EvasionMetricsPage = lazy(() =>
  import('./EvasionMetricsPage').then(m => ({ default: m.EvasionMetricsPage }))
);
const MeshHealthPage = lazy(() =>
  import('./MeshHealthPage').then(m => ({ default: m.MeshHealthPage }))
);
const TracingPage = lazy(() =>
  import('./TracingPage').then(m => ({ default: m.TracingPage }))
);

type AnalyticsTab = 'timeline' | 'comparison' | 'scan-diff' | 'evasion' | 'mesh' | 'tracing';

const tabs: { id: AnalyticsTab; label: string; icon: React.ReactNode }[] = [
  { id: 'timeline', label: 'Timeline', icon: <CalendarClock size={16} /> },
  { id: 'comparison', label: 'Compare', icon: <ArrowLeftRight size={16} /> },
  { id: 'scan-diff', label: 'Scan Diff', icon: <GitCompareArrows size={16} /> },
  { id: 'evasion', label: 'Evasion', icon: <ShieldAlert size={16} /> },
  { id: 'mesh', label: 'Mesh', icon: <Server size={16} /> },
  { id: 'tracing', label: 'Tracing', icon: <Activity size={16} /> },
];

export function AnalyticsHubPage() {
  const [searchParams] = useSearchParams();
  const initialTab = searchParams.get('tab') as AnalyticsTab | null;
  const [activeTab, setActiveTab] = useState<AnalyticsTab>(
    initialTab && tabs.some(t => t.id === initialTab) ? initialTab : 'timeline'
  );

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<Activity size={20} />}
        title="Analytics"
        subtitle="Timeline, comparisons, evasion metrics, mesh telemetry, and distributed tracing"
      />

      <div
        className="flex flex-wrap bg-surface-2 p-1 rounded-lg border border-line"
        role="tablist"
        aria-label="Analytics sections"
      >
        {tabs.map(tab => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={isActive}
              className={`relative z-10 flex items-center gap-2 px-4 py-2 text-sm font-semibold rounded-md transition-colors duration-200 cursor-pointer ${
                isActive ? 'text-accent font-bold' : 'text-text-secondary hover:text-text-primary'
              }`}
              onClick={() => setActiveTab(tab.id)}
              style={{ background: 'transparent' }}
            >
              {isActive && (
                <motion.div
                  layoutId="activeAnalyticsTab"
                  className="absolute inset-0 bg-accent-soft border border-accent/20 rounded-md z-[-1]"
                  transition={{ type: 'spring', stiffness: 300, damping: 30 }}
                />
              )}
              {tab.icon}
              {tab.label}
            </button>
          );
        })}
      </div>

      <Suspense fallback={<TabFallback />}>
        {activeTab === 'timeline' && <FindingsTimelinePage />}
        {activeTab === 'comparison' && <TargetComparison />}
        {activeTab === 'scan-diff' && <ScanDiffPage />}
        {activeTab === 'evasion' && <EvasionMetricsPage />}
        {activeTab === 'mesh' && <MeshHealthPage />}
        {activeTab === 'tracing' && <TracingPage />}
      </Suspense>
    </div>
  );
}
