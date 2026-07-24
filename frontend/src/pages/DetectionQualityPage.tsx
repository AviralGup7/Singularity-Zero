import { useState, Suspense, lazy } from 'react';
import { useSearchParams } from 'react-router-dom';
import { motion } from 'framer-motion';
import { ShieldCheck, Brain } from 'lucide-react';
import { PageHeader } from '../components/ui';

const GapAnalysisPage = lazy(() =>
  import('../pages/GapAnalysisPage').then(m => ({ default: m.GapAnalysisPage }))
);
const LearningPage = lazy(() =>
  import('../pages/LearningPage').then(m => ({ default: m.LearningPage }))
);

type DetectionTab = 'gap-analysis' | 'learning';

const tabs: { id: DetectionTab; label: string; icon: React.ReactNode }[] = [
  { id: 'gap-analysis', label: 'Gap Analysis', icon: <ShieldCheck size={16} /> },
  { id: 'learning', label: 'Autonomous Learning', icon: <Brain size={16} /> },
];

function TabFallback() {
  return (
    <div className="flex items-center justify-center py-20 text-muted animate-pulse font-mono text-xs uppercase tracking-widest">
      Loading...
    </div>
  );
}

export function DetectionQualityPage() {
  const [searchParams] = useSearchParams();
  const initialTab = searchParams.get('tab') as DetectionTab | null;
  const [activeTab, setActiveTab] = useState<DetectionTab>(initialTab && tabs.some(t => t.id === initialTab) ? initialTab : 'gap-analysis');

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<ShieldCheck size={20} />}
        title="Detection Quality"
        subtitle="Detection coverage review and autonomous feedback calibration"
      />

      <div className="flex bg-surface-2 p-1 rounded-lg border border-line" role="tablist" aria-label="Detection quality sections">
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
                  layoutId="activeDetectionTab"
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
        {activeTab === 'gap-analysis' && <GapAnalysisPage />}
        {activeTab === 'learning' && <LearningPage />}
      </Suspense>
    </div>
  );
}
