import { useState, Suspense, lazy } from 'react';
import { useSearchParams } from 'react-router-dom';
import { motion } from 'framer-motion';
import { BarChart3, CheckCircle2, ShieldCheck, Database } from 'lucide-react';
import { PageHeader } from '@/components/ui/PageHeader';
import { TabFallback } from '@/components/ui/TabFallback';

const RiskScorePage = lazy(() =>
  import('./RiskScorePage').then(m => ({ default: m.RiskScorePage }))
);
const RemediationPlanner = lazy(() =>
  import('./RemediationPlanner').then(m => ({ default: m.RemediationPlanner }))
);
const AcceptancePage = lazy(() =>
  import('./AcceptancePage').then(m => ({ default: m.AcceptancePage }))
);
const AssetCriticalityPage = lazy(() =>
  import('./AssetCriticalityPage').then(m => ({ default: m.AssetCriticalityPage }))
);

type RiskTab = 'score' | 'remediation' | 'acceptance' | 'assets';

const tabs: { id: RiskTab; label: string; icon: React.ReactNode }[] = [
  { id: 'score', label: 'Risk Score', icon: <BarChart3 size={16} /> },
  { id: 'remediation', label: 'Remediation', icon: <CheckCircle2 size={16} /> },
  { id: 'acceptance', label: 'Acceptance', icon: <ShieldCheck size={16} /> },
  { id: 'assets', label: 'Assets', icon: <Database size={16} /> },
];

export function RiskHubPage() {
  const [searchParams] = useSearchParams();
  const initialTab = searchParams.get('tab') as RiskTab | null;
  const [activeTab, setActiveTab] = useState<RiskTab>(
    initialTab && tabs.some(t => t.id === initialTab) ? initialTab : 'score'
  );

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<BarChart3 size={20} />}
        title="Risk Management"
        subtitle="Exposure scoring, remediation tracking, and risk acceptance"
      />

      <div
        className="flex bg-surface-2 p-1 rounded-lg border border-line"
        role="tablist"
        aria-label="Risk sections"
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
                  layoutId="activeRiskTab"
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
        {activeTab === 'score' && <RiskScorePage />}
        {activeTab === 'remediation' && <RemediationPlanner />}
        {activeTab === 'acceptance' && <AcceptancePage />}
        {activeTab === 'assets' && <AssetCriticalityPage />}
      </Suspense>
    </div>
  );
}
