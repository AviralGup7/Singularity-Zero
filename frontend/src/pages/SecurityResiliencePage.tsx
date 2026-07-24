import { useState, Suspense, lazy } from 'react';
import { useSearchParams } from 'react-router-dom';
import { motion } from 'framer-motion';
import { ShieldCheck, Zap } from 'lucide-react';
import { PageHeader } from '../components/ui';

const SecurityPage = lazy(() =>
  import('../pages/SecurityPage').then(m => ({ default: m.SecurityPage }))
);
const SelfHealingPage = lazy(() =>
  import('../pages/SelfHealingPage').then(m => ({ default: m.SelfHealingPage }))
);

type SecurityTab = 'api' | 'self-healing';

const tabs: { id: SecurityTab; label: string; icon: React.ReactNode }[] = [
  { id: 'api', label: 'API Security', icon: <ShieldCheck size={16} /> },
  { id: 'self-healing', label: 'Self-Healing', icon: <Zap size={16} /> },
];

function TabFallback() {
  return (
    <div className="flex items-center justify-center py-20 text-muted animate-pulse font-mono text-xs uppercase tracking-widest">
      Loading...
    </div>
  );
}

export function SecurityResiliencePage() {
  const [searchParams] = useSearchParams();
  const initialTab = searchParams.get('tab') as SecurityTab | null;
  const [activeTab, setActiveTab] = useState<SecurityTab>(initialTab && tabs.some(t => t.id === initialTab) ? initialTab : 'api');

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<ShieldCheck size={20} />}
        title="Security & Resilience"
        subtitle="API controls, enforcement events, and autonomous recovery"
      />

      <div className="flex bg-surface-2 p-1 rounded-lg border border-line" role="tablist" aria-label="Security sections">
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
                  layoutId="activeSecurityTab"
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
        {activeTab === 'api' && <SecurityPage />}
        {activeTab === 'self-healing' && <SelfHealingPage />}
      </Suspense>
    </div>
  );
}
