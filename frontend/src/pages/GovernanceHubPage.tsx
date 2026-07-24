import { useState, Suspense, lazy } from 'react';
import { useSearchParams } from 'react-router-dom';
import { motion } from 'framer-motion';
import { ShieldCheck, FileText, Fingerprint, Link } from 'lucide-react';
import { PageHeader } from '@/components/ui/PageHeader';
import { TabFallback } from '@/components/ui/TabFallback';

const ComplianceDashboard = lazy(() =>
  import('./ComplianceDashboard').then(m => ({ default: m.ComplianceDashboard }))
);
const AuditLogViewer = lazy(() =>
  import('@/components/AuditLogViewer').then(m => ({ default: m.AuditLogViewer }))
);
const AccessLogsPage = lazy(() =>
  import('@/components/ComplianceLogViewer').then(m => ({ default: m.ComplianceLogViewer }))
);
const EvidenceCustodyPage = lazy(() =>
  import('./EvidenceCustodyPage').then(m => ({ default: m.EvidenceCustodyPage }))
);

type GovernanceTab = 'compliance' | 'audit' | 'access' | 'evidence';

const tabs: { id: GovernanceTab; label: string; icon: React.ReactNode }[] = [
  { id: 'compliance', label: 'Compliance', icon: <ShieldCheck size={16} /> },
  { id: 'audit', label: 'Audit Logs', icon: <Fingerprint size={16} /> },
  { id: 'access', label: 'Access Logs', icon: <FileText size={16} /> },
  { id: 'evidence', label: 'Evidence Chain', icon: <Link size={16} /> },
];

export function GovernanceHubPage() {
  const [searchParams] = useSearchParams();
  const initialTab = searchParams.get('tab') as GovernanceTab | null;
  const [activeTab, setActiveTab] = useState<GovernanceTab>(
    initialTab && tabs.some(t => t.id === initialTab) ? initialTab : 'compliance'
  );

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<ShieldCheck size={20} />}
        title="Governance"
        subtitle="Compliance, audit trails, and evidence management"
      />

      <div
        className="flex bg-surface-2 p-1 rounded-lg border border-line"
        role="tablist"
        aria-label="Governance sections"
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
                  layoutId="activeGovernanceTab"
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
        {activeTab === 'compliance' && <ComplianceDashboard />}
        {activeTab === 'audit' && <AuditLogViewer />}
        {activeTab === 'access' && <AccessLogsPage />}
        {activeTab === 'evidence' && <EvidenceCustodyPage />}
      </Suspense>
    </div>
  );
}
