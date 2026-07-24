export interface PageMeta {
  title: string;
  subtitle: string;
}

export const PAGE_META: Record<string, PageMeta> = {
  '/': { title: 'Dashboard', subtitle: 'Security Operations Overview' },
  '/targets': { title: 'Targets', subtitle: 'Asset and URL testing scope' },
  '/jobs': { title: 'Jobs', subtitle: 'Pipeline execution queue' },
  '/pipeline': { title: 'Pipeline Overview', subtitle: 'Stage flow and scanner telemetry' },
  '/findings': { title: 'Findings', subtitle: 'Security issues and evidence' },
  '/bug-bounty': { title: 'Bounty Dashboard', subtitle: 'Bug bounty submission pipeline and yields' },
  '/risk': { title: 'Risk', subtitle: 'Exposure scoring, remediation, and acceptance' },
  '/risk-score': { title: 'Risk Score', subtitle: 'Target exposure scoring' },
  '/findings-timeline': { title: 'Timeline', subtitle: 'Findings activity over time' },
  '/target-comparison': { title: 'Compare', subtitle: 'Target posture comparison' },
  '/gap-analysis': { title: 'Gap Analysis', subtitle: 'Detection coverage review' },
  '/detection-quality': { title: 'Detection Quality', subtitle: 'Coverage review and feedback calibration' },
  '/learning': { title: 'Autonomous Learning', subtitle: 'Neural feedback and threshold calibration' },
  '/replay': { title: 'Replay', subtitle: 'Request replay tooling' },
  '/cache-management': { title: 'Cache', subtitle: 'Backend cache controls' },
  '/settings': { title: 'Settings', subtitle: 'System preferences and controls' },
  '/tracing': { title: 'Tracing', subtitle: 'Distributed stage waterfalls' },
  '/security': { title: 'Security', subtitle: 'API controls and enforcement events' },
  '/cockpit': { title: 'Security Cockpit', subtitle: 'Operations command center' },
  '/remediation-planner': { title: 'Remediation Planner', subtitle: 'Prioritized fix tracking' },
  '/mesh': { title: 'Mesh Command', subtitle: 'Distributed node orchestration' },
  '/audit-logs': { title: 'Audit Logs', subtitle: 'System event journal' },
  '/compliance': { title: 'Security Compliance', subtitle: 'Regulatory GRC mapping and attestations' },
  '/reports': { title: 'Reports', subtitle: 'Signed report artefacts and attestations' },
  '/access-logs': { title: 'Access Logs', subtitle: 'Compliance audit trail' },
  '/governance': { title: 'Governance', subtitle: 'Compliance, audit trails, and evidence' },
  '/evasion': { title: 'Evasion Metrics', subtitle: 'WAF/IDS bypass success rates' },
};

export const ROUTE_PREFETCH_MAP: Record<string, () => Promise<unknown>> = {
  '/': () => import('@/pages/DashboardPage'),
  '/targets': () => import('@/pages/TargetsPage'),
  '/jobs': () => import('@/pages/JobsPage'),
  '/findings': () => import('@/features/findings/FindingsPage'),
  '/bug-bounty': () => import('@/pages/BugBountyDashboardPage'),
  '/settings': () => import('@/pages/SettingsPage'),
  '/cockpit': () => import('@/pages/CockpitPage'),
  '/replay': () => import('@/components/ReplayInterface'),
  '/pipeline': () => import('@/pages/PipelineOverviewPage'),
  '/risk': () => import('@/pages/RiskHubPage'),
  '/risk-score': () => import('@/pages/RiskHubPage'),
  '/findings-timeline': () => import('@/pages/FindingsTimelinePage'),
  '/target-comparison': () => import('@/pages/TargetComparison'),
  '/scan-diff': () => import('@/pages/ScanDiffPage'),
  '/remediation-planner': () => import('@/pages/RiskHubPage'),
  '/gap-analysis': () => import('@/pages/DetectionQualityPage'),
  '/learning': () => import('@/pages/DetectionQualityPage'),
  '/detection-quality': () => import('@/pages/DetectionQualityPage'),
  '/mesh': () => import('@/pages/MeshHealthPage'),
  '/security': () => import('@/pages/SecurityResiliencePage'),
  '/tracing': () => import('@/pages/TracingPage'),
  '/audit-logs': () => import('@/components/AuditLogViewer'),
  '/compliance': () => import('@/pages/GovernanceHubPage'),
  '/reports': () => import('@/pages/ReportLibraryPage'),
  '/reports/builder': () => import('@/pages/ReportBuilderPage'),
  '/access-logs': () => import('@/components/ComplianceLogViewer'),
  '/evidence-custody': () => import('@/pages/EvidenceCustodyPage'),
  '/self-healing': () => import('@/pages/SecurityResiliencePage'),
  '/evasion': () => import('@/pages/EvasionMetricsPage'),
  '/risk/acceptance': () => import('@/pages/RiskHubPage'),
  '/risk/assets': () => import('@/pages/RiskHubPage'),
  '/governance': () => import('@/pages/GovernanceHubPage'),
};

export function prefetchRoute(path: string) {
  const loader = ROUTE_PREFETCH_MAP[path];
  if (loader) {
    loader().catch(() => {});
  }
}
