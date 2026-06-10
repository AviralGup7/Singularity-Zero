import { Suspense, lazy, useState, useEffect, Component, type ReactNode } from 'react';
import { Routes, Route, Navigate, useLocation, useParams } from 'react-router-dom';
import { CoreProviders } from '@/context/CoreProviders';
import { AppLayout } from '@/components/layout/AppLayout';
import { RouteGuard } from '@/components/RouteGuard';
import { RouteFocusManager } from '@/components/ui/RouteFocusManager';
import { PageTransition } from '@/components/motion/PageTransition';
import { getLiveness } from '@/api/health';
import { syncServerTime } from '@/lib/timeSync';
import { errorTracker } from '@/utils/errorTracker';
import { LoginPage } from '@/pages/LoginPage';
import { NotFoundPage } from '@/pages/NotFoundPage';
import { useAuthStore } from '@/stores/authStore';
import { useEventLogStore } from '@/stores/eventLogStore';
import { validateEvidenceId } from '@/utils/routeValidation';

// --- Lazy Page Imports ---
const DashboardPage = lazy(() => import('@/pages/DashboardPage').then(m => ({ default: m.DashboardPage })));
const TargetsPage = lazy(() => import('@/pages/TargetsPage').then(m => ({ default: m.TargetsPage })));
const JobsPage = lazy(() => import('@/pages/JobsPage').then(m => ({ default: m.JobsPage })));
const JobDetailPage = lazy(() => import('@/pages/JobDetailPage').then(m => ({ default: m.JobDetailPage })));
const FindingsPage = lazy(() => import('@/pages/findings/FindingsPage').then(m => ({ default: m.FindingsPage })));
const BugBountyDashboardPage = lazy(() => import('@/pages/BugBountyDashboardPage').then(m => ({ default: m.BugBountyDashboardPage })));
const SettingsPage = lazy(() => import('@/pages/SettingsPage').then(m => ({ default: m.SettingsPage })));
const CockpitPage = lazy(() => import('@/pages/CockpitPage').then(m => ({ default: m.CockpitPage })));
const ReplayPage = lazy(() => import('@/pages/ReplayPage').then(m => ({ default: m.ReplayPage })));
const CacheManagementPage = lazy(() => import('@/pages/CacheManagementPage').then(m => ({ default: m.CacheManagementPage })));
const PipelineOverviewPage = lazy(() => import('@/pages/PipelineOverviewPage').then(m => ({ default: m.PipelineOverviewPage })));
const RiskScorePage = lazy(() => import('@/pages/RiskScorePage').then(m => ({ default: m.RiskScorePage })));
const FindingsTimelinePage = lazy(() => import('@/pages/FindingsTimelinePage').then(m => ({ default: m.FindingsTimelinePage })));
const TargetComparison = lazy(() => import('@/pages/TargetComparison').then(m => ({ default: m.TargetComparison })));
const ScanDiffPage = lazy(() => import('@/pages/ScanDiffPage').then(m => ({ default: m.ScanDiffPage })));
const RemediationPlanner = lazy(() => import('@/pages/RemediationPlanner').then(m => ({ default: m.RemediationPlanner })));
const GapAnalysisPage = lazy(() => import('@/pages/GapAnalysisPage').then(m => ({ default: m.GapAnalysisPage })));
const LearningPage = lazy(() => import('@/pages/LearningPage').then(m => ({ default: m.LearningPage })));
const MeshHealthPage = lazy(() => import('@/pages/MeshHealthPage').then(m => ({ default: m.MeshHealthPage })));
const TracingPage = lazy(() => import('@/pages/TracingPage').then(m => ({ default: m.TracingPage })));
const SecurityPage = lazy(() => import('@/pages/SecurityPage').then(m => ({ default: m.SecurityPage })));
const AuditLogViewer = lazy(() => import('@/components/AuditLogViewer').then(m => ({ default: m.AuditLogViewer })));
const ComplianceDashboard = lazy(() => import('@/pages/ComplianceDashboard').then(m => ({ default: m.ComplianceDashboard })));
const ReportLibraryPage = lazy(() => import('@/pages/ReportLibraryPage').then(m => ({ default: m.ReportLibraryPage })));
const ReportBuilderPage = lazy(() => import('@/pages/ReportBuilderPage').then(m => ({ default: m.ReportBuilderPage })));
const AccessLogsPage = lazy(() => import('@/components/ComplianceLogViewer').then(m => ({ default: m.ComplianceLogViewer })));
const EvidenceCustodyViewer = lazy(() => import('@/components/common/EvidenceCustodyViewer').then(m => ({ default: m.EvidenceCustodyViewer })));
const EvidenceCustodyPage = lazy(() => import('@/pages/EvidenceCustodyPage').then(m => ({ default: m.EvidenceCustodyPage })));
const SelfHealingPage = lazy(() => import('@/pages/SelfHealingPage').then(m => ({ default: m.SelfHealingPage })));
const EvasionMetricsPage = lazy(() => import('@/pages/EvasionMetricsPage').then(m => ({ default: m.EvasionMetricsPage })));
const AcceptancePage = lazy(() => import('@/pages/AcceptancePage').then(m => ({ default: m.AcceptancePage })));
const AssetCriticalityPage = lazy(() => import('@/pages/AssetCriticalityPage').then(m => ({ default: m.AssetCriticalityPage })));
const TracePage = lazy(() => import('@/pages/TracePage').then(m => ({ default: m.TracePage })));

/** Route-level prefetch map — triggers chunk download on hover/focus */
const ROUTE_PREFETCH_MAP: Record<string, () => Promise<unknown>> = {
  '/': () => import('@/pages/DashboardPage'),
  '/targets': () => import('@/pages/TargetsPage'),
  '/jobs': () => import('@/pages/JobsPage'),
  '/findings': () => import('@/pages/findings/FindingsPage'),
  '/bug-bounty': () => import('@/pages/BugBountyDashboardPage'),
  '/settings': () => import('@/pages/SettingsPage'),
  '/cockpit': () => import('@/pages/CockpitPage'),
  '/replay': () => import('@/pages/ReplayPage'),
  '/pipeline': () => import('@/pages/PipelineOverviewPage'),
  '/risk-score': () => import('@/pages/RiskScorePage'),
  '/findings-timeline': () => import('@/pages/FindingsTimelinePage'),
  '/target-comparison': () => import('@/pages/TargetComparison'),
  '/scan-diff': () => import('@/pages/ScanDiffPage'),
  '/remediation-planner': () => import('@/pages/RemediationPlanner'),
  '/gap-analysis': () => import('@/pages/GapAnalysisPage'),
  '/learning': () => import('@/pages/LearningPage'),
  '/mesh': () => import('@/pages/MeshHealthPage'),
  '/tracing': () => import('@/pages/TracingPage'),
  '/security': () => import('@/pages/SecurityPage'),
  '/cache-management': () => import('@/pages/CacheManagementPage'),
  '/audit-logs': () => import('@/components/AuditLogViewer'),
  '/compliance': () => import('@/pages/ComplianceDashboard'),
  '/reports': () => import('@/pages/ReportLibraryPage'),
  '/reports/builder': () => import('@/pages/ReportBuilderPage'),
  '/access-logs': () => import('@/components/ComplianceLogViewer'),
  '/evidence-custody': () => import('@/pages/EvidenceCustodyPage'),
  '/self-healing': () => import('@/pages/SelfHealingPage'),
  '/evasion': () => import('@/pages/EvasionMetricsPage'),
  '/risk/acceptance': () => import('@/pages/AcceptancePage'),
  '/risk/assets': () => import('@/pages/AssetCriticalityPage'),
  '/trace': () => import('@/pages/TracePage'),
};

export function prefetchRoute(path: string) {
  const loader = ROUTE_PREFETCH_MAP[path];
  if (loader) {
    loader().catch(() => {});
  }
}

function ContentFallback() {
  return (
    <div className="flex-1 flex items-center justify-center">
      <div className="flex flex-col items-center gap-3">
        <div className="h-5 w-5 border-2 border-accent/30 border-t-accent rounded-full animate-spin" />
        <span className="text-xs font-mono uppercase tracking-widest text-muted">Loading…</span>
      </div>
    </div>
  );
}

function ChunkLoadErrorFallback({ error, onRetry }: { error: Error; onRetry: () => void }) {
  const isChunkError = error.message?.includes('Failed to fetch') ||
    error.message?.includes('Loading chunk') ||
    error.message?.includes('Importing a module script') ||
    error.name === 'ChunkLoadError' ||
    error.name === 'TypeError';

  return (
    <div className="flex flex-col items-center justify-center p-12 text-center" role="alert" aria-live="assertive">
      <div className="text-4xl mb-4" aria-hidden="true">📦</div>
      <h2 className="text-lg font-bold text-[var(--text-primary)] mb-2">Failed to load page</h2>
      <p className="text-sm text-[var(--text-secondary)] mb-3">
        {isChunkError
          ? 'The page module could not be downloaded. This may be due to a network issue or a new deployment.'
          : 'An error occurred while loading this page.'}
      </p>
      <div className="flex gap-2">
        <button className="btn btn-primary text-sm" onClick={onRetry} aria-label="Retry loading page">
          Retry
        </button>
        <button
          className="btn btn-secondary text-sm"
          onClick={() => window.location.reload()}
          aria-label="Reload entire page"
        >
          Reload Page
        </button>
      </div>
    </div>
  );
}

class SuspenseErrorBoundary extends Component<
  { children: ReactNode; onRetry?: () => void },
  { hasError: boolean; error: Error | null }
> {
  state = { hasError: false, error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error) {
    console.error('[SuspenseErrorBoundary]', error);
    errorTracker.track(error, {
      component: 'SuspenseErrorBoundary',
      action: 'chunk_load_error',
    });
  }

  render() {
    if (this.state.hasError && this.state.error) {
      return <ChunkLoadErrorFallback error={this.state.error} onRetry={() => {
        this.setState({ hasError: false, error: null });
        this.props.onRetry?.();
      }} />;
    }
    return this.props.children;
  }
}

function RouteWatcher() {
  const location = useLocation();
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [location.pathname]);
  return null;
}

class RouteErrorBoundary extends Component<
  { children: ReactNode },
  { hasError: boolean; error: Error | null; retryCount: number; crashId: string }
> {
  state = { hasError: false, error: null as Error | null, retryCount: 0, crashId: '' };

  static getDerivedStateFromError(error: Error) {
    const crashId = `RTE-${Date.now().toString(36).toUpperCase()}`;
    return { hasError: true, error, crashId };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('[RouteErrorBoundary]', error);
    errorTracker.track(error, {
      component: 'RouteErrorBoundary',
      action: 'route_crash',
      metadata: { componentStack: errorInfo.componentStack, crashId: this.state.crashId },
    });
  }

  handleRetry = () => {
    this.setState(prev => ({
      hasError: false,
      error: null,
      retryCount: prev.retryCount + 1,
      crashId: '',
    }));
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center p-12 text-center" role="alert" aria-live="assertive">
          <div className="text-4xl mb-4" aria-hidden="true">⚠️</div>
          <h2 className="text-lg font-bold text-[var(--text-primary)] mb-2">Something went wrong</h2>
          <p className="text-sm text-[var(--text-secondary)] mb-3">
            {this.state.error?.message || 'This section encountered an unexpected error.'}
          </p>
          <p className="text-[11px] font-mono text-[var(--text-tertiary)] mb-4">
            Crash ID: {this.state.crashId}{this.state.retryCount > 0 ? ` · Retry #${this.state.retryCount}` : ''}
          </p>
          <div className="flex gap-2">
            <button className="btn btn-primary text-sm" onClick={this.handleRetry} aria-label="Try again">
              Try Again
            </button>
            <a href="/" className="btn btn-secondary text-sm" aria-label="Go to dashboard">
              Go to Dashboard
            </a>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function EvidenceCustodyViewerWrapper() {
  const { evidenceId } = useParams<{ evidenceId: string }>();
  const validId = validateEvidenceId(evidenceId);
  if (!validId) return <Navigate to="/" replace />;
  return <EvidenceCustodyViewer evidenceId={validId} />;
}

function RouteElement({ children }: { children: React.ReactNode }) {
  const [retryKey, setRetryKey] = useState(0);
  return (
    <PageTransition>
      <RouteErrorBoundary key={`route-${retryKey}`}>
        <SuspenseErrorBoundary onRetry={() => setRetryKey(k => k + 1)}>
          <Suspense fallback={<ContentFallback />} key={retryKey}>
            {children}
          </Suspense>
        </SuspenseErrorBoundary>
      </RouteErrorBoundary>
    </PageTransition>
  );
}

export default function App() {
  useEffect(() => {
    getLiveness()
      .then(res => {
        if (res.timestamp) syncServerTime(res.timestamp);
      })
      .catch(err => {
        errorTracker.track(err, { component: 'App', action: 'telemetry-sync' });
        console.warn('[SYSTEM] Initial telemetry sync failed. Backend may be offline.');
      });
  }, []);

  useEffect(() => {
    useAuthStore.getState().hydrateAuth();
  }, []);

  useEffect(() => {
    const interval = setInterval(() => {
      useEventLogStore.getState().prune();
    }, 5 * 60 * 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <CoreProviders>
      <RouteWatcher />
      <RouteFocusManager />
      <AppLayout>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/" element={<RouteGuard><RouteElement><DashboardPage /></RouteElement></RouteGuard>} />
          <Route path="/targets" element={<RouteGuard><RouteElement><TargetsPage /></RouteElement></RouteGuard>} />
          <Route path="/jobs" element={<RouteGuard><RouteElement><JobsPage /></RouteElement></RouteGuard>} />
          <Route path="/jobs/:id" element={<RouteGuard><RouteElement><JobDetailPage /></RouteElement></RouteGuard>} />
          <Route path="/findings" element={<RouteGuard><RouteElement><FindingsPage /></RouteElement></RouteGuard>} />
          <Route path="/bug-bounty" element={<RouteGuard><RouteElement><BugBountyDashboardPage /></RouteElement></RouteGuard>} />
          <Route path="/pipeline" element={<RouteGuard><RouteElement><PipelineOverviewPage /></RouteElement></RouteGuard>} />
          <Route path="/settings" element={<RouteGuard><RouteElement><SettingsPage /></RouteElement></RouteGuard>} />
          <Route path="/cockpit" element={<RouteGuard><RouteElement><CockpitPage /></RouteElement></RouteGuard>} />
          <Route path="/replay" element={<RouteGuard><RouteElement><ReplayPage /></RouteElement></RouteGuard>} />
          <Route path="/cache-management" element={<RouteGuard requiredRole="admin"><RouteElement><CacheManagementPage /></RouteElement></RouteGuard>} />
          <Route path="/risk-score" element={<RouteGuard><RouteElement><RiskScorePage /></RouteElement></RouteGuard>} />
          <Route path="/findings-timeline" element={<RouteGuard><RouteElement><FindingsTimelinePage /></RouteElement></RouteGuard>} />
          <Route path="/target-comparison" element={<RouteGuard><RouteElement><TargetComparison /></RouteElement></RouteGuard>} />
          <Route path="/scan-diff" element={<RouteGuard><RouteElement><ScanDiffPage /></RouteElement></RouteGuard>} />
          <Route path="/remediation-planner" element={<RouteGuard><RouteElement><RemediationPlanner /></RouteElement></RouteGuard>} />
          <Route path="/gap-analysis" element={<RouteGuard><RouteElement><GapAnalysisPage /></RouteElement></RouteGuard>} />
          <Route path="/learning" element={<RouteGuard><RouteElement><LearningPage /></RouteElement></RouteGuard>} />
          <Route path="/mesh" element={<RouteGuard><RouteElement><MeshHealthPage /></RouteElement></RouteGuard>} />
          <Route path="/security" element={<RouteGuard requiredRole="admin"><RouteElement><SecurityPage /></RouteElement></RouteGuard>} />
          <Route path="/tracing" element={<RouteGuard><RouteElement><TracingPage /></RouteElement></RouteGuard>} />
          <Route path="/audit-logs" element={<RouteGuard requiredPermission="viewAuditLogs"><RouteElement><AuditLogViewer /></RouteElement></RouteGuard>} />
          <Route path="/compliance" element={<RouteGuard><RouteElement><ComplianceDashboard /></RouteElement></RouteGuard>} />
          <Route path="/reports" element={<RouteGuard requiredPermission="viewAuditLogs"><RouteElement><ReportLibraryPage /></RouteElement></RouteGuard>} />
          <Route path="/reports/builder" element={<RouteGuard requiredPermission="viewAuditLogs"><RouteElement><ReportBuilderPage /></RouteElement></RouteGuard>} />
          <Route path="/access-logs" element={<RouteGuard><RouteElement><AccessLogsPage /></RouteElement></RouteGuard>} />
          <Route path="/evidence-custody" element={<RouteGuard><RouteElement><EvidenceCustodyPage /></RouteElement></RouteGuard>} />
          <Route path="/evidence-custody/:evidenceId" element={<RouteGuard><RouteElement><EvidenceCustodyViewerWrapper /></RouteElement></RouteGuard>} />
          <Route path="/self-healing" element={<RouteGuard><RouteElement><SelfHealingPage /></RouteElement></RouteGuard>} />
          <Route path="/evasion" element={<RouteGuard><RouteElement><EvasionMetricsPage /></RouteElement></RouteGuard>} />
          <Route path="/risk/acceptance" element={<RouteGuard><RouteElement><AcceptancePage /></RouteElement></RouteGuard>} />
          <Route path="/risk/assets" element={<RouteGuard><RouteElement><AssetCriticalityPage /></RouteElement></RouteGuard>} />
          <Route path="/trace" element={<RouteGuard><RouteElement><TracePage /></RouteElement></RouteGuard>} />
          <Route path="*" element={<RouteGuard><RouteElement><NotFoundPage /></RouteElement></RouteGuard>} />
        </Routes>
      </AppLayout>
    </CoreProviders>
  );
}
