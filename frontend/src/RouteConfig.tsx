import { Suspense, useState, useEffect, useRef, Component   } from 'react';
import type {ReactNode} from 'react';
import { Routes, Route, Navigate, useParams, useLocation } from 'react-router-dom';
import { lazyWithPrefetch } from '@/PrefetchRegistry';
import { RouteGuard } from '@/components/RouteGuard';
import { PageTransition } from '@/components/motion/PageTransition';
import { errorTracker } from '@/utils/errorTracker';
import { validateEvidenceId } from '@/utils/routeValidation';
import ReplayInterface from '@/components/ReplayInterface';
import { Breadcrumbs } from '@/components/ui/Breadcrumbs';
import { LoadingBar } from '@/components/ui/LoadingBar';
import { useAutoBreadcrumbs } from '@/hooks/useAutoBreadcrumbs';
import { LoginPage } from '@/pages/LoginPage';
import { NotFoundPage } from '@/pages/NotFoundPage';

const DashboardPage = lazyWithPrefetch('/', () => import('@/pages/DashboardPage').then(m => ({ default: m.DashboardPage })));
const TargetsPage = lazyWithPrefetch('/targets', () => import('@/pages/TargetsPage').then(m => ({ default: m.TargetsPage })));
const JobsPage = lazyWithPrefetch('/jobs', () => import('@/pages/JobsPage').then(m => ({ default: m.JobsPage })));
const JobDetailPage = lazyWithPrefetch('/jobs/:id', () => import('@/pages/JobDetailPage').then(m => ({ default: m.JobDetailPage })));
const FindingsPage = lazyWithPrefetch('/findings', () => import('@/features/findings/FindingsPage').then(m => ({ default: m.FindingsPage })));
const BugBountyDashboardPage = lazyWithPrefetch('/bug-bounty', () => import('@/pages/BugBountyDashboardPage').then(m => ({ default: m.BugBountyDashboardPage })));
const SettingsPage = lazyWithPrefetch('/settings', () => import('@/pages/SettingsPage').then(m => ({ default: m.SettingsPage })));
const CockpitPage = lazyWithPrefetch('/cockpit', () => import('@/pages/CockpitPage').then(m => ({ default: m.CockpitPage })));
const CacheManagementPage = lazyWithPrefetch('/cache-management', () => import('@/pages/CacheManagementPage').then(m => ({ default: m.CacheManagementPage })));
const PipelineOverviewPage = lazyWithPrefetch('/pipeline', () => import('@/pages/PipelineOverviewPage').then(m => ({ default: m.PipelineOverviewPage })));
const RiskHubPage = lazyWithPrefetch('/risk', () => import('@/pages/RiskHubPage').then(m => ({ default: m.RiskHubPage })));
const SecurityPage = lazyWithPrefetch('/security', () => import('@/pages/SecurityResiliencePage').then(m => ({ default: m.SecurityResiliencePage })));
const DetectionQualityPage = lazyWithPrefetch('/detection-quality', () => import('@/pages/DetectionQualityPage').then(m => ({ default: m.DetectionQualityPage })));
const GovernanceHubPage = lazyWithPrefetch('/governance', () => import('@/pages/GovernanceHubPage').then(m => ({ default: m.GovernanceHubPage })));
const ReportLibraryPage = lazyWithPrefetch('/reports', () => import('@/pages/ReportLibraryPage').then(m => ({ default: m.ReportLibraryPage })));
const ReportBuilderPage = lazyWithPrefetch('/reports/builder', () => import('@/pages/ReportBuilderPage').then(m => ({ default: m.ReportBuilderPage })));
const AnalyticsHubPage = lazyWithPrefetch('/analytics', () => import('@/pages/AnalyticsHubPage').then(m => ({ default: m.AnalyticsHubPage })));
const AuditLogViewer = lazyWithPrefetch('/audit-logs', () => import('@/components/AuditLogViewer').then(m => ({ default: m.AuditLogViewer })));
const EvidenceCustodyViewer = lazyWithPrefetch('/evidence-custody/:evidenceId', () => import('@/components/common/ChainOfCustodyViewer').then(m => ({ default: m.ChainOfCustodyViewer })));
const FindingsTimelinePage = lazyWithPrefetch('/findings-timeline', () => import('@/pages/FindingsTimelinePage').then(m => ({ default: m.FindingsTimelinePage })));
const TargetComparison = lazyWithPrefetch('/target-comparison', () => import('@/pages/TargetComparison').then(m => ({ default: m.TargetComparison })));
const ScanDiffPage = lazyWithPrefetch('/scan-diff', () => import('@/pages/ScanDiffPage').then(m => ({ default: m.ScanDiffPage })));
const MeshHealthPage = lazyWithPrefetch('/mesh', () => import('@/pages/MeshHealthPage').then(m => ({ default: m.MeshHealthPage })));
const TracingPage = lazyWithPrefetch('/tracing', () => import('@/pages/TracingPage').then(m => ({ default: m.TracingPage })));
const EvasionMetricsPage = lazyWithPrefetch('/evasion', () => import('@/pages/EvasionMetricsPage').then(m => ({ default: m.EvasionMetricsPage })));

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
        <h2 className="text-lg font-bold text-text-primary mb-2">Failed to load page</h2>
        <p className="text-sm text-text-secondary mb-3">
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
  override state = { hasError: false, error: null as Error | null };

  override componentDidCatch(error: Error) {
    this.setState({ hasError: true, error });
    console.error('[SuspenseErrorBoundary]', error);
    errorTracker.track(error, {
      component: 'SuspenseErrorBoundary',
      action: 'chunk_load_error',
    });
  }

  override render() {
    if (this.state.hasError && this.state.error) {
      return <ChunkLoadErrorFallback error={this.state.error} onRetry={() => {
        this.setState({ hasError: false, error: null });
        this.props.onRetry?.();
      }} />;
    }
    return this.props.children;
  }
}

class RouteErrorBoundary extends Component<
  { children: ReactNode },
  { hasError: boolean; error: Error | null; retryCount: number; crashId: string }
> {
  override state = { hasError: false, error: null as Error | null, retryCount: 0, crashId: '' };

  override componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    const crashId = `RTE-${Date.now().toString(36).toUpperCase()}`;
    this.setState({ hasError: true, error, crashId });
    console.error('[RouteErrorBoundary]', error);
    errorTracker.track(error, {
      component: 'RouteErrorBoundary',
      action: 'route_crash',
      metadata: { componentStack: errorInfo.componentStack, crashId },
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

  override render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center p-12 text-center" role="alert" aria-live="assertive">
          <div className="text-4xl mb-4" aria-hidden="true">⚠️</div>
          <h2 className="text-lg font-bold text-text-primary mb-2">Something went wrong</h2>
          <p className="text-sm text-text-secondary mb-3">
            {this.state.error?.message || 'This section encountered an unexpected error.'}
          </p>
          <p className="text-[11px] font-mono text-text-tertiary mb-4">
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

function ReplayPageRoute() {
  const crumbs = useAutoBreadcrumbs();
  const headingRef = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    const el = headingRef.current;
    if (el) {
      el.setAttribute('tabindex', '-1');
      el.focus({ preventScroll: false });
    }
  }, []);
  return (
    <div className="replay-page">
      <h1 ref={headingRef} className="sr-only" data-page-heading>Replay Request</h1>
      <Breadcrumbs items={crumbs} />
      <ReplayInterface />
    </div>
  );
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

function RouteWatcher() {
  const location = useLocation();
  const previousPathRef = useRef(location.pathname);
  useEffect(() => {
    window.scrollTo(0, 0);
    if (previousPathRef.current !== location.pathname) {
      const heading = document.querySelector<HTMLElement>('main h1, main h2, [data-page-heading]');
      if (heading) {
        heading.setAttribute('tabindex', '-1');
        heading.focus({ preventScroll: false });
      } else {
        const main = document.querySelector<HTMLElement>('main');
        if (main) {
          main.setAttribute('tabindex', '-1');
          main.focus({ preventScroll: false });
        }
      }
      previousPathRef.current = location.pathname;
    }
  }, [location.pathname]);
  return null;
}

export function RouteConfig() {
  return (
    <>
      <LoadingBar />
      <RouteWatcher />
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
      <Route path="/replay" element={<RouteGuard><RouteElement><ReplayPageRoute /></RouteElement></RouteGuard>} />
      <Route path="/cache-management" element={<RouteGuard requiredRole="admin"><RouteElement><CacheManagementPage /></RouteElement></RouteGuard>} />
      <Route path="/risk" element={<RouteGuard><RouteElement><RiskHubPage /></RouteElement></RouteGuard>} />
      <Route path="/findings-timeline" element={<RouteGuard><RouteElement><FindingsTimelinePage /></RouteElement></RouteGuard>} />
      <Route path="/target-comparison" element={<RouteGuard><RouteElement><TargetComparison /></RouteElement></RouteGuard>} />
      <Route path="/scan-diff" element={<RouteGuard><RouteElement><ScanDiffPage /></RouteElement></RouteGuard>} />
      <Route path="/mesh" element={<RouteGuard><RouteElement><MeshHealthPage /></RouteElement></RouteGuard>} />
      <Route path="/security" element={<RouteGuard><RouteElement><SecurityPage /></RouteElement></RouteGuard>} />
      <Route path="/detection-quality" element={<RouteGuard><RouteElement><DetectionQualityPage /></RouteElement></RouteGuard>} />
      <Route path="/tracing" element={<RouteGuard><RouteElement><TracingPage /></RouteElement></RouteGuard>} />
      <Route path="/audit-logs" element={<RouteGuard requiredPermission="viewAuditLogs"><RouteElement><AuditLogViewer /></RouteElement></RouteGuard>} />
      <Route path="/reports" element={<RouteGuard requiredPermission="viewAuditLogs"><RouteElement><ReportLibraryPage /></RouteElement></RouteGuard>} />
      <Route path="/reports/builder" element={<RouteGuard requiredPermission="viewAuditLogs"><RouteElement><ReportBuilderPage /></RouteElement></RouteGuard>} />
      <Route path="/evidence-custody/:evidenceId" element={<RouteGuard><RouteElement><EvidenceCustodyViewerWrapper /></RouteElement></RouteGuard>} />
      <Route path="/evasion" element={<RouteGuard><RouteElement><EvasionMetricsPage /></RouteElement></RouteGuard>} />
      <Route path="/governance" element={<RouteGuard><RouteElement><GovernanceHubPage /></RouteElement></RouteGuard>} />
      <Route path="/analytics" element={<RouteGuard><RouteElement><AnalyticsHubPage /></RouteElement></RouteGuard>} />
      <Route path="*" element={<RouteGuard><RouteElement><NotFoundPage /></RouteElement></RouteGuard>} />
    </Routes>
    </>
  );
}
