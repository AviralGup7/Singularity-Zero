import { Routes, Route, Navigate, useLocation, useParams } from 'react-router-dom';
import { lazy, useEffect } from 'react';

import { CoreProviders } from '@/context/CoreProviders';
import { AppLayout } from '@/components/layout/AppLayout';
import { RouteGuard } from '@/components/RouteGuard';
import { getLiveness } from '@/api/health';
import { syncServerTime } from '@/lib/timeSync';

// --- Page Imports ---
const DashboardPage = lazy(() => import('@/pages/DashboardPage').then(m => ({ default: m.DashboardPage })));
const LoginPage = lazy(() => import('@/pages/LoginPage').then(m => ({ default: m.LoginPage })));
const TargetsPage = lazy(() => import('@/pages/TargetsPage').then(m => ({ default: m.TargetsPage })));
const JobsPage = lazy(() => import('@/pages/JobsPage').then(m => ({ default: m.JobsPage })));
const JobDetailPage = lazy(() => import('@/pages/JobDetailPage').then(m => ({ default: m.JobDetailPage })));
const FindingsPage = lazy(() => import('@/pages/findings/FindingsPage').then(m => ({ default: m.FindingsPage })));
const SettingsPage = lazy(() => import('@/pages/SettingsPage').then(m => ({ default: m.SettingsPage })));
const CockpitPage = lazy(() => import('@/pages/CockpitPage').then(m => ({ default: m.CockpitPage })));
const ReplayPage = lazy(() => import('@/pages/ReplayPage').then(m => ({ default: m.ReplayPage })));
const CacheManagementPage = lazy(() => import('@/pages/CacheManagementPage').then(m => ({ default: m.CacheManagementPage })));
const PipelineOverviewPage = lazy(() => import('@/pages/PipelineOverviewPage').then(m => ({ default: m.PipelineOverviewPage })));
const RiskScorePage = lazy(() => import('@/pages/RiskScorePage').then(m => ({ default: m.RiskScorePage })));
const FindingsTimelinePage = lazy(() => import('@/pages/FindingsTimelinePage').then(m => ({ default: m.FindingsTimelinePage })));
const TargetComparison = lazy(() => import('@/pages/TargetComparison').then(m => ({ default: m.TargetComparison })));
const GapAnalysisPage = lazy(() => import('@/pages/GapAnalysisPage').then(m => ({ default: m.GapAnalysisPage })));
const MeshHealthPage = lazy(() => import('@/pages/MeshHealthPage').then(m => ({ default: m.MeshHealthPage })));
const TracingPage = lazy(() => import('@/pages/TracingPage').then(m => ({ default: m.TracingPage })));
const SecurityPage = lazy(() => import('@/pages/SecurityPage').then(m => ({ default: m.SecurityPage })));
const AuditLogViewer = lazy(() => import('@/components/AuditLogViewer').then(m => ({ default: m.AuditLogViewer })));
const ComplianceLogViewer = lazy(() => import('@/components/ComplianceLogViewer').then(m => ({ default: m.ComplianceLogViewer })));
const EvidenceCustodyViewer = lazy(() => import('@/components/common/EvidenceCustodyViewer').then(m => ({ default: m.EvidenceCustodyViewer })));

function RouteWatcher() {
  const location = useLocation();
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [location.pathname]);
  return null;
}

function EvidenceCustodyViewerWrapper() {
  const { evidenceId } = useParams<{ evidenceId: string }>();
  if (!evidenceId) return <Navigate to="/" replace />;
  return <EvidenceCustodyViewer evidenceId={evidenceId} />;
}

export default function App() {
  // --- Overhaul: High-Resolution Time Sync ---
  useEffect(() => {
    getLiveness()
      .then(res => {
        if (res.timestamp) syncServerTime(res.timestamp);
      })
      .catch(() => {
        console.warn('[SYSTEM] Initial telemetry sync failed. Backend may be offline.');
      });
  }, []);

  return (
    <CoreProviders>
      <RouteWatcher />
      <AppLayout>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/" element={<RouteGuard><DashboardPage /></RouteGuard>} />
          <Route path="/targets" element={<RouteGuard><TargetsPage /></RouteGuard>} />
          <Route path="/jobs" element={<RouteGuard><JobsPage /></RouteGuard>} />
          <Route path="/jobs/:id" element={<RouteGuard><JobDetailPage /></RouteGuard>} />
          <Route path="/findings" element={<RouteGuard><FindingsPage /></RouteGuard>} />
          <Route path="/pipeline" element={<RouteGuard><PipelineOverviewPage /></RouteGuard>} />
          <Route path="/settings" element={<RouteGuard><SettingsPage /></RouteGuard>} />
          <Route path="/cockpit" element={<RouteGuard><CockpitPage /></RouteGuard>} />
          <Route path="/replay" element={<RouteGuard><ReplayPage /></RouteGuard>} />
          <Route path="/cache-management" element={<RouteGuard requiredRole="admin"><CacheManagementPage /></RouteGuard>} />
          <Route path="/risk-score" element={<RouteGuard><RiskScorePage /></RouteGuard>} />
          <Route path="/findings-timeline" element={<RouteGuard><FindingsTimelinePage /></RouteGuard>} />
          <Route path="/target-comparison" element={<RouteGuard><TargetComparison /></RouteGuard>} />
          <Route path="/gap-analysis" element={<RouteGuard><GapAnalysisPage /></RouteGuard>} />
          <Route path="/mesh" element={<RouteGuard><MeshHealthPage /></RouteGuard>} />
          <Route path="/security" element={<RouteGuard requiredRole="admin"><SecurityPage /></RouteGuard>} />
          <Route path="/tracing" element={<RouteGuard><TracingPage /></RouteGuard>} />
          <Route path="/audit-logs" element={<RouteGuard requiredPermission="viewAuditLogs"><AuditLogViewer /></RouteGuard>} />
          <Route path="/compliance" element={<RouteGuard><ComplianceLogViewer /></RouteGuard>} />
          <Route path="/evidence-custody/:evidenceId" element={<RouteGuard><EvidenceCustodyViewerWrapper /></RouteGuard>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AppLayout>
    </CoreProviders>
  );
}
