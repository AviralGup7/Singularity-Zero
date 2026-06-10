import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useState, useEffect, useCallback, useRef, useMemo, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { motion } from 'framer-motion';
import { APP_VERSION } from '../../config';
import { useTheme } from '@/hooks/useTheme';
import { useAuth } from '@/hooks/useAuth';
import { CommandPalette } from './CommandPalette';
import { emitSearchItems, emitRefresh } from '../../lib/events';
import { useCommandPaletteItems, getAllItems } from '../../hooks/useCommandPaletteItems';
import { useWebSocket } from '../../hooks/useWebSocket';
import { useMotionPolicy } from '../../hooks/useMotionPolicy';
import { useDisplayStore } from '@/stores/displayStore';
import type { SearchableItem } from './CommandPalette';
import { useToast } from '@/hooks/useToast';
import { useNotifications } from '@/hooks/useNotifications';
import { Icon } from '../ui/Icon';
import { useHealthStatus } from '@/hooks/useHealthStatus';

import { Sidebar } from './Sidebar';
import { Header } from './Header';
import { Footer } from './Footer';
import { ShortcutsModal } from './ShortcutsModal';
import { ScanStatusBar } from '@/components/ScanStatusBar';

interface NavSection {
  label: string;
  items: { path: string; label: string; icon: string; key?: string; count?: string }[];
}

function useNavSections(): NavSection[] {
  const { t } = useTranslation();
  const workflowMode = useDisplayStore((state) => state.workflowMode);
  return useMemo(() => {
    const overview = [
      { path: '/', label: 'Dashboard', icon: 'barChart', count: '1' },
      { path: '/targets', label: t('navigation.targets'), icon: 'target', count: '2' },
      { path: '/jobs', label: t('navigation.jobs'), icon: 'zap', count: '3' },
      { path: '/findings', label: t('navigation.findings'), icon: 'shield', count: '4' },
      { path: '/bug-bounty', label: 'Bounty Dashboard', icon: 'bug', count: '6' },
    ];

    if (workflowMode === 'pentest') {
      return [
        { label: t('navigation.overview'), items: overview },
        {
          label: 'Analysis',
          items: [
            { path: '/pipeline', label: 'Pipeline Overview', icon: 'activity' },
            { path: '/cockpit', label: 'Security Cockpit', icon: 'target' },
            { path: '/remediation-planner', label: 'Remediation Planner', icon: 'checkCircle' },
            { path: '/risk-score', label: 'Risk Score', icon: 'alertTriangle' },
            { path: '/scan-diff', label: 'Scan Diff', icon: 'activity' },
            { path: '/findings-timeline', label: 'Findings Timeline', icon: 'activity' },
            { path: '/target-comparison', label: t('navigation.compare'), icon: 'activity' },
            { path: '/gap-analysis', label: t('navigation.gapAnalysis'), icon: 'shieldCheck' },
            { path: '/learning', label: 'Autonomous Learning', icon: 'zap' },
            { path: '/evasion', label: 'Evasion Metrics', icon: 'shield' },
          ],
        },
        {
          label: t('navigation.system'),
          items: [
            { path: '/mesh', label: 'Mesh Command', icon: 'server' },
            { path: '/self-healing', label: 'Self-Healing', icon: 'zap' },
            { path: '/tracing', label: 'Tracing', icon: 'activity' },
            { path: '/cache-management', label: 'Cache', icon: 'database' },
            { path: '/audit-logs', label: 'Audit Logs', icon: 'file' },
            { path: '/compliance', label: 'Compliance', icon: 'shieldCheck' },
            { path: '/reports', label: 'Reports', icon: 'fileText' },
            { path: '/access-logs', label: 'Access Logs', icon: 'fileText' },
            { path: '/evidence-custody', label: 'Evidence Chain', icon: 'link' },
            { path: '/security', label: 'Security', icon: 'shieldCheck' },
            { path: '/settings', label: t('navigation.settings'), icon: 'settings', count: 'S' },
          ],
        },
      ];
    }

    return [
      { label: t('navigation.overview'), items: overview },
      {
        label: 'Analysis',
        items: [
          { path: '/pipeline', label: 'Pipeline Overview', icon: 'activity' },
          { path: '/cockpit', label: 'Security Cockpit', icon: 'target' },
          { path: '/remediation-planner', label: 'Remediation Planner', icon: 'checkCircle' },
          { path: '/risk-score', label: 'Risk Score', icon: 'alertTriangle' },
          { path: '/target-comparison', label: t('navigation.compare'), icon: 'activity' },
          { path: '/scan-diff', label: 'Scan Diff', icon: 'activity' },
          { path: '/gap-analysis', label: t('navigation.gapAnalysis'), icon: 'shieldCheck' },
          { path: '/learning', label: 'Autonomous Learning', icon: 'zap' },
          { path: '/evasion', label: 'Evasion Metrics', icon: 'shield' },
        ],
      },
      {
        label: t('navigation.system'),
        items: [
          { path: '/mesh', label: 'Mesh Command', icon: 'server' },
          { path: '/self-healing', label: 'Self-Healing', icon: 'zap' },
          { path: '/tracing', label: 'Tracing', icon: 'activity' },
          { path: '/cache-management', label: 'Cache', icon: 'database' },
          { path: '/audit-logs', label: 'Audit Logs', icon: 'file' },
          { path: '/compliance', label: 'Compliance', icon: 'shieldCheck' },
          { path: '/reports', label: 'Reports', icon: 'fileText' },
          { path: '/access-logs', label: 'Access Logs', icon: 'fileText' },
          { path: '/evidence-custody', label: 'Evidence Chain', icon: 'link' },
          { path: '/security', label: 'Security', icon: 'shieldCheck' },
          { path: '/settings', label: t('navigation.settings'), icon: 'settings', count: 'S' },
        ],
      },
    ];
  }, [t, workflowMode]);
}

function buildDefaultNavItems(sections: NavSection[]): SearchableItem[] {
  return sections.flatMap(section =>
    section.items.map(item => ({
      id: `nav-${item.path}`,
      type: 'page' as const,
      title: item.label,
      subtitle: section.label,
      href: item.path,
    }))
  );
}

function buildDefaultActionItems(
  theme: { mode: string },
  themeUpdater: { setThemeMode: (mode: 'dark' | 'light') => void },
  toggleSidebar: () => void,
  toggleCommandPalette: () => void,
  navigate: (path: string) => void,
  toast: ReturnType<typeof useToast>,
): SearchableItem[] {
  return [
    {
      id: 'action-toggle-theme',
      type: 'action',
      title: 'Toggle Theme',
      subtitle: `Switch to ${theme.mode === 'dark' ? 'light' : 'dark'} mode`,
      meta: 'Theme',
      action: () => themeUpdater.setThemeMode(theme.mode === 'dark' ? 'light' : 'dark'),
    },
    {
      id: 'action-refresh',
      type: 'action',
      title: 'Force System Resync',
      subtitle: 'Trigger a full data refresh',
      meta: 'Data',
      action: () => {
        emitRefresh();
        toast.info('System resync requested');
      },
    },
    {
      id: 'action-toggle-sidebar',
      type: 'action',
      title: 'Toggle Sidebar',
      subtitle: 'Collapse or expand the navigation sidebar',
      meta: 'Layout',
      action: () => toggleSidebar(),
    },
    {
      id: 'action-go-findings',
      type: 'action',
      title: 'Go to Findings',
      subtitle: 'Jump to the findings triage surface',
      meta: 'Navigate',
      action: () => navigate('/findings'),
    },
    {
      id: 'action-go-jobs',
      type: 'action',
      title: 'Go to Jobs',
      subtitle: 'Jump to the active scan queue',
      meta: 'Navigate',
      action: () => navigate('/jobs'),
    },
    {
      id: 'action-go-targets',
      type: 'action',
      title: 'Go to Targets',
      subtitle: 'Open target management',
      meta: 'Navigate',
      action: () => navigate('/targets'),
    },
    {
      id: 'action-go-settings',
      type: 'action',
      title: 'Open Settings',
      subtitle: 'Configure display, motion, and notifications',
      meta: 'Navigate',
      action: () => navigate('/settings'),
    },
    {
      id: 'action-go-cockpit',
      type: 'action',
      title: 'Open Security Cockpit',
      subtitle: 'Launch the operations command center',
      meta: 'Navigate',
      action: () => navigate('/cockpit'),
    },
    {
      id: 'action-reopen-palette',
      type: 'action',
      title: 'Show Keyboard Shortcuts',
      subtitle: 'Display the in-app shortcut reference',
      meta: 'Help',
      action: () => toggleCommandPalette(),
    },
  ];
}

const PAGE_META: Record<string, { title: string; subtitle: string }> = {
  '/': { title: 'Dashboard', subtitle: 'Security Operations Overview' },
  '/targets': { title: 'Targets', subtitle: 'Asset and URL testing scope' },
  '/jobs': { title: 'Jobs', subtitle: 'Pipeline execution queue' },
  '/pipeline': { title: 'Pipeline Overview', subtitle: 'Stage flow and scanner telemetry' },
  '/findings': { title: 'Findings', subtitle: 'Security issues and evidence' },
  '/bug-bounty': { title: 'Bounty Dashboard', subtitle: 'Bug bounty submission pipeline and yields' },
  '/risk-score': { title: 'Risk Score', subtitle: 'Target exposure scoring' },
  '/findings-timeline': { title: 'Timeline', subtitle: 'Findings activity over time' },
  '/target-comparison': { title: 'Compare', subtitle: 'Target posture comparison' },
  '/gap-analysis': { title: 'Gap Analysis', subtitle: 'Detection coverage review' },
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
};

interface AppLayoutProps {
  children: ReactNode;
}

export function AppLayout({ children }: AppLayoutProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const { theme, updater: themeUpdater } = useTheme();
  const { user } = useAuth();
  const toast = useToast();
  const navSections = useNavSections();
   
  const [showShortcuts, setShowShortcuts] = useState(false);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const sidebarCollapsed = useDisplayStore((state) => state.sidebarCollapsed);
  const toggleSidebarCollapsed = useDisplayStore((state) => state.toggleSidebarCollapsed);
  const workflowMode = useDisplayStore((state) => state.workflowMode);

  const [isOnline, setIsOnline] = useState(() => (typeof navigator !== 'undefined' ? navigator.onLine : true));
  const healthStatus = useHealthStatus();
  const sidebarRef = useRef<HTMLElement>(null);

  // Server-backed notifications via REST + SSE
  const {
    notifications,
    markRead,
    markAllRead,
    dismiss: dismissNotification,
    clearAll: clearAllNotifications,
  } = useNotifications();
   
  const defaultNavItems = useMemo(() => buildDefaultNavItems(navSections), [navSections]);
  const defaultActionItems = useMemo(
    () => buildDefaultActionItems(
      theme,
      themeUpdater,
      toggleSidebarCollapsed,
      () => setShowShortcuts(prev => !prev),
      navigate,
      toast,
    ),
    [theme, themeUpdater, toggleSidebarCollapsed, navigate, toast]
  );
  const { policy, strategy } = useMotionPolicy('layout');

  useCommandPaletteItems([...defaultNavItems, ...defaultActionItems]);

  // Toast on incoming SSE notifications
  const prevNotifCountRef = useRef(notifications.length);
  useEffect(() => {
    if (notifications.length > prevNotifCountRef.current) {
      const newest = notifications[0];
      if (newest && !newest.read) {
        if (newest.type === 'new_finding' || newest.type === 'critical_vulnerability') {
          toast.info(`${newest.title}: ${newest.message}`);
        } else if (newest.type === 'error') {
          toast.error(newest.message);
        } else if (newest.type === 'scan_completed') {
          toast.success(newest.message);
        }
      }
    }
    prevNotifCountRef.current = notifications.length;
  }, [notifications, toast]);

  const { connectionState: liveConnectionState } = useWebSocket({
    jobId: undefined,
    enabled: false,
    onMessage: () => {},
    onFallback: () => {},
  });

  useEffect(() => {
    const handleSearchUpdate = (e: Event) => {
      const detail = (e as CustomEvent<{ items: SearchableItem[] }>).detail;
      const existing = getAllItems();
   
      const merged = [...defaultNavItems, ...detail.items, ...existing.filter(i => i.type !== 'page')];
      const seen = new Set<string>();
      const deduped = merged.filter(i => {
        if (seen.has(i.id)) return false;
        seen.add(i.id);
        return true;
      });
      emitSearchItems({ items: deduped });
    };
    window.addEventListener('search:items-update', handleSearchUpdate);
    return () => window.removeEventListener('search:items-update', handleSearchUpdate);
   
  }, [defaultNavItems]);

  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      setCommandPaletteOpen(prev => !prev);
      return;
    }

    if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;

    if (e.key === '?' || (e.shiftKey && e.key === '/')) {
      e.preventDefault();
      setShowShortcuts(prev => !prev);
    } else if (e.key === '1') {
      e.preventDefault();
      navigate('/');
    } else if (e.key === '2') {
      e.preventDefault();
      navigate('/targets');
    } else if (e.key === '3') {
      e.preventDefault();
      navigate('/jobs');
    } else if (e.key === '4') {
      e.preventDefault();
      navigate('/findings');
    } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'd') {
      e.preventDefault();
      themeUpdater.setThemeMode(theme.mode === 'dark' ? 'light' : 'dark');
    } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
      e.preventDefault();
      navigate('/settings');
    } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'b') {
      e.preventDefault();
      toggleSidebarCollapsed();
    } else if (e.key === '5') {
      e.preventDefault();
      navigate('/pipeline');
    } else if (e.key === '6') {
      e.preventDefault();
      navigate('/bug-bounty');
    } else if (e.key.toLowerCase() === 'r' && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      emitRefresh();
    } else if (e.key === 'Escape') {
      setShowShortcuts(false);
      setCommandPaletteOpen(false);
      if (sidebarOpen) setSidebarOpen(false);
    }
  }, [navigate, sidebarOpen, theme.mode, themeUpdater, toggleSidebarCollapsed]);

  useEffect(() => {
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);

  useEffect(() => {
    let mounted = true;
    Promise.resolve().then(() => {
      if (mounted) setSidebarOpen(false);
    });
    return () => { mounted = false; };
  }, [location.pathname]);

  useEffect(() => {
    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);
    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  const allCommandItems = useMemo(() => getAllItems(), []);

  const quickActions = useMemo(() => [
    { label: 'New Scan', path: '/targets', icon: 'plus' },
  ], []);

  const mobilePrimary = useMemo(() => navSections
    .flatMap(section => section.items)
    .filter(item => ['/', '/targets', '/jobs', '/findings', '/bug-bounty', '/cockpit', '/reports', '/settings'].includes(item.path)), [navSections]);

  const motionDuration = strategy.duration || 0.2;
  const isLogin = location.pathname === '/login';
  
  const pageMeta = useMemo(() => {
    if (location.pathname.startsWith('/jobs/')) {
      return { title: 'Job Detail', subtitle: 'Pipeline run telemetry and artifacts' };
    }
    return PAGE_META[location.pathname] ?? PAGE_META['/'];
  }, [location.pathname]);

  if (isLogin) {
    return <div className="app-shell--auth">{children}</div>;
  }

  return (
    <div className="app-shell app-shell--hud">
      <a href="#main" className="skip-link">Skip to content</a>

      <Sidebar
        sidebarRef={sidebarRef}
        sidebarOpen={sidebarOpen}
        setSidebarOpen={setSidebarOpen}
        sidebarCollapsed={sidebarCollapsed}
        toggleSidebarCollapsed={toggleSidebarCollapsed}
        policy={policy}
        motionDuration={motionDuration}
        navSections={navSections}
        theme={theme}
        themeUpdater={themeUpdater}
      />

      <div className="app-main-wrapper flex flex-col min-h-screen">
        <Header
          sidebarOpen={sidebarOpen}
          setSidebarOpen={setSidebarOpen}
          pageMeta={pageMeta}
          setCommandPaletteOpen={setCommandPaletteOpen}
          quickActions={quickActions}
          workflowMode={workflowMode}
          liveConnectionState={liveConnectionState}
          user={user}
          isOnline={isOnline}
          policy={policy}
          motionDuration={motionDuration}
          notifications={notifications}
          onMarkNotificationRead={markRead}
          onMarkAllNotificationsRead={markAllRead}
          onClearAllNotifications={clearAllNotifications}
          onDismissNotification={dismissNotification}
        />

        {(!healthStatus.loading && !healthStatus.ready) && (
          <div
            className="flex items-center gap-2 px-4 py-2 text-xs border-b border-[var(--line)]"
            style={{ background: 'var(--warning-bg, rgba(234, 179, 8, 0.08))', color: 'var(--warning-text, #eab308)' }}
            role="alert"
            aria-live="polite"
          >
            <Icon name="alertTriangle" size={14} aria-hidden="true" />
            <span className="font-medium">System Degraded</span>
            <span className="text-[var(--text-secondary)]">
              {healthStatus.error
                ? 'Unable to reach backend'
                : healthStatus.degradedReasons.length > 0
                  ? healthStatus.degradedReasons.join(' · ')
                  : 'Some subsystems are unavailable'}
            </span>
          </div>
        )}

        <motion.main
          id="main"
          role="main"
          tabIndex={-1}
          className="app-main-content flex-1"
          initial={policy.allowFramer ? { opacity: 0, y: strategy.distance } : false}
          animate={policy.allowFramer ? { opacity: 1, y: 0 } : undefined}
          transition={{ duration: motionDuration, ease: 'easeOut' }}
        >
          {children}
        </motion.main>

        <Footer
          appVersion={APP_VERSION}
          isOnline={isOnline}
          onRefresh={emitRefresh}
          liveConnectionState={liveConnectionState}
        />
        <ScanStatusBar />
      </div>

      <nav className="mobile-dock" aria-label="Primary sections">
        {mobilePrimary.map(item => {
          const isActive = location.pathname === item.path;
          return (
            <Link
              key={`mobile-${item.path}`}
              to={item.path}
              className={`mobile-dock-item ${isActive ? 'mobile-dock-item--active' : ''}`}
              aria-current={isActive ? 'page' : undefined}
            >
              <Icon name={item.icon} size={16} aria-hidden="true" />
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>

      <CommandPalette
        open={commandPaletteOpen}
        onClose={() => setCommandPaletteOpen(false)}
        items={allCommandItems}
      />

      <ShortcutsModal
        isOpen={showShortcuts}
        onClose={() => setShowShortcuts(false)}
      />
    </div>
  );
}
