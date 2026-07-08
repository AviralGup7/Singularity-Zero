import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useState, useEffect, useCallback, useRef, useMemo, lazy, Suspense, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { motion } from 'framer-motion';
import { APP_VERSION } from '../../config';
import { ROUTES } from '@/config/paths';
import { PAGE_META } from '@/config/routes';
import { useTheme } from '@/hooks/useTheme';
import { useAuth } from '@/hooks/useAuth';
import { emitRefresh } from '../../lib/events';
import { useCommandPaletteItems, useCommandItems } from '../../hooks/useCommandPaletteItems';
import { useWebSocket } from '../../hooks/useWebSocket';
import { useMotionPolicy } from '../../hooks/useMotionPolicy';
import { useDisplayStore } from '@/stores/displayStore';
const CommandPalette = lazy(() => import('./CommandPalette').then(m => ({ default: m.CommandPalette })));
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
      { path: ROUTES.DASHBOARD, label: 'Dashboard', icon: 'barChart', count: '1' },
      { path: ROUTES.TARGETS, label: t('navigation.targets'), icon: 'target', count: '2' },
      { path: ROUTES.JOBS, label: t('navigation.jobs'), icon: 'zap', count: '3' },
      { path: ROUTES.FINDINGS, label: t('navigation.findings'), icon: 'shield', count: '4' },
      { path: ROUTES.BUG_BOUNTY, label: 'Bounty Dashboard', icon: 'bug', count: '6' },
    ];

    if (workflowMode === 'pentest') {
      return [
        { label: t('navigation.overview'), items: overview },
        {
          label: 'Analysis',
          items: [
            { path: ROUTES.PIPELINE, label: 'Pipeline Overview', icon: 'activity' },
            { path: ROUTES.COCKPIT, label: 'Security Cockpit', icon: 'target' },
            { path: ROUTES.REMEDIATION_PLANNER, label: 'Remediation Planner', icon: 'checkCircle' },
            { path: ROUTES.RISK_SCORE, label: 'Risk Score', icon: 'alertTriangle' },
            { path: ROUTES.SCAN_DIFF, label: 'Scan Diff', icon: 'activity' },
            { path: ROUTES.FINDINGS_TIMELINE, label: 'Findings Timeline', icon: 'activity' },
            { path: ROUTES.TARGET_COMPARISON, label: t('navigation.compare'), icon: 'activity' },
            { path: ROUTES.GAP_ANALYSIS, label: t('navigation.gapAnalysis'), icon: 'shieldCheck' },
            { path: ROUTES.LEARNING, label: 'Autonomous Learning', icon: 'zap' },
            { path: ROUTES.EVASION, label: 'Evasion Metrics', icon: 'shield' },
          ],
        },
        {
          label: t('navigation.system'),
          items: [
            { path: ROUTES.MESH, label: 'Mesh Command', icon: 'server' },
            { path: ROUTES.SELF_HEALING, label: 'Self-Healing', icon: 'zap' },
            { path: ROUTES.TRACING, label: 'Tracing', icon: 'activity' },
            { path: ROUTES.CACHE_MANAGEMENT, label: 'Cache', icon: 'database' },
            { path: ROUTES.AUDIT_LOGS, label: 'Audit Logs', icon: 'file' },
            { path: ROUTES.COMPLIANCE, label: 'Compliance', icon: 'shieldCheck' },
            { path: ROUTES.REPORTS, label: 'Reports', icon: 'fileText' },
            { path: ROUTES.ACCESS_LOGS, label: 'Access Logs', icon: 'fileText' },
            { path: ROUTES.EVIDENCE_CUSTODY, label: 'Evidence Chain', icon: 'link' },
            { path: ROUTES.SECURITY, label: 'Security', icon: 'shieldCheck' },
            { path: ROUTES.SETTINGS, label: t('navigation.settings'), icon: 'settings', count: 'S' },
          ],
        },
      ];
    }

    return [
      { label: t('navigation.overview'), items: overview },
      {
        label: 'Analysis',
        items: [
          { path: ROUTES.PIPELINE, label: 'Pipeline Overview', icon: 'activity' },
          { path: ROUTES.COCKPIT, label: 'Security Cockpit', icon: 'target' },
          { path: ROUTES.REMEDIATION_PLANNER, label: 'Remediation Planner', icon: 'checkCircle' },
          { path: ROUTES.RISK_SCORE, label: 'Risk Score', icon: 'alertTriangle' },
          { path: ROUTES.TARGET_COMPARISON, label: t('navigation.compare'), icon: 'activity' },
          { path: ROUTES.SCAN_DIFF, label: 'Scan Diff', icon: 'activity' },
          { path: ROUTES.GAP_ANALYSIS, label: t('navigation.gapAnalysis'), icon: 'shieldCheck' },
          { path: ROUTES.LEARNING, label: 'Autonomous Learning', icon: 'zap' },
          { path: ROUTES.EVASION, label: 'Evasion Metrics', icon: 'shield' },
        ],
      },
      {
        label: t('navigation.system'),
        items: [
          { path: ROUTES.MESH, label: 'Mesh Command', icon: 'server' },
          { path: ROUTES.SELF_HEALING, label: 'Self-Healing', icon: 'zap' },
          { path: ROUTES.TRACING, label: 'Tracing', icon: 'activity' },
          { path: ROUTES.CACHE_MANAGEMENT, label: 'Cache', icon: 'database' },
          { path: ROUTES.AUDIT_LOGS, label: 'Audit Logs', icon: 'file' },
          { path: ROUTES.COMPLIANCE, label: 'Compliance', icon: 'shieldCheck' },
          { path: ROUTES.REPORTS, label: 'Reports', icon: 'fileText' },
          { path: ROUTES.ACCESS_LOGS, label: 'Access Logs', icon: 'fileText' },
          { path: ROUTES.EVIDENCE_CUSTODY, label: 'Evidence Chain', icon: 'link' },
          { path: ROUTES.SECURITY, label: 'Security', icon: 'shieldCheck' },
          { path: ROUTES.SETTINGS, label: t('navigation.settings'), icon: 'settings', count: 'S' },
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
      action: () => navigate(ROUTES.FINDINGS),
    },
    {
      id: 'action-go-jobs',
      type: 'action',
      title: 'Go to Jobs',
      subtitle: 'Jump to the active scan queue',
      meta: 'Navigate',
      action: () => navigate(ROUTES.JOBS),
    },
    {
      id: 'action-go-targets',
      type: 'action',
      title: 'Go to Targets',
      subtitle: 'Open target management',
      meta: 'Navigate',
      action: () => navigate(ROUTES.TARGETS),
    },
    {
      id: 'action-go-settings',
      type: 'action',
      title: 'Open Settings',
      subtitle: 'Configure display, motion, and notifications',
      meta: 'Navigate',
      action: () => navigate(ROUTES.SETTINGS),
    },
    {
      id: 'action-go-cockpit',
      type: 'action',
      title: 'Open Security Cockpit',
      subtitle: 'Launch the operations command center',
      meta: 'Navigate',
      action: () => navigate(ROUTES.COCKPIT),
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
  const commandPaletteTriggerRef = useRef<HTMLButtonElement | null>(null);
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

  // Reactively track all registered command items
  const allCommandItems = useCommandItems();

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

  // Items are now managed reactively via useCommandItems() above.
  // The old search:items-update event dance has been removed in favor of
  // the CommandRegistry singleton that components register with at import time.

  // Save/restore focus for command palette
  useEffect(() => {
    if (commandPaletteOpen) {
      commandPaletteTriggerRef.current = document.activeElement as HTMLButtonElement;
    } else if (commandPaletteTriggerRef.current) {
      const trigger = commandPaletteTriggerRef.current;
      requestAnimationFrame(() => trigger.focus());
      commandPaletteTriggerRef.current = null;
    }
  }, [commandPaletteOpen]);

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
      navigate(ROUTES.DASHBOARD);
    } else if (e.key === '2') {
      e.preventDefault();
      navigate(ROUTES.TARGETS);
    } else if (e.key === '3') {
      e.preventDefault();
      navigate(ROUTES.JOBS);
    } else if (e.key === '4') {
      e.preventDefault();
      navigate(ROUTES.FINDINGS);
    } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'd') {
      e.preventDefault();
      themeUpdater.setThemeMode(theme.mode === 'dark' ? 'light' : 'dark');
    } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
      e.preventDefault();
      navigate(ROUTES.SETTINGS);
    } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'b') {
      e.preventDefault();
      toggleSidebarCollapsed();
    } else if (e.key === '5') {
      e.preventDefault();
      navigate(ROUTES.PIPELINE);
    } else if (e.key === '6') {
      e.preventDefault();
      navigate(ROUTES.BUG_BOUNTY);
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

  const quickActions = useMemo(() => [
    { label: 'New Scan', path: ROUTES.TARGETS, icon: 'plus' },
  ], []);

  const mobilePrimary = useMemo(() => navSections
    .flatMap(section => section.items)
    .filter(item => [ROUTES.DASHBOARD, ROUTES.TARGETS, ROUTES.JOBS, ROUTES.FINDINGS, ROUTES.BUG_BOUNTY, ROUTES.COCKPIT, ROUTES.REPORTS, ROUTES.SETTINGS].includes(item.path)), [navSections]);

  const motionDuration = strategy.duration || 0.2;
  const isLogin = location.pathname === ROUTES.LOGIN;

  const pageMeta = useMemo(() => {
    if (location.pathname.startsWith(ROUTES.JOBS + '/')) {
      return { title: 'Job Detail', subtitle: 'Pipeline run telemetry and artifacts' };
    }
    return PAGE_META[location.pathname] ?? PAGE_META[ROUTES.DASHBOARD];
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
          style={{ scrollMarginTop: 'var(--topbar-height, 64px)' }}
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

      <Suspense fallback={null}>
        <CommandPalette
          open={commandPaletteOpen}
          onClose={() => setCommandPaletteOpen(false)}
          items={allCommandItems}
        />
      </Suspense>

      <ShortcutsModal
        isOpen={showShortcuts}
        onClose={() => setShowShortcuts(false)}
      />
    </div>
  );
}
