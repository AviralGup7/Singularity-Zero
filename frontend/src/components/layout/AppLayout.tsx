import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useState, useEffect, useCallback, useRef, useMemo, lazy, Suspense  } from 'react';
import type {ReactNode} from 'react';
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
import { VisibilityIndicator } from '@/hooks/useVisibilityAPI';
import { SessionGuard } from '@/components/SessionGuard';
import { useEscapeToClose } from '@/hooks/useKeyboardShortcuts';
import { shouldIgnoreGlobalShortcut } from '@/utils/findingTime';
import { isNavPathActive } from '@/utils/navActive';

const CommandPalette = lazy(() => import('./CommandPalette').then(m => ({ default: m.CommandPalette })));
const NightCityHud = lazy(() => import('./NightCityHud').then(m => ({ default: m.NightCityHud })));

interface NavSection {
  label: string;
  items: { path: string; label: string; icon: string; key?: string; count?: string }[];
  collapsible?: boolean;
  defaultCollapsed?: boolean;
}

function useNavSections(): NavSection[] {
  const { t } = useTranslation();
  const workflowMode = useDisplayStore((state) => state.workflowMode);

  return useMemo(() => {
    const main = [
      { path: ROUTES.DASHBOARD, label: 'Dashboard', icon: 'barChart' },
      { path: ROUTES.TARGETS, label: t('navigation.targets'), icon: 'target' },
      { path: ROUTES.JOBS, label: t('navigation.jobs'), icon: 'zap' },
      { path: ROUTES.FINDINGS, label: t('navigation.findings'), icon: 'shield' },
      { path: ROUTES.SETTINGS, label: t('navigation.settings'), icon: 'settings' },
    ];

    const security = [
      { path: ROUTES.COCKPIT, label: 'Cockpit', icon: 'target' },
      { path: ROUTES.RISK_HUB, label: 'Risk', icon: 'alertTriangle' },
      { path: ROUTES.SECURITY, label: 'Security', icon: 'shieldCheck' },
      { path: ROUTES.GOVERNANCE_HUB, label: 'Governance', icon: 'shieldCheck' },
      { path: ROUTES.DETECTION_QUALITY, label: 'Detection Quality', icon: 'shieldCheck' },
    ];

    const analytics = [
      { path: ROUTES.PIPELINE, label: 'Pipeline', icon: 'activity' },
      { path: ROUTES.BUG_BOUNTY, label: 'Bug Bounty', icon: 'bug' },
      { path: ROUTES.ANALYTICS_HUB, label: 'Analytics', icon: 'activity' },
    ];

    const sections = [
      { label: 'Main', items: main, collapsible: false },
      { label: 'Security', items: security, collapsible: false },
      { label: 'Analytics', items: analytics, collapsible: true, defaultCollapsed: false },
    ];

    return sections;
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
      id: 'action-go-risk',
      type: 'action',
      title: 'Open Risk',
      subtitle: 'View risk scores, remediation, and acceptance',
      meta: 'Navigate',
      action: () => navigate(ROUTES.RISK_HUB),
    },
    {
      id: 'action-go-security',
      type: 'action',
      title: 'Open Security',
      subtitle: 'API security and self-healing controls',
      meta: 'Navigate',
      action: () => navigate(ROUTES.SECURITY),
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
  const isLogin = location.pathname === ROUTES.LOGIN;
  const toast = useToast();
  const navSections = useNavSections();
   
  const [showShortcuts, setShowShortcuts] = useState(false);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const commandPaletteTriggerRef = useRef<HTMLButtonElement | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  useEscapeToClose(() => {
    setShowShortcuts(false);
    setCommandPaletteOpen(false);
    setSidebarOpen(false);
  }, commandPaletteOpen || showShortcuts || sidebarOpen);

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
  } = useNotifications(Boolean(user) && !isLogin);
   
  const defaultNavItems = useMemo(() => buildDefaultNavItems(navSections), [navSections]);
  const toggleShortcuts = useCallback(() => setShowShortcuts((prev) => !prev), []);
  const defaultActionItems = useMemo(
    () => buildDefaultActionItems(
      theme,
      themeUpdater,
      toggleSidebarCollapsed,
      toggleShortcuts,
      navigate,
      toast,
    ),
    [theme, themeUpdater, toggleSidebarCollapsed, toggleShortcuts, navigate, toast]
  );
  const { policy, strategy } = useMotionPolicy('layout');

  const commandPaletteItems = useMemo(() => [...defaultNavItems, ...defaultActionItems], [defaultNavItems, defaultActionItems]);
  useCommandPaletteItems(commandPaletteItems);

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

    // Escape must dismiss overlays even when focus is in the palette search
    // input. The previous prune left this only in useEscapeToClose, which
    // skipped editable targets — so Escape did nothing while the palette
    // (or any overlay search field) was focused.
    if (e.key === 'Escape') {
      if (showShortcuts || commandPaletteOpen || sidebarOpen) {
        e.preventDefault();
        setShowShortcuts(false);
        setCommandPaletteOpen(false);
        setSidebarOpen(false);
      }
      return;
    }

    if (shouldIgnoreGlobalShortcut(e.target)) return;

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
    } else if (e.key === '7') {
      e.preventDefault();
      navigate(ROUTES.RISK_HUB);
    } else if (e.key === '8') {
      e.preventDefault();
      navigate(ROUTES.SECURITY);
    } else if (e.key.toLowerCase() === 'r' && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      emitRefresh();
    }
  }, [navigate, theme.mode, themeUpdater, toggleSidebarCollapsed, showShortcuts, commandPaletteOpen, sidebarOpen]);

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
    .filter(item => [ROUTES.DASHBOARD, ROUTES.TARGETS, ROUTES.JOBS, ROUTES.FINDINGS, ROUTES.COCKPIT, ROUTES.SETTINGS].some((route) => route === item.path)), [navSections]);

  const motionDuration = strategy.duration || 0.2;


  const pageMeta = useMemo(() => {
    if (location.pathname.startsWith(ROUTES.JOBS + '/')) {
      return { title: 'Job Detail', subtitle: 'Pipeline run telemetry and artifacts' };
    }
    return PAGE_META[location.pathname] ?? { title: 'Security Console', subtitle: '' };
  }, [location.pathname]);

  const nightCityHud = theme.preset === 'night-city' ? (
    <Suspense fallback={null}>
      <NightCityHud
        sector={isLogin ? 'WATSON' : 'OPS'}
        district={isLogin ? 'NIGHT CITY' : pageMeta.title}
        jobTitle={isLogin ? 'JACK IN' : 'PIPELINE LIVE'}
        jobObjective={
          isLogin
            ? 'Sign in to open the console.'
            : pageMeta.subtitle || 'Triage findings. Keep scans live.'
        }
        ready={!healthStatus.error && healthStatus.ready}
      />
    </Suspense>
  ) : null;

  if (isLogin) {
    return (
      <>
        {nightCityHud}
        <div className="app-shell--auth">{children}</div>
      </>
    );
  }

  return (
    <div className="app-shell app-shell--hud">
      <SessionGuard />
      <VisibilityIndicator />
      {nightCityHud}
      <a href="#main-content" className="skip-link">
        Skip to content
      </a>

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
          healthReady={!healthStatus.loading && healthStatus.ready && !healthStatus.error}
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
            className="flex items-center gap-2 px-4 py-2 text-xs border-b border-line bg-warn/8 text-warn"
            role="alert"
            aria-live="assertive"
          >
            <Icon name="alertTriangle" size={14} aria-hidden="true" />
            <span className="font-medium">System Degraded</span>
            <span className="text-text-secondary">
              {healthStatus.error
                ? 'Unable to reach backend'
                : healthStatus.degradedReasons.length > 0
                  ? healthStatus.degradedReasons.join(' · ')
                  : 'Some subsystems are unavailable'}
            </span>
          </div>
        )}

        <motion.main
          id="main-content"
          role="main"
          tabIndex={-1}
          className="app-main-content flex-1"
          aria-label={pageMeta.title}
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

      <nav className="mobile-dock" aria-label="Primary navigation">
        {mobilePrimary.map(item => {
          const isActive = isNavPathActive(location.pathname, item.path);
          return (
            <Link
              key={`mobile-${item.path}`}
              to={item.path}
              className={`mobile-dock-item ${isActive ? 'mobile-dock-item--active' : ''}`}
              aria-current={isActive ? 'page' : undefined}
              aria-label={item.label}
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
