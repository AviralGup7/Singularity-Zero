import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useState, useEffect, useCallback, useRef, useMemo, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { motion } from 'framer-motion';
import { APP_VERSION } from '../../config';
import { useTheme } from '@/hooks/useTheme';
import { useAuth } from '@/hooks/useAuth';
import { FocusTrap } from '../FocusTrap';
import { Icon } from '../Icon';
import { CommandPalette } from '../CommandPalette';
import { emitNotification, emitSearchItems, emitRefresh } from '../../lib/events';
import { useCommandPaletteItems, getAllItems } from '../../hooks/useCommandPaletteItems';
import { useWebSocket } from '../../hooks/useWebSocket';
import { useMotionPolicy } from '../../hooks/useMotionPolicy';
import { useDebouncedPersist } from '../../hooks/useDebouncedPersist';
import type { Notification } from '../NotificationCenter';
import type { SearchableItem } from '../CommandPalette';

interface NavSection {
  label: string;
  items: { path: string; label: string; icon: string; key?: string; count?: string }[];
}

function useNavSections(): NavSection[] {
  const { t } = useTranslation();
  return useMemo(() => [
    {
      label: t('navigation.overview'),
      items: [
        { path: '/', label: 'Dashboard', icon: 'barChart', count: '1' },
        { path: '/targets', label: t('navigation.targets'), icon: 'target', count: '2' },
        { path: '/jobs', label: t('navigation.jobs'), icon: 'zap', count: '3' },
        { path: '/findings', label: t('navigation.findings'), icon: 'shield', count: '4' },
      ],
    },
    {
      label: 'Analysis',
      items: [
        { path: '/pipeline', label: 'Pipeline Overview', icon: 'activity' },
        { path: '/risk-score', label: 'Risk Score', icon: 'alertTriangle' },
        { path: '/target-comparison', label: t('navigation.compare'), icon: 'activity' },
        { path: '/gap-analysis', label: t('navigation.gapAnalysis'), icon: 'shieldCheck' },
      ],
    },
    {
      label: t('navigation.system'),
      items: [
        { path: '/mesh', label: 'Mesh Command', icon: 'server' },
        { path: '/tracing', label: 'Tracing', icon: 'activity' },
        { path: '/audit-logs', label: 'Audit Logs', icon: 'file' },
        { path: '/compliance', label: 'Compliance', icon: 'shieldCheck' },
        { path: '/evidence-custody', label: 'Evidence Chain', icon: 'link' },
        { path: '/security', label: 'Security', icon: 'shieldCheck' },
        { path: '/settings', label: t('navigation.settings'), icon: 'settings', count: 'S' },
      ],
    },
   
  ], [t]);
}

const NOTIF_STORAGE_KEY = 'cyber-pipeline-notifications';
const NOTIF_TTL_MS = 24 * 60 * 60 * 1000;

function loadNotifications(): Notification[] {
  try {
    const raw = localStorage.getItem(NOTIF_STORAGE_KEY);
    if (!raw) return [];
    const parsed: Notification[] = JSON.parse(raw);
    const now = Date.now();
    return parsed.filter(n => (now - n.timestamp) < NOTIF_TTL_MS);
  } catch {
    return [];
  }
}

function saveNotifications(notifs: Notification[]) {
  try {
    localStorage.setItem(NOTIF_STORAGE_KEY, JSON.stringify(notifs));
  } catch {
    // ignore write failures
  }
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

const PAGE_META: Record<string, { title: string; subtitle: string }> = {
  '/': { title: 'Dashboard', subtitle: 'Security Operations Overview' },
  '/targets': { title: 'Targets', subtitle: 'Asset and URL testing scope' },
  '/jobs': { title: 'Jobs', subtitle: 'Pipeline execution queue' },
  '/pipeline': { title: 'Pipeline Overview', subtitle: 'Stage flow and scanner telemetry' },
  '/findings': { title: 'Findings', subtitle: 'Security issues and evidence' },
  '/risk-score': { title: 'Risk Score', subtitle: 'Target exposure scoring' },
  '/findings-timeline': { title: 'Timeline', subtitle: 'Findings activity over time' },
  '/target-comparison': { title: 'Compare', subtitle: 'Target posture comparison' },
  '/gap-analysis': { title: 'Gap Analysis', subtitle: 'Detection coverage review' },
  '/replay': { title: 'Replay', subtitle: 'Request replay tooling' },
  '/cache-management': { title: 'Cache', subtitle: 'Backend cache controls' },
  '/settings': { title: 'Settings', subtitle: 'System preferences and controls' },
  '/tracing': { title: 'Tracing', subtitle: 'Distributed stage waterfalls' },
  '/security': { title: 'Security', subtitle: 'API controls and enforcement events' },
  '/cockpit': { title: 'Security Cockpit', subtitle: 'Operations command center' },
};

interface AppLayoutProps {
  children: ReactNode;
}

export function AppLayout({ children }: AppLayoutProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const { theme, updater: themeUpdater } = useTheme();
  const { user } = useAuth();
  const navSections = useNavSections();
   
  const [showShortcuts, setShowShortcuts] = useState(false);
   
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
   
  const [notifications, setNotifications] = useState<Notification[]>(loadNotifications);
   
  const [sidebarOpen, setSidebarOpen] = useState(false);
   
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
   
  const [isOnline, setIsOnline] = useState(() => (typeof navigator !== 'undefined' ? navigator.onLine : true));
  const sidebarRef = useRef<HTMLElement>(null);
   
  const defaultNavItems = useMemo(() => buildDefaultNavItems(navSections), [navSections]);
  const { policy, strategy } = useMotionPolicy('layout');

  useCommandPaletteItems(defaultNavItems);

  const addNotification = useCallback((notif: Omit<Notification, 'id' | 'timestamp' | 'read'>) => {
    const id = `notif-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
    const newNotif: Notification = { ...notif, id, timestamp: Date.now(), read: false };
   
    setNotifications(prev => [newNotif, ...prev].slice(0, 100));
    emitNotification({ message: notif.message, type: notif.type });
  }, []);

  useWebSocket({
    jobId: undefined,
    enabled: true,
    onMessage: (data: unknown) => {
      try {
        const msg = data as { type?: string; severity?: string; message?: string; title?: string };
        const notifType: 'error' | 'scan_complete' | 'scan_failed' | 'new_finding' =
          msg.type === 'error' || msg.severity === 'critical' ? 'error'
            : msg.type === 'scan_complete' ? 'scan_complete'
              : msg.type === 'scan_failed' ? 'scan_failed'
                : msg.type === 'new_finding' ? 'new_finding'
                  : 'scan_complete';
        addNotification({
          title: msg.title || 'Notification',
          message: msg.message || msg.title || 'New notification',
          type: notifType,
          severity: notifType === 'error' || notifType === 'scan_failed' ? 'high' : notifType === 'new_finding' ? 'medium' : 'info',
        });
      } catch {
        addNotification({
          title: 'Notification',
          message: String(data),
          type: 'scan_complete',
          severity: 'info',
        });
      }
    },
    onFallback: () => {
      // fallback path handled by polling hooks
    },
  });

  const persistNotifications = useCallback((data: Notification[]) => {
    saveNotifications(data);
  }, []);
  useDebouncedPersist(notifications, persistNotifications, 500);

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
      setSidebarCollapsed(prev => !prev);
    } else if (e.key === 'Escape') {
      setShowShortcuts(false);
      setCommandPaletteOpen(false);
      if (sidebarOpen) setSidebarOpen(false);
    }
   
  }, [navigate, sidebarOpen, theme.mode, themeUpdater]);

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

  const quickActions = [
    { label: 'New Scan', path: '/targets', icon: 'plus' },
  ];

  const mobilePrimary = navSections
    .flatMap(section => section.items)
   
    .filter(item => ['/', '/targets', '/jobs', '/findings', '/settings'].includes(item.path));

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

      {sidebarOpen && <div className="sidebar-overlay" onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLElement).click()} onClick={() => setSidebarOpen(false)} role="presentation" />}

      <motion.aside
        ref={sidebarRef}
        id="sidebar-nav"
        className={`sidebar ${sidebarOpen ? 'sidebar--open' : ''} ${sidebarCollapsed ? 'sidebar--collapsed' : ''}`}
        role="navigation"
        aria-label="Main navigation"
        initial={policy.allowFramer ? { x: -30, opacity: 0 } : false}
        animate={policy.allowFramer ? { x: 0, opacity: 1 } : undefined}
        transition={{ duration: motionDuration, ease: 'easeOut' }}
      >
        <div className="sidebar-header">
          <button
            type="button"
            className="sidebar-brand"
            onClick={() => navigate('/')}
            aria-label="Navigate to dashboard"
          >
            <Icon name="shield" size={18} className="text-accent" aria-hidden="true" />
            {!sidebarCollapsed && <span className="sidebar-brand-text">Security Console</span>}
          </button>
          <button
            type="button"
            className="sidebar-collapse-btn"
            onClick={() => setSidebarCollapsed(prev => !prev)}
            title="Toggle sidebar (Ctrl+B)"
            aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            <Icon name={sidebarCollapsed ? 'chevronRight' : 'chevronLeft'} size={16} aria-hidden="true" />
          </button>
        </div>

        <nav className="sidebar-nav" aria-label="Sidebar navigation">
          {navSections.filter(section => section.label !== 'Hidden').map(section => (
            <div key={section.label} className="sidebar-section">
              {!sidebarCollapsed && <div className="sidebar-section-label">{section.label}</div>}
              {section.items.map(item => {
                const isActive = location.pathname === item.path;
                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    className={`sidebar-nav-item ${isActive ? 'sidebar-nav-item--active' : ''}`}
                    aria-current={isActive ? 'page' : undefined}
                    aria-label={`Navigate to ${item.label}`}
                    title={item.label}
                  >
                    <Icon name={item.icon} size={17} aria-hidden="true" />
                    {!sidebarCollapsed && <span className="sidebar-nav-label">{item.label}</span>}
                    {!sidebarCollapsed && (item.count || item.key) && <span className="sidebar-nav-hotkey">{item.count || item.key}</span>}
                  </Link>
                );
              })}
            </div>
          ))}
        </nav>

        <div className="sidebar-footer">
          <button
            type="button"
            className="sidebar-theme-toggle"
            onClick={() => themeUpdater.setThemeMode(theme.mode === 'dark' ? 'light' : 'dark')}
            title="Toggle theme"
            aria-label={`Switch to ${theme.mode === 'dark' ? 'light' : 'dark'} mode`}
          >
            <Icon name={theme.mode === 'dark' ? 'moon' : 'sun'} size={16} aria-hidden="true" />
            {!sidebarCollapsed && <span>{theme.mode === 'dark' ? 'Dark' : 'Light'}</span>}
          </button>
        </div>
      </motion.aside>

      <div className="app-main-wrapper">
        <motion.header
          className="app-command-header"
          role="banner"
          initial={policy.allowFramer ? { y: -18, opacity: 0 } : false}
          animate={policy.allowFramer ? { y: 0, opacity: 1 } : undefined}
          transition={{ duration: motionDuration, ease: 'easeOut' }}
        >
          <div className="header-left">
            <button
              type="button"
              className="sidebar-toggle-btn mobile-visible"
              onClick={() => setSidebarOpen(prev => !prev)}
              aria-label="Toggle navigation menu"
              aria-expanded={sidebarOpen}
              aria-controls="sidebar-nav"
            >
              <Icon name="menu" size={20} aria-hidden="true" />
            </button>
            <div className="header-title-block">
              <h1>{pageMeta.title}</h1>
            </div>
          </div>

          <div className="header-command-row">
            <button
              type="button"
              className="command-search"
              onClick={() => setCommandPaletteOpen(true)}
              aria-label="Open command palette"
            >
              <Icon name="search" size={14} aria-hidden="true" />
              <span>Search or run command...</span>
              <kbd>⌘ K</kbd>
            </button>
            <div className="header-quick-actions" role="navigation" aria-label="Quick actions">
              {quickActions.map(action => (
                <Link key={action.path} to={action.path} className="btn btn-primary btn-sm topbar-primary">
                  <Icon name={action.icon} size={13} aria-hidden="true" />
                  {action.label}
                </Link>
              ))}
            </div>
          </div>

          <div className="header-right-actions">
            <div className="header-live-pill">
  // eslint-disable-next-line security/detect-object-injection
              {user?.name ? user.name.split(' ').map(n => n[0]).join('').toUpperCase().substring(0, 2) : 'A'}
            </div>
          </div>
        </motion.header>

        {!isOnline && (
          <div className="status-rail" role="region" aria-label="Live pipeline status">
            <div className="banner warning" role="alert">
              You are offline. Data may be stale while reconnection is pending.
            </div>
          </div>
        )}

        <motion.main
          id="main"
          role="main"
          tabIndex={-1}
          className="app-main-content"
          initial={policy.allowFramer ? { opacity: 0, y: strategy.distance } : false}
          animate={policy.allowFramer ? { opacity: 1, y: 0 } : undefined}
          transition={{ duration: motionDuration, ease: 'easeOut' }}
        >
          {children}
        </motion.main>

        <footer className="app-footer" role="contentinfo">
          <span>v{APP_VERSION}</span>
          <span 
            className={`footer-health cursor-pointer hover:text-accent transition-colors ${isOnline ? 'text-ok' : 'text-bad'}`} 
            onClick={() => emitRefresh()}
            title="Force Full System Resync"
          >
            System Status
            <i className={`ml-2 inline-block w-2 h-2 rounded-full ${isOnline ? 'bg-ok' : 'bg-bad'}`} aria-hidden="true" />
          </span>
        </footer>
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

      {showShortcuts && (
        <FocusTrap active={showShortcuts} onDeactivate={() => setShowShortcuts(false)}>
          <div
            className="modal-overlay-fixed"
            role="dialog"
            aria-modal="true"
            aria-labelledby="shortcuts-modal-title"
            onClick={() => setShowShortcuts(false)}
          >
            <div
              tabIndex={-1}
              className="card modal-card"
              onClick={e => e.stopPropagation()}
            >
              <h3 id="shortcuts-modal-title" className="mb-16 text-accent">Keyboard Shortcuts</h3>
              <div className="modal-grid">
                <div className="shortcut-row"><span>Dashboard</span><kbd className="kbd">1</kbd></div>
                <div className="shortcut-row"><span>Targets</span><kbd className="kbd">2</kbd></div>
                <div className="shortcut-row"><span>Jobs</span><kbd className="kbd">3</kbd></div>
                <div className="shortcut-row"><span>Findings</span><kbd className="kbd">4</kbd></div>
                <div className="shortcut-row"><span>Theme Toggle</span><kbd className="kbd">Ctrl</kbd>+<kbd className="kbd">D</kbd></div>
                <div className="shortcut-row"><span>Settings</span><kbd className="kbd">Ctrl</kbd>+<kbd className="kbd">S</kbd></div>
                <div className="shortcut-row"><span>Sidebar Toggle</span><kbd className="kbd">Ctrl</kbd>+<kbd className="kbd">B</kbd></div>
                <div className="shortcut-row"><span>Command Palette</span><kbd className="kbd">Ctrl</kbd>+<kbd className="kbd">K</kbd></div>
                <div className="shortcut-row"><span>Close Modal</span><kbd className="kbd">Esc</kbd></div>
              </div>
            </div>
          </div>
        </FocusTrap>
      )}
    </div>
  );
}
