import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Icon } from '../ui/Icon';
import { NotificationCenter } from './NotificationCenter';
import type { AppNotification } from '@/types/notifications';
import { shortcutGlyph, userInitials } from '@/utils/userChrome';
import { ROUTES } from '@/config/paths';

interface HeaderProps {
  sidebarOpen: boolean;
  setSidebarOpen: (open: boolean | ((prev: boolean) => boolean)) => void;
  pageMeta: { title: string; subtitle: string };
  setCommandPaletteOpen: (open: boolean) => void;
  quickActions: Array<{ label: string; path: string; icon: string }>;
  workflowMode: string;
  liveConnectionState: string;
  user: { name?: string } | null;
  isOnline: boolean;
  healthReady?: boolean;
  policy: { allowFramer: boolean };
  motionDuration: number;
  notifications?: AppNotification[];
  onMarkNotificationRead?: (id: string) => void;
  onMarkAllNotificationsRead?: () => void;
  onClearAllNotifications?: () => void;
  onDismissNotification?: (id: string) => void;
}

export function Header({
  sidebarOpen,
  setSidebarOpen,
  pageMeta,
  setCommandPaletteOpen,
  quickActions,
  workflowMode,
  liveConnectionState,
  user,
  isOnline,
  healthReady = false,
  policy,
  motionDuration,
  notifications = [],
  onMarkNotificationRead = () => {},
  onMarkAllNotificationsRead = () => {},
  onClearAllNotifications = () => {},
  onDismissNotification = () => {},
}: HeaderProps) {
  return (
    <>
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
            className="sidebar-toggle-btn mobile-visible hover:bg-surface-hover p-2 rounded transition-colors"
            onClick={() => setSidebarOpen((prev) => !prev)}
            aria-label="Toggle navigation menu"
            aria-expanded={sidebarOpen}
            aria-controls="sidebar-nav"
          >
            <Icon name="menu" size={20} aria-hidden="true" />
          </button>
          <div className="header-title-block">
            <h1>
              {pageMeta.title}
            </h1>
            {pageMeta.subtitle && (
              <p className="header-subtitle">{pageMeta.subtitle}</p>
            )}
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
            <kbd>{shortcutGlyph()}</kbd>
          </button>
          <div
            className="header-quick-actions"
            role="navigation"
            aria-label="Quick actions"
          >
            {quickActions.map((action) => (
              <Link
                key={action.path}
                to={action.path}
                className="btn btn-primary btn-sm topbar-primary"
                aria-label={action.label}
              >
                <Icon name={action.icon} size={13} aria-hidden="true" />
                {action.label}
              </Link>
            ))}
          </div>
        </div>

        <div className="header-right-actions">
          {healthReady && isOnline && (
            <div
              className="header-online-chip"
              role="status"
              aria-live="polite"
              aria-label="System online"
              title="Backend health check is ready"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-ok" aria-hidden="true" />
              <span className="text-[10px] font-black uppercase tracking-widest">Online</span>
            </div>
          )}
          <NotificationCenter
            notifications={notifications}
            onMarkRead={onMarkNotificationRead}
            onMarkAllRead={onMarkAllNotificationsRead}
            onClearAll={onClearAllNotifications}
            onDismiss={onDismissNotification}
          />
          {workflowMode === 'pentest' && (
            <div
              className={`header-live-indicator ${
                liveConnectionState === 'connected'
                  ? 'header-live-indicator--connected'
                  : liveConnectionState === 'reconnecting'
                    ? 'header-live-indicator--reconnecting'
                    : 'header-live-indicator--offline'
              }`}
              role="status"
              aria-live="polite"
              aria-label={`Live data stream ${liveConnectionState}`}
              title={
                liveConnectionState === 'connected'
                  ? 'Live: WebSocket connected'
                  : liveConnectionState === 'reconnecting'
                    ? 'Reconnecting to live stream…'
                    : 'Offline — using polled fallback'
              }
            >
              <span
                className="header-live-indicator-dot"
                aria-hidden="true"
              />
              <span>
                {liveConnectionState === 'connected'
                  ? 'Live'
                  : liveConnectionState === 'reconnecting'
                    ? 'Sync'
                    : 'Offline'}
              </span>
            </div>
          )}
          <Link
            to={ROUTES.SETTINGS}
            className="header-live-pill"
            aria-label={user?.name ? `Open settings for ${user.name}` : 'Open settings'}
            title={user?.name ? `${user.name} · Settings` : 'Settings'}
          >
            {userInitials(user?.name)}
          </Link>
        </div>
      </motion.header>

      {!isOnline && (
        <div className="status-rail" role="region" aria-label="Live pipeline status">
          <div className="banner warning" role="alert" aria-live="assertive">
            You are offline. Data may be stale while reconnection is pending.
          </div>
        </div>
      )}
    </>
  );
}
