import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Icon } from '../ui/Icon';
import { NotificationCenter } from './NotificationCenter';
import type { AppNotification } from '@/types/notifications';

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
        className="app-command-header border-b border-white/5 bg-panel/90 backdrop-blur-md sticky top-0 z-30"
        role="banner"
        initial={policy.allowFramer ? { y: -18, opacity: 0 } : false}
        animate={policy.allowFramer ? { y: 0, opacity: 1 } : undefined}
        transition={{ duration: motionDuration, ease: 'easeOut' }}
      >
        <div className="header-left flex items-center gap-4">
          <button
            type="button"
            className="sidebar-toggle-btn mobile-visible hover:bg-white/5 p-2 rounded transition-colors"
            onClick={() => setSidebarOpen((prev) => !prev)}
            aria-label="Toggle navigation menu"
            aria-expanded={sidebarOpen}
            aria-controls="sidebar-nav"
          >
            <Icon name="menu" size={20} aria-hidden="true" />
          </button>
          <div className="header-title-block">
            <h1 className="text-xl font-bold tracking-tight text-text">
              {pageMeta.title}
            </h1>
            {pageMeta.subtitle && (
              <p className="text-xs text-muted/80">{pageMeta.subtitle}</p>
            )}
          </div>
        </div>

        <div className="header-command-row flex items-center gap-4 flex-1 justify-center max-w-2xl px-4">
          <button
            type="button"
            className="command-search flex items-center justify-between w-full max-w-md bg-white/5 border border-white/10 hover:border-accent/40 rounded-lg px-3 py-1.5 text-xs text-muted hover:text-text transition-all duration-200"
            onClick={() => setCommandPaletteOpen(true)}
            aria-label="Open command palette"
          >
            <div className="flex items-center gap-2">
              <Icon name="search" size={14} className="text-muted/60" aria-hidden="true" />
              <span>Search or run command...</span>
            </div>
            <kbd className="bg-white/10 px-1.5 py-0.5 rounded text-[10px] font-mono border border-white/5">
              ⌘ K
            </kbd>
          </button>
          <div
            className="header-quick-actions flex items-center gap-2"
            role="navigation"
            aria-label="Quick actions"
          >
            {quickActions.map((action) => (
              <Link
                key={action.path}
                to={action.path}
                className="btn btn-primary btn-sm topbar-primary flex items-center gap-1.5 px-3 py-1.5 bg-accent hover:bg-accent/90 text-white text-xs font-semibold rounded-lg shadow-md transition-all duration-200"
              >
                <Icon name={action.icon} size={13} aria-hidden="true" />
                {action.label}
              </Link>
            ))}
          </div>
        </div>

        <div className="header-right-actions flex items-center gap-4">
          <NotificationCenter
            notifications={notifications}
            onMarkRead={onMarkNotificationRead}
            onMarkAllRead={onMarkAllNotificationsRead}
            onClearAll={onClearAllNotifications}
            onDismiss={onDismissNotification}
          />
          {workflowMode === 'pentest' && (
            <div
              className={`header-live-indicator flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-white/5 bg-white/5 ${
                liveConnectionState === 'connected'
                  ? 'header-live-indicator--connected text-ok'
                  : liveConnectionState === 'reconnecting'
                    ? 'header-live-indicator--reconnecting text-warn'
                    : 'header-live-indicator--offline text-muted'
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
                className={`header-live-indicator-dot w-1.5 h-1.5 rounded-full ${
                  liveConnectionState === 'connected'
                    ? 'bg-ok pulse-dot'
                    : liveConnectionState === 'reconnecting'
                      ? 'bg-warn'
                      : 'bg-muted'
                }`}
                aria-hidden="true"
              />
              <span className="text-[10px] font-black uppercase tracking-widest">
                {liveConnectionState === 'connected'
                  ? 'Live'
                  : liveConnectionState === 'reconnecting'
                    ? 'Sync'
                    : 'Offline'}
              </span>
            </div>
          )}
          <div className="header-live-pill w-8 h-8 rounded-full bg-accent text-white flex items-center justify-center text-sm font-semibold border border-white/10 hover:scale-105 transition-transform cursor-pointer">
            {user?.name
              ? user.name
                  .split(' ')
                  .map((n) => n[0])
                  .join('')
                  .toUpperCase()
                  .substring(0, 2)
              : 'A'}
          </div>
        </div>
      </motion.header>

      {!isOnline && (
        <div className="status-rail w-full" role="region" aria-label="Live pipeline status">
          <div className="banner warning text-center py-2 bg-warn/10 text-warn border-b border-warn/20 text-xs font-semibold" role="alert">
            You are offline. Data may be stale while reconnection is pending.
          </div>
        </div>
      )}
    </>
  );
}
