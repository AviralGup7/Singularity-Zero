import { useState, useEffect, useRef } from 'react';
import { Icon } from './Icon';

export interface Notification {
  id: string;
  type: 'scan_complete' | 'scan_failed' | 'new_finding' | 'error';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  message: string;
  timestamp: number;
  read: boolean;
  source?: string;
  href?: string;
}

interface NotificationCenterProps {
  notifications: Notification[];
  onMarkRead: (id: string) => void;
  onMarkAllRead: () => void;
  onClearAll: () => void;
  onDismiss: (id: string) => void;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'var(--color-danger, #ff3b30)',
  high: 'var(--color-warning, #ff9500)',
  medium: 'var(--color-accent, #00e5ff)',
  low: 'var(--color-success, #34c759)',
  info: 'var(--color-muted, #8e8e93)',
};

const TYPE_ICONS: Record<string, string> = {
  scan_complete: 'checkCircle',
  scan_failed: 'xCircle',
  new_finding: 'shield',
  error: 'alertCircle',
};

function timeAgo(ts: number): string {
  const diff = Date.now() - ts;
  const secs = Math.floor(diff / 1000);
  if (secs < 60) return 'Just now';
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function NotificationItem({ notification, onMarkRead, onDismiss }: {
  notification: Notification;
  onMarkRead: (id: string) => void;
  onDismiss: (id: string) => void;
}) {
  const severityColor = Reflect.get(SEVERITY_COLORS, notification.severity) || SEVERITY_COLORS.info;
  const icon = Reflect.get(TYPE_ICONS, notification.type) || 'info';

  return (
    <div
      className={`notification-item ${notification.read ? 'notification-read' : 'notification-unread'} ${notification.severity === 'critical' ? 'notification-critical' : ''}`}
      style={{ borderLeft: `3px solid ${severityColor}` }}
      onClick={() => {
        if (!notification.read) onMarkRead(notification.id);
      }}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          if (!notification.read) onMarkRead(notification.id);
        }
      }}
    >
      <div className="notification-icon" style={{ color: severityColor }}>
        <Icon name={icon} size={16} />
      </div>
      <div className="notification-content">
        <div className="notification-header">
          <span className="notification-title">{notification.title}</span>
          <span className="notification-time">{timeAgo(notification.timestamp)}</span>
        </div>
        <p className="notification-message">{notification.message}</p>
        {notification.source && (
          <span className="notification-source">{notification.source}</span>
        )}
      </div>
      <div className="notification-item-actions">
        <button
          className="notification-dismiss-btn"
          onClick={(e) => { e.stopPropagation(); onDismiss(notification.id); }}
          aria-label="Dismiss notification"
        >
          <Icon name="x" size={12} />
        </button>
        {!notification.read && (
          <span className="notification-dot" style={{ backgroundColor: severityColor }} />
        )}
      </div>
    </div>
  );
}

export function NotificationCenter({
  notifications,
  onMarkRead,
  onMarkAllRead,
  onClearAll,
  onDismiss,
}: NotificationCenterProps) {
   
  const [open, setOpen] = useState(false);
   
  const [filter, setFilter] = useState<'all' | Notification['type']>('all');
  const panelRef = useRef<HTMLDivElement>(null);

  const unreadCount = notifications.filter(n => !n.read).length;

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    if (open) document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
   
  }, [open]);

  const filtered = filter === 'all' ? notifications : notifications.filter(n => n.type === filter);

  const grouped = filtered.reduce<Record<string, Notification[]>>((acc, n) => {
    const key = n.type;
  // eslint-disable-next-line security/detect-object-injection
    if (!acc[key]) acc[key] = [];
  // eslint-disable-next-line security/detect-object-injection
    acc[key].push(n);
    return acc;
  }, {});

  const groupLabels: Record<string, string> = {
    scan_complete: 'Scan Complete',
    scan_failed: 'Scan Failed',
    new_finding: 'New Findings',
    error: 'Errors',
  };

  return (
    <div className="notification-center" ref={panelRef}>
      <button
        className="notification-bell-btn"
        onClick={() => setOpen(!open)}
        aria-label={`Notifications${unreadCount > 0 ? `, ${unreadCount} unread` : ''}`}
        aria-expanded={open}
        aria-haspopup="true"
      >
        <Icon name="alertCircle" size={18} />
        {unreadCount > 0 && (
          <span className="notification-badge" style={{
            backgroundColor: notifications.some(n => n.severity === 'critical' && !n.read)
              ? 'var(--color-danger, #ff3b30)'
              : 'var(--color-accent, #00e5ff)',
          }}>
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
      </button>

      {open && (
        <div className="notification-panel" role="dialog" aria-label="Notification center">
          <div className="notification-panel-header">
            <h3>Notifications</h3>
            <div className="notification-panel-actions">
              {unreadCount > 0 && (
                <button className="notification-action-btn" onClick={onMarkAllRead}>
                  Mark all read
                </button>
              )}
              {notifications.length > 0 && (
                <>
                  <button className="notification-action-btn" onClick={() => notifications.filter(n => n.read).forEach(n => onDismiss(n.id))}>
                    Clear read
                  </button>
                  <button className="notification-action-btn notification-clear-all" onClick={onClearAll}>
                    Clear all
                  </button>
                </>
              )}
            </div>
          </div>

          <div className="notification-filters">
  // eslint-disable-next-line security/detect-object-injection
            {(['all', 'scan_complete', 'scan_failed', 'new_finding', 'error'] as const).map(type => (
              <button
                key={type}
                className={`notification-filter-btn ${filter === type ? 'active' : ''}`}
                onClick={() => setFilter(type)}
              >
                {type === 'all' ? 'All' : Reflect.get(groupLabels, type)}
              </button>
            ))}
          </div>

          <div className="notification-list">
            {filtered.length === 0 ? (
              <div className="notification-empty">
                <Icon name="checkCircle" size={32} />
                <p>No notifications</p>
              </div>
            ) : (
   
              Object.entries(grouped).map(([type, items]) => (
                <div key={type} className="notification-group">
                  <div className="notification-group-header">
                    <span>{Reflect.get(groupLabels, type) || type}</span>
                    <span className="notification-group-count">{items.length}</span>
                  </div>
                  {items.map(n => (
                    <NotificationItem
                      key={n.id}
                      notification={n}
                      onMarkRead={onMarkRead}
                      onDismiss={onDismiss}
                    />
                  ))}
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
