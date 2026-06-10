import { Link, useLocation, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Icon } from '../ui/Icon';
import { prefetchRoute } from '@/App';

interface SidebarProps {
  sidebarRef: React.RefObject<HTMLElement | null>;
  sidebarOpen: boolean;
  setSidebarOpen: (open: boolean) => void;
  sidebarCollapsed: boolean;
  toggleSidebarCollapsed: () => void;
  policy: { allowFramer: boolean };
  motionDuration: number;
  navSections: Array<{
    label: string;
    items: Array<{ path: string; label: string; icon: string; count?: string; key?: string }>;
  }>;
  theme: { mode: string };
  themeUpdater: { setThemeMode: (mode: 'dark' | 'light') => void };
}

export function Sidebar({
  sidebarRef,
  sidebarOpen,
  setSidebarOpen,
  sidebarCollapsed,
  toggleSidebarCollapsed,
  policy,
  motionDuration,
  navSections,
  theme,
  themeUpdater,
}: SidebarProps) {
  const location = useLocation();
  const navigate = useNavigate();

  return (
    <>
      {sidebarOpen && (
        <div
          className="sidebar-overlay animate-fade-in"
          onKeyDown={(e) => e.key === 'Enter' && setSidebarOpen(false)}
          onClick={() => setSidebarOpen(false)}
          role="presentation"
        />
      )}

      <motion.aside
        ref={sidebarRef}
        id="sidebar-nav"
        className={`sidebar ${sidebarOpen ? 'sidebar--open' : ''} ${
          sidebarCollapsed ? 'sidebar--collapsed' : ''
        }`}
        role="navigation"
        aria-label="Main navigation"
        initial={policy.allowFramer ? { x: -30, opacity: 0 } : false}
        animate={policy.allowFramer ? { x: 0, opacity: 1 } : undefined}
        transition={{ duration: motionDuration, ease: 'easeOut' }}
      >
        <div className="sidebar-header">
          <button
            type="button"
            className="sidebar-brand flex items-center gap-2 group transition-all duration-300"
            onClick={() => navigate('/')}
            aria-label="Navigate to dashboard"
          >
            <Icon
              name="shield"
              size={18}
              className="text-accent group-hover:scale-110 transition-transform duration-300"
              aria-hidden="true"
            />
            {!sidebarCollapsed && (
              <span className="sidebar-brand-text font-bold tracking-wider hover:text-accent transition-colors duration-300">
                Security Console
              </span>
            )}
          </button>
          <button
            type="button"
            className="sidebar-collapse-btn hover:bg-white/5 p-1.5 rounded transition-colors duration-200"
            onClick={() => toggleSidebarCollapsed()}
            title="Toggle sidebar (Ctrl+B)"
            aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            <Icon
              name={sidebarCollapsed ? 'chevronRight' : 'chevronLeft'}
              size={16}
              aria-hidden="true"
            />
          </button>
        </div>

        <nav className="sidebar-nav space-y-4" aria-label="Sidebar navigation">
          {navSections
            .filter((section) => section.label !== 'Hidden')
            .map((section) => (
              <div key={section.label} className="sidebar-section">
                {!sidebarCollapsed && (
                  <div className="sidebar-section-label text-[10px] font-bold uppercase tracking-wider text-muted/60 mb-2">
                    {section.label}
                  </div>
                )}
                <div className="space-y-1">
                  {section.items.map((item) => {
                    const isActive = location.pathname === item.path;
                    return (
                      <Link
                        key={item.path}
                        to={item.path}
                        onMouseEnter={() => prefetchRoute(item.path)}
                        onFocus={() => prefetchRoute(item.path)}
                        className={`sidebar-nav-item flex items-center justify-between px-3 py-2 rounded-lg transition-all duration-200 hover:bg-white/5 hover:translate-x-0.5 group ${
                          isActive
                            ? 'sidebar-nav-item--active bg-accent-dim/10 text-accent font-semibold border-l-2 border-accent shadow-[0_0_10px_rgba(59,130,246,0.05)]'
                            : ''
                        }`}
                        aria-current={isActive ? 'page' : undefined}
                        aria-label={`Navigate to ${item.label}`}
                        title={item.label}
                      >
                        <div className="flex items-center gap-3">
                          <Icon
                            name={item.icon}
                            size={17}
                            className={`group-hover:text-accent transition-colors duration-200 ${
                              isActive ? 'text-accent' : 'text-muted'
                            }`}
                            aria-hidden="true"
                          />
                          {!sidebarCollapsed && (
                            <span className="sidebar-nav-label text-sm transition-colors duration-200">
                              {item.label}
                            </span>
                          )}
                        </div>
                        {!sidebarCollapsed && (item.count || item.key) && (
                          <span className="sidebar-nav-hotkey text-[10px] font-mono bg-white/5 text-muted/80 px-1.5 py-0.5 rounded border border-white/5 group-hover:border-accent/30 group-hover:text-accent transition-all duration-200">
                            {item.count || item.key}
                          </span>
                        )}
                      </Link>
                    );
                  })}
                </div>
              </div>
            ))}
        </nav>

        <div className="sidebar-footer p-4 border-t border-white/5">
          <button
            type="button"
            className="sidebar-theme-toggle flex items-center justify-center gap-3 w-full py-2 px-3 rounded-lg hover:bg-white/5 text-muted hover:text-text transition-all duration-200"
            onClick={() =>
              themeUpdater.setThemeMode(theme.mode === 'dark' ? 'light' : 'dark')
            }
            title="Toggle theme"
            aria-label={`Switch to ${theme.mode === 'dark' ? 'light' : 'dark'} mode`}
          >
            <Icon
              name={theme.mode === 'dark' ? 'moon' : 'sun'}
              size={16}
              className="text-accent-dim group-hover:text-accent transition-colors duration-200"
              aria-hidden="true"
            />
            {!sidebarCollapsed && (
              <span className="text-sm font-medium">
                {theme.mode === 'dark' ? 'Dark' : 'Light'}
              </span>
            )}
          </button>
        </div>
      </motion.aside>
    </>
  );
}
