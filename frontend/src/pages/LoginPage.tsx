import { useState } from 'react';
import { useNavigate, useLocation, Navigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { LogIn, ChevronDown, LockKeyhole, ScanLine, Shield, User, Workflow, ShieldCheck } from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import { useSettingsStore } from '@/stores/settingsStore';
import { APP_VERSION } from '@/config';
import { dispatchToast } from '@/lib/toastDispatcher';
import type { UserRole } from '@/context/AuthContext';

const ROLE_OPTIONS: { value: UserRole; label: string }[] = [
  { value: 'analyst', label: 'Analyst' },
  { value: 'viewer', label: 'Viewer' },
];

const EASE_OUT = [0.16, 1, 0.3, 1] as const;

export function LoginPage() {
  const {
    user,
    login,
    loginWithApiKey,
    loginWithGuestToken,
  } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const enableGuestLogin = useSettingsStore((state) => state.settings.api.enableGuestLogin);

  const [name, setName] = useState('');
  const [role, setRole] = useState<UserRole>('analyst');
  const [apiKey, setApiKey] = useState('');
  const [authError, setAuthError] = useState<string | null>(null);
  const [authLoading, setAuthLoading] = useState(false);
  const [shakeError, setShakeError] = useState(false);
  const [guestLoading, setGuestLoading] = useState(false);

  const from = (location.state as { from?: { pathname: string } })?.from?.pathname || '/';

  if (user) {
    return <Navigate to={from} replace />;
  }

  const triggerShake = () => {
    setShakeError(true);
    setTimeout(() => setShakeError(false), 500);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    login(name.trim(), role);
    navigate(from, { replace: true });
  };

  const handleApiKeySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!apiKey.trim()) return;
    setAuthLoading(true);
    setAuthError(null);
    try {
      await loginWithApiKey(apiKey.trim());
      navigate(from, { replace: true });
    } catch {
      setAuthError('API key authentication failed');
      triggerShake();
    } finally {
      setAuthLoading(false);
    }
  };

  const handleGuestLogin = async () => {
    setGuestLoading(true);
    setAuthError(null);
    try {
      await loginWithGuestToken();
      navigate(from, { replace: true });
    } catch (err) {
      const reason = err instanceof Error ? err.message : 'Guest login failed';
      dispatchToast(reason, 'error');
      triggerShake();
    } finally {
      setGuestLoading(false);
    }
  };

  const inputFocusClass = 'focus-within:shadow-[0_0_0_2px_var(--accent-soft),0_0_12px_rgba(59,130,246,0.15)] transition-shadow duration-200';

  return (
    <main className="auth-canvas" aria-label="Sign in">
      <section className="auth-card" style={{ backdropFilter: 'blur(24px)', WebkitBackdropFilter: 'blur(24px)' }}>
        <motion.div
          className="auth-left"
          initial={{ opacity: 0, x: -30 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.6, ease: EASE_OUT }}
        >
          <h1>Cyber Pipeline</h1>
          <p className="auth-subtitle">Sign in to continue</p>

          <form onSubmit={handleApiKeySubmit} className={`auth-form ${shakeError ? 'animate-shake' : ''}`}>
            <label htmlFor="login-api-key">API Key</label>
            <div className={`auth-field ${inputFocusClass}`}>
              <LockKeyhole size={24} strokeWidth={1.7} aria-hidden="true" />
              <input
                id="login-api-key"
                type="password"
                value={apiKey}
                onChange={e => setApiKey(e.target.value)}
                placeholder="Enter API key"
                autoFocus
              />
            </div>

            {authError && (
              <motion.p
                className="auth-demo text-bad"
                initial={{ opacity: 0, y: -4 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.2 }}
              >
                {authError}
              </motion.p>
            )}

            <button type="submit" className="auth-submit cyber-gradient-btn" disabled={!apiKey.trim() || authLoading}>
              {authLoading && (
                <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent mr-2" />
              )}
              <span>{authLoading ? 'Signing In...' : 'Sign In'}</span>
              <LogIn size={18} strokeWidth={2} aria-hidden="true" />
            </button>
          </form>

          <div className="auth-divider"><span>OR</span></div>

          <form onSubmit={handleSubmit} className="auth-form">
            <label htmlFor="login-name">Demo Name</label>
            <div className={`auth-field ${inputFocusClass}`}>
              <User size={24} strokeWidth={1.7} aria-hidden="true" />
              <input
                id="login-name"
                type="text"
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="Enter your name"
                required
              />
            </div>

            <label htmlFor="login-role">Role</label>
            <div className={`auth-field auth-select-wrap ${inputFocusClass}`}>
              <Shield size={24} strokeWidth={1.7} aria-hidden="true" />
              <select
                id="login-role"
                value={role}
                onChange={e => setRole(e.target.value as UserRole)}
              >
                {ROLE_OPTIONS.map(opt => (
                  <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
              </select>
              <ChevronDown size={18} strokeWidth={2} aria-hidden="true" />
            </div>

            <button type="submit" className="auth-submit" disabled={!name.trim()}>
              <span>Demo Sign In</span>
              <LogIn size={18} strokeWidth={2} aria-hidden="true" />
            </button>
          </form>

          {enableGuestLogin && (
            <button
              type="button"
              className="auth-submit"
              onClick={handleGuestLogin}
              disabled={guestLoading}
              style={{ marginTop: 12 }}
            >
              {guestLoading && (
                <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent mr-2" />
              )}
              <span>{guestLoading ? 'Continuing as Guest...' : 'Continue as Guest'}</span>
            </button>
          )}

          <button type="button" className="auth-sso" onClick={() => login('SSO User', 'viewer')} style={{ backdropFilter: 'blur(12px)' }} aria-describedby="sso-demo-note">
            <Shield size={22} strokeWidth={1.8} aria-hidden="true" />
            <span>Sign in with SSO (Demo)</span>
          </button>

          <p id="sso-demo-note" className="auth-demo">
            <LockKeyhole size={15} strokeWidth={1.8} aria-hidden="true" />
            Demo auth - no real authentication is performed
          </p>
        </motion.div>

        <motion.div
          className="auth-right"
          aria-hidden="true"
          initial={{ opacity: 0, x: 30 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.6, delay: 0.2, ease: EASE_OUT }}
        >
          <div className="security-scene">
            <div className="scene-grid" />
            <div className="scene-card scene-card-left" />
            <div className="scene-card scene-card-right" />
            <div className="scene-platform platform-back" />
            <div className="scene-platform platform-mid" />
            <div className="scene-platform platform-front" />
            <div className="scene-shield" style={{ animation: 'glow-pulse 3s ease-in-out infinite', color: 'var(--accent)' }}>
              <Shield size={116} strokeWidth={1.15} />
            </div>
            <span className="scene-node node-1" />
            <span className="scene-node node-2" />
            <span className="scene-node node-3" />
            <span className="scene-node node-4" />
          </div>

          <div className="auth-features">
            {[
              { icon: ScanLine, title: 'Unified Security Testing', desc: 'Manage targets, jobs, and findings in one place' },
              { icon: Workflow, title: 'Real-time Visibility', desc: 'Monitor scans and pipeline activity live' },
              { icon: ShieldCheck, title: 'Actionable Insights', desc: 'Identify risks and take action faster' },
            ].map((feat, i) => (
              <motion.div
                key={feat.title}
                className="feature-row"
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.4 + i * 0.1, duration: 0.4, ease: EASE_OUT }}
              >
                <span className="feature-icon"><feat.icon size={24} strokeWidth={1.65} /></span>
                <span>
                  <strong>{feat.title}</strong>
                  <small>{feat.desc}</small>
                </span>
              </motion.div>
            ))}
          </div>
        </motion.div>
      </section>
      <footer className="auth-footer">
        Cyber Pipeline Dashboard v{APP_VERSION} &bull; {new Date().getFullYear()}
      </footer>
    </main>
  );
}
