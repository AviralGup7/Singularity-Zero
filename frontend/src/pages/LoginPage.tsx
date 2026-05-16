import { useState } from 'react';
import { useNavigate, useLocation, Navigate } from 'react-router-dom';
import { LogIn, ChevronDown, LockKeyhole, ScanLine, Shield, User, Workflow, ShieldCheck } from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import { APP_VERSION } from '@/config';
import type { UserRole } from '@/context/AuthContext';

const ROLE_OPTIONS: { value: UserRole; label: string }[] = [
  { value: 'analyst', label: 'Analyst' },
  { value: 'viewer', label: 'Viewer' },
];

export function LoginPage() {
  const { user, login, loginWithApiKey } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
   
  const [name, setName] = useState('');
   
  const [role, setRole] = useState<UserRole>('analyst');
   
  const [apiKey, setApiKey] = useState('');
   
  const [authError, setAuthError] = useState<string | null>(null);
   
  const [authLoading, setAuthLoading] = useState(false);

  const from = (location.state as { from?: { pathname: string } })?.from?.pathname || '/';

  if (user) {
    return <Navigate to={from} replace />;
  }

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
    } finally {
      setAuthLoading(false);
    }
  };

  return (
    <main className="auth-canvas" aria-label="Sign in">
      <section className="auth-card">
        <div className="auth-left">
          <h1>Cyber Pipeline</h1>
          <p className="auth-subtitle">Sign in to continue</p>

          <form onSubmit={handleApiKeySubmit} className="auth-form">
            <label htmlFor="login-api-key">API Key</label>
            <div className="auth-field">
              <LockKeyhole size={24} strokeWidth={1.7} aria-hidden="true" />
              <input
                id="login-api-key"
                type="password"
                value={apiKey}
                onChange={e => setApiKey(e.target.value)}
                placeholder="Enter API key"
                // eslint-disable-next-line jsx-a11y/no-autofocus
                autoFocus
              />
            </div>

            {authError && <p className="auth-demo text-bad">{authError}</p>}

            <button type="submit" className="auth-submit" disabled={!apiKey.trim() || authLoading}>
              <span>{authLoading ? 'Signing In...' : 'Sign In'}</span>
              <LogIn size={18} strokeWidth={2} aria-hidden="true" />
            </button>
          </form>

          <div className="auth-divider"><span>OR</span></div>

          <form onSubmit={handleSubmit} className="auth-form">
            <label htmlFor="login-name">Demo Name</label>
            <div className="auth-field">
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
            <div className="auth-field auth-select-wrap">
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

          <button type="button" className="auth-sso" onClick={() => login('SSO User', 'viewer')}>
            <Shield size={22} strokeWidth={1.8} aria-hidden="true" />
            <span>Sign in with SSO</span>
          </button>

          <p className="auth-demo">
            <LockKeyhole size={15} strokeWidth={1.8} aria-hidden="true" />
            Demo auth - no real authentication is performed
          </p>
        </div>

        <div className="auth-right" aria-hidden="true">
          <div className="security-scene">
            <div className="scene-grid" />
            <div className="scene-card scene-card-left" />
            <div className="scene-card scene-card-right" />
            <div className="scene-platform platform-back" />
            <div className="scene-platform platform-mid" />
            <div className="scene-platform platform-front" />
            <div className="scene-shield">
              <Shield size={116} strokeWidth={1.15} />
            </div>
            <span className="scene-node node-1" />
            <span className="scene-node node-2" />
            <span className="scene-node node-3" />
            <span className="scene-node node-4" />
          </div>

          <div className="auth-features">
            <div className="feature-row">
              <span className="feature-icon"><ScanLine size={24} strokeWidth={1.65} /></span>
              <span>
                <strong>Unified Security Testing</strong>
                <small>Manage targets, jobs, and findings in one place</small>
              </span>
            </div>
            <div className="feature-row">
              <span className="feature-icon"><Workflow size={24} strokeWidth={1.65} /></span>
              <span>
                <strong>Real-time Visibility</strong>
                <small>Monitor scans and pipeline activity live</small>
              </span>
            </div>
            <div className="feature-row">
              <span className="feature-icon"><ShieldCheck size={24} strokeWidth={1.65} /></span>
              <span>
                <strong>Actionable Insights</strong>
                <small>Identify risks and take action faster</small>
              </span>
            </div>
          </div>
        </div>
      </section>
      <footer className="auth-footer">
        Cyber Pipeline Dashboard v{APP_VERSION} &bull; {new Date().getFullYear()}
      </footer>
    </main>
  );
}
