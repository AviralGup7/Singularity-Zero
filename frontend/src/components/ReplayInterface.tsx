import { useState } from 'react';
import { replayRequest } from '@/api/client';
import type { ReplayResult } from '@/types/api';

interface ReplayInterfaceProps {
  targetName?: string;
  runName?: string;
  replayId?: string;
}

export default function ReplayInterface({ targetName, runName, replayId }: ReplayInterfaceProps) {
   
  const [target, setTarget] = useState(targetName || '');
   
  const [run, setRun] = useState(runName || '');
   
  const [replay, setReplay] = useState(replayId || '');
   
  const [authMode, setAuthMode] = useState('inherit');
   
  const [authorization, setAuthorization] = useState('');
   
  const [loading, setLoading] = useState(false);
   
  const [error, setError] = useState<string | null>(null);
   
  const [result, setResult] = useState<ReplayResult | null>(null);
   
  const [targetError, setTargetError] = useState<string | null>(null);
   
  const [runError, setRunError] = useState<string | null>(null);
   
  const [replayError, setReplayError] = useState<string | null>(null);

  const handleReplay = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setResult(null);
    setTargetError(null);
    setRunError(null);
    setReplayError(null);

    let hasError = false;
    if (!target.trim()) {
      setTargetError('Target name is required.');
      hasError = true;
    }
    if (!run.trim()) {
      setRunError('Run name is required.');
      hasError = true;
    }
    if (!replay.trim()) {
      setReplayError('Replay ID is required.');
      hasError = true;
    }

    if (hasError) {
      setError('Please fix the errors below.');
      return;
    }

    setLoading(true);
    try {
      const data = await replayRequest({
        target,
        run,
        replay_id: replay,
        auth_mode: authMode,
        authorization: authorization || undefined,
      });
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Replay request failed');
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (changed: boolean | null) => {
    if (changed === null) return 'var(--muted)';
    return changed ? 'var(--bad)' : 'var(--ok)';
  };

  const getStatusIcon = (changed: boolean | null) => {
    if (changed === null) return '—';
    return changed ? '⚠️ Changed' : '✅ Unchanged';
  };
  // FIX: Removed unused getStatusLabel function

  return (
    <div className="section">
      <div className="section-title">🔄 Replay Request</div>

      <form onSubmit={handleReplay} className="card card-padded">
        {error && <div className="banner error" role="alert">{error}</div>}

        <div className="replay-form-grid">
          <div>
            <label htmlFor="replay-target" className="form-label">
              Target Name
            </label>
            <input
              id="replay-target"
              type="text"
              value={target}
              onChange={e => { setTarget(e.target.value); if (targetError) setTargetError(null); }}
              placeholder="example-com"
              required
              aria-required="true"
              aria-invalid={!!targetError}
              aria-describedby={targetError ? 'replay-target-error' : undefined}
              className={`form-input${targetError ? ' form-input--error' : ''}`}
            />
            {targetError && (
              <div id="replay-target-error" className="form-error" role="alert" aria-live="polite">
                {targetError}
              </div>
            )}
          </div>
          <div>
            <label htmlFor="replay-run" className="form-label">
              Run Name
            </label>
            <input
              id="replay-run"
              type="text"
              value={run}
              onChange={e => { setRun(e.target.value); if (runError) setRunError(null); }}
              placeholder="2026-04-03T10:00:00"
              required
              aria-required="true"
              aria-invalid={!!runError}
              aria-describedby={runError ? 'replay-run-error' : undefined}
              className={`form-input${runError ? ' form-input--error' : ''}`}
            />
            {runError && (
              <div id="replay-run-error" className="form-error" role="alert" aria-live="polite">
                {runError}
              </div>
            )}
          </div>
          <div>
            <label htmlFor="replay-id" className="form-label">
              Replay ID
            </label>
            <input
              id="replay-id"
              type="text"
              value={replay}
              onChange={e => { setReplay(e.target.value); if (replayError) setReplayError(null); }}
              placeholder="replay-001"
              required
              aria-required="true"
              aria-invalid={!!replayError}
              aria-describedby={replayError ? 'replay-id-error' : undefined}
              className={`form-input${replayError ? ' form-input--error' : ''}`}
            />
            {replayError && (
              <div id="replay-id-error" className="form-error" role="alert" aria-live="polite">
                {replayError}
              </div>
            )}
          </div>
        </div>

        <div className="replay-form-grid">
          <div>
            <label htmlFor="replay-auth-mode" className="form-label">
              Auth Mode
            </label>
            <select
              id="replay-auth-mode"
              value={authMode}
              onChange={e => setAuthMode(e.target.value)}
              className="form-select"
            >
              <option value="inherit">Inherit</option>
              <option value="custom">Custom</option>
              <option value="none">None</option>
            </select>
          </div>
          <div>
            <label htmlFor="replay-authorization" className="form-label">
              Authorization Header
            </label>
            <input
              id="replay-authorization"
              type="text"
              value={authorization}
              onChange={e => setAuthorization(e.target.value)}
              placeholder="Bearer token..."
              className="form-input"
              disabled={authMode !== 'custom'}
            />
          </div>
        </div>

        <button type="submit" className={`btn w-full ${loading ? 'btn-loading' : ''}`} disabled={loading}>
          {loading ? 'Replaying...' : '🔄 Replay Request'}
        </button>
      </form>

      {result && (
        <div className="card card-padded mt-16 animate-in fade-in slide-in-from-top-4 duration-300">
          <h3 className="mb-16 text-accent">📊 Replay Results</h3>

          <div className="replay-stat-grid">
            <div className="stat-box">
              <div className="text-xxs text-muted uppercase tracking-widest font-bold">Status Code</div>
              <div className={`text-2xl font-black font-mono ${result.status_code && result.status_code >= 400 ? 'text-bad' : 'text-ok'}`}>
                {result.status_code ?? '—'}
              </div>
            </div>
            <div className="stat-box">
              <div className="text-xxs text-muted uppercase tracking-widest font-bold">Body Similarity</div>
              <div className="text-2xl font-black font-mono text-text">
                {result.body_similarity !== null ? `${Math.round(result.body_similarity * 100)}%` : '—'}
              </div>
            </div>
            <div className="stat-box">
              <div className="text-xxs text-muted uppercase tracking-widest font-bold">Auth Mode</div>
              <div className="text-lg font-bold text-accent">{result.auth_mode.toUpperCase()}</div>
            </div>
          </div>

          <div className="mb-16">
            <h4 className="text-md text-accent mb-8">Change Detection</h4>
            <div className="replay-change-grid">
              <div className="change-box">
                <div className="text-xxs text-muted">Status Changed</div>
                <div className="text-sm status-dynamic" style={{ '--status-color': getStatusColor(result.status_changed) } as React.CSSProperties}>
                  {getStatusIcon(result.status_changed)}
                </div>
              </div>
              <div className="change-box">
                <div className="text-xxs text-muted">Redirect Changed</div>
                <div className="text-sm status-dynamic" style={{ '--status-color': getStatusColor(result.redirect_changed) } as React.CSSProperties}>
                  {getStatusIcon(result.redirect_changed)}
                </div>
              </div>
              <div className="change-box">
                <div className="text-xxs text-muted">Content Changed</div>
                <div className="text-sm status-dynamic" style={{ '--status-color': getStatusColor(result.content_changed) } as React.CSSProperties}>
                  {getStatusIcon(result.content_changed)}
                </div>
              </div>
            </div>
          </div>

          {result.redirect_chain && result.redirect_chain.length > 0 && (
            <div className="mb-16">
              <h4 className="text-md text-accent mb-8">Redirect Chain</h4>
              <div className="redirect-chain">
                {result.redirect_chain.map((url, i) => (
                  <div key={i} className="redirect-chain-item">
                    {i > 0 && <span className="redirect-arrow"> → </span>}
                    {url}
                  </div>
                ))}
              </div>
            </div>
          )}

          <div>
            <h4 className="text-md text-accent mb-8">Applied Headers</h4>
            <div className="flex gap-4 flex-wrap">
              {result.applied_header_names.map(name => (
                <span key={name} className="sev info text-sm">
                  {name}
                </span>
              ))}
              {result.applied_header_names.length === 0 && (
                <span className="text-sm text-muted">No headers applied</span>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
