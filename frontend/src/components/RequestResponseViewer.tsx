import { useState, useCallback, useMemo } from 'react';
import { cn } from '@/lib/utils';
import { Icon } from '@/components/Icon';
import type { RequestResponsePair } from '@/types/api';

const SENSITIVE_PATTERNS = [
   
  { regex: /(?:Bearer\s+|token[=:\s]+|api[_-]?key[=:\s]+|access[_-]?token[=:\s]+)["']?([A-Za-z0-9\-._~+/]+=*)/gi, label: 'Token' },
   
  { regex: /(?:password|passwd|pwd|secret|credential)[=:\s]+["']?([^\s"']+)/gi, label: 'Credential' },
   
  { regex: /(?:Authorization|Cookie|X-Api-Key|X-Auth-Token)[=:\s]+["']?([^\s"']+)/gi, label: 'Auth Header' },
   
  { regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, label: 'Email' },
];

function decodePayload(data: string, encoding?: string): string {
  if (!data) return '';
  try {
    if (encoding === 'base64') {
      return atob(data);
    }
    if (encoding === 'url') {
      return decodeURIComponent(data);
    }
    if (encoding === 'hex') {
   
      return data.replace(/([0-9a-fA-F]{2})/g, (match) =>
        String.fromCharCode(parseInt(match, 16))
      );
    }
  } catch {
    return data;
  }
  return data;
}

function detectContentType(body: string, headers?: Record<string, string>): string {
  if (headers) {
   
    const ct = headers['Content-Type'] || headers['content-type'] || '';
    if (ct.includes('json')) return 'json';
    if (ct.includes('xml')) return 'xml';
    if (ct.includes('html')) return 'html';
  }
  const trimmed = body.trim();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) return 'json';
  if (trimmed.startsWith('<?xml') || trimmed.startsWith('<')) return 'xml';
  if (trimmed.startsWith('<!DOCTYPE') || trimmed.startsWith('<html')) return 'html';
  return 'text';
}

function formatPayload(body: string, contentType: string): string {
  if (!body) return '';
  try {
    if (contentType === 'json') {
      return JSON.stringify(JSON.parse(body), null, 2);
    }
  } catch {
    // Not valid JSON, return as-is
  }
  return body;
}

function redactText(text: string): string {
  let result = text;
  for (const { regex, label } of SENSITIVE_PATTERNS) {
   
    result = result.replace(regex, `[REDACTED: ${label}]`);
  }
  return result;
}

function buildCurlCommand(pair: RequestResponsePair): string {
  const { request } = pair;
  let cmd = `curl -X ${request.method} '${request.url}'`;

  if (request.headers) {
   
    for (const [key, value] of Object.entries(request.headers)) {
      cmd += ` \\\n  -H '${key}: ${value}'`;
    }
  }

  if (request.body) {
    const decoded = decodePayload(request.body, request.body_encoding);
    cmd += ` \\\n  -d '${decoded.replace(/'/g, "'\\''")}'`;
  }

  return cmd;
}

function copyToClipboard(text: string): Promise<void> {
  return navigator.clipboard.writeText(text);
}

type ViewMode = 'request' | 'response' | 'diff';

export interface RequestResponseViewerProps {
  pairs: RequestResponsePair[];
  className?: string;
  defaultRedacted?: boolean;
}

export function RequestResponseViewer({ pairs, className, defaultRedacted = false }: RequestResponseViewerProps) {
   
  const [activeIndex, setActiveIndex] = useState(0);
   
  const [viewMode, setViewMode] = useState<ViewMode>('request');
   
  const [redacted, setRedacted] = useState(defaultRedacted);
   
  const [decoded, setDecoded] = useState(true);
   
  const [copied, setCopied] = useState(false);

  // eslint-disable-next-line security/detect-object-injection
  const currentPair = pairs[activeIndex] ?? null;

  const processedRequest = useMemo(() => {
    if (!currentPair) return { headers: '', body: '' };
    const req = currentPair.request;
    const headers = Object.entries(req.headers || {})
   
      .map(([k, v]) => `${k}: ${v}`)
      .join('\n');
    let body = req.body || '';
    if (decoded) body = decodePayload(body, req.body_encoding);
    const contentType = detectContentType(body, req.headers);
    body = formatPayload(body, contentType);
    if (redacted) body = redactText(body);
    return { headers, body, method: req.method, url: req.url };
   
  }, [currentPair, decoded, redacted]);

  const processedResponse = useMemo(() => {
    if (!currentPair) return { headers: '', body: '' };
    const res = currentPair.response;
    const headers = Object.entries(res.headers || {})
   
      .map(([k, v]) => `${k}: ${v}`)
      .join('\n');
    let body = res.body || '';
    if (decoded) body = decodePayload(body, res.body_encoding);
    const contentType = detectContentType(body, res.headers);
    body = formatPayload(body, contentType);
    if (redacted) body = redactText(body);
    return { headers, body, status: res.status };
   
  }, [currentPair, decoded, redacted]);

  const handleCopyCurl = useCallback(async () => {
    if (!currentPair) return;
    const curl = buildCurlCommand(currentPair);
    try {
      await copyToClipboard(curl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard not available
    }
   
  }, [currentPair]);

  const handleCopyBody = useCallback(async (body: string) => {
    try {
      await copyToClipboard(body);
    } catch {
      // Clipboard not available
    }
  }, []);

  if (!pairs || pairs.length === 0) {
    return (
      <div className={cn('rr-viewer', className)}>
        <div className="rr-empty">
          <Icon name="shield" size={24} className="text-muted" />
          <span>No request/response data available</span>
        </div>
      </div>
    );
  }

  const getStatusColor = (status: number): string => {
    if (status >= 500) return 'var(--bad)';
    if (status >= 400) return 'var(--warn)';
    if (status >= 300) return 'var(--accent-2)';
    if (status >= 200) return 'var(--ok)';
    return 'var(--muted)';
  };

  return (
    <div className={cn('rr-viewer', className)}>
      <div className="rr-header">
        <div className="rr-tabs">
          {pairs.map((pair, idx) => (
            <button
              key={pair.id || idx}
              className={cn('rr-tab', activeIndex === idx && 'active')}
              onClick={() => setActiveIndex(idx)}
            >
              Request {idx + 1}
              {pair.response && (
                <span
                  className="rr-status-badge"
                  style={{ color: getStatusColor(pair.response.status) }}
                >
                  {pair.response.status}
                </span>
              )}
            </button>
          ))}
        </div>

        <div className="rr-controls">
          <div className="rr-view-toggle">
            <button
              className={cn('rr-control-btn', viewMode === 'request' && 'active')}
              onClick={() => setViewMode('request')}
            >
              Request
            </button>
            <button
              className={cn('rr-control-btn', viewMode === 'response' && 'active')}
              onClick={() => setViewMode('response')}
            >
              Response
            </button>
            {pairs.length > 1 && (
              <button
                className={cn('rr-control-btn', viewMode === 'diff' && 'active')}
                onClick={() => setViewMode('diff')}
              >
                Diff
              </button>
            )}
          </div>

          <button
            className={cn('rr-control-btn', decoded && 'active')}
            onClick={() => setDecoded(prev => !prev)}
          >
            Decode
          </button>

          <button
            className={cn('rr-control-btn', redacted && 'active')}
            onClick={() => setRedacted(prev => !prev)}
          >
            <Icon name="eye-off" size={14} />
            Redact
          </button>

          <button
            className="rr-control-btn rr-curl-btn"
            onClick={handleCopyCurl}
          >
            {copied ? 'Copied!' : 'Copy as curl'}
          </button>
        </div>
      </div>

      {currentPair && viewMode !== 'diff' && (
        <div className="rr-content">
          {(viewMode === 'request' || viewMode === 'response') && (
            <div className={cn('rr-panel', viewMode === 'request' ? 'rr-request' : 'rr-response')}>
              {viewMode === 'request' && (
                <>
                  <div className="rr-panel-header">
                    <span className="rr-method">{processedRequest.method}</span>
                    <span className="rr-url">{processedRequest.url}</span>
                  </div>
                  {processedRequest.headers && (
                    <div className="rr-section">
                      <div className="rr-section-header">
                        Headers
                        <button
                          className="rr-copy-btn"
                          onClick={() => handleCopyBody(processedRequest.headers)}
                        >
                          Copy
                        </button>
                      </div>
                      <pre className="rr-headers">{processedRequest.headers}</pre>
                    </div>
                  )}
                  {processedRequest.body && (
                    <div className="rr-section">
                      <div className="rr-section-header">
                        Body
                        <button
                          className="rr-copy-btn"
                          onClick={() => handleCopyBody(processedRequest.body)}
                        >
                          Copy
                        </button>
                      </div>
                      <pre className={cn('rr-body', `lang-${detectContentType(currentPair.request.body || '', currentPair.request.headers)}`)}>
                        {processedRequest.body}
                      </pre>
                    </div>
                  )}
                </>
              )}

              {viewMode === 'response' && (
                <>
                  <div className="rr-panel-header">
                    <span
                      className="rr-status"
                      style={{ color: getStatusColor(processedResponse.status || 0) }}
                    >
                      {processedResponse.status}
                    </span>
                  </div>
                  {processedResponse.headers && (
                    <div className="rr-section">
                      <div className="rr-section-header">
                        Headers
                        <button
                          className="rr-copy-btn"
                          onClick={() => handleCopyBody(processedResponse.headers)}
                        >
                          Copy
                        </button>
                      </div>
                      <pre className="rr-headers">{processedResponse.headers}</pre>
                    </div>
                  )}
                  {processedResponse.body && (
                    <div className="rr-section">
                      <div className="rr-section-header">
                        Body
                        <button
                          className="rr-copy-btn"
                          onClick={() => handleCopyBody(processedResponse.body)}
                        >
                          Copy
                        </button>
                      </div>
                      <pre className={cn('rr-body', `lang-${detectContentType(currentPair.response.body || '', currentPair.response.headers)}`)}>
                        {processedResponse.body}
                      </pre>
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      )}

      {currentPair && viewMode === 'diff' && pairs.length > 1 && (
        <div className="rr-diff">
          {pairs.map((pair, idx) => (
            <div key={pair.id || idx} className="rr-diff-panel">
              <div className="rr-diff-header">Request {idx + 1}</div>
              <pre className="rr-body">
                {decoded
                  ? decodePayload(pair.request.body || '', pair.request.body_encoding)
                  : pair.request.body || ''}
              </pre>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
