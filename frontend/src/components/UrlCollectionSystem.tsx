import { useCallback, useMemo, useRef, useState, type ChangeEvent } from 'react';
import { useToast } from '@/hooks/useToast';
import { usePersistedState } from '@/hooks/usePersistedState';
import { parseUrls, validateUrl } from '@/lib/utils';

type UrlCollectionStatus = 'new' | 'queued' | 'running' | 'started' | 'failed';
type CollectionSource = 'manual' | 'file';

interface UrlCollectionItem {
  id: string;
  url: string;
  hostname: string;
  status: UrlCollectionStatus;
  addedAt: string;
  source: CollectionSource;
  lastJobId?: string;
  processedAt?: string;
  processingProfile?: 'quick' | 'full';
  errorMessage?: string;
}

interface ImportReport {
  added: number;
  duplicates: number;
  invalid: string[];
}

const STORAGE_KEY = 'targets-url-collection-v1';
const TRACKING_PARAM_RE = /^(utm_|fbclid$|gclid$|msclkid$)/i;
const STATIC_ASSET_RE = /\.(?:png|jpe?g|gif|svg|ico|webp|css|js|map|woff2?|ttf|eot|pdf)$/i;

function normalizeCollectedUrl(input: string): string {
  const withProtocol = input.match(/^https?:\/\//i) ? input : `https://${input}`;
  const parsed = new URL(withProtocol);

  parsed.protocol = parsed.protocol.toLowerCase();
  parsed.hostname = parsed.hostname.toLowerCase();

  if ((parsed.protocol === 'https:' && parsed.port === '443') || (parsed.protocol === 'http:' && parsed.port === '80')) {
    parsed.port = '';
  }

  parsed.hash = '';

  // Drop common tracking params and keep deterministic ordering for dedupe.
  const params = new URLSearchParams(parsed.search);
   
  const kept: Array<[string, string]> = [];
  params.forEach((value, key) => {
    if (!TRACKING_PARAM_RE.test(key)) {
   
      kept.push([key, value]);
    }
  });
   
  kept.sort(([a], [b]) => a.localeCompare(b));
  parsed.search = kept.length > 0 ? `?${new URLSearchParams(kept).toString()}` : '';

  if (parsed.pathname.length > 1) {
    parsed.pathname = parsed.pathname.replace(/\/+$/, '');
  }

  return parsed.toString();
}

function statusTone(status: UrlCollectionStatus): string {
  if (status === 'started') return 'ok';
  if (status === 'failed') return 'bad';
  if (status === 'running') return 'accent';
  return 'muted';
}

function createCollectionId(): string {
  return `url-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

function createLocalJobId(hostname: string, mode: 'quick' | 'full'): string {
   
  const safeHost = hostname.replace(/[^a-z0-9]/gi, '').toLowerCase().slice(0, 12) || 'target';
  return `local-${mode}-${safeHost}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
}

function statusLabel(status: UrlCollectionStatus): string {
  if (status === 'new') return 'New';
  if (status === 'queued') return 'Queued';
  if (status === 'running') return 'Running';
  if (status === 'started') return 'Started';
  return 'Failed';
}

export function UrlCollectionSystem() {
  const toast = useToast();
   
  const [items, setItems] = usePersistedState<UrlCollectionItem[]>(STORAGE_KEY, []);
   
  const [draftInput, setDraftInput] = useState('');
   
  const [query, setQuery] = useState('');
   
  const [statusFilter, setStatusFilter] = useState<'all' | UrlCollectionStatus>('all');
   
  const [sourceFilter, setSourceFilter] = useState<'all' | CollectionSource>('all');
   
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
   
  const [scanMode, setScanMode] = useState<'quick' | 'full'>('quick');
   
  const [isSubmitting, setIsSubmitting] = useState(false);
   
  const [processingProgress, setProcessingProgress] = useState(0);
   
  const [importReport, setImportReport] = useState<ImportReport | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const filteredItems = useMemo(() => {
    return items.filter((item) => {
      if (statusFilter !== 'all' && item.status !== statusFilter) return false;
      if (sourceFilter !== 'all' && item.source !== sourceFilter) return false;
      if (!query.trim()) return true;
      const q = query.trim().toLowerCase();
      return item.url.toLowerCase().includes(q) || item.hostname.toLowerCase().includes(q);
    });
   
  }, [items, query, sourceFilter, statusFilter]);

  const stats = useMemo(() => {
    return items.reduce(
      (acc, item) => {
        acc.total += 1;
   
        acc[item.status] += 1;
        return acc;
      },
      { total: 0, new: 0, queued: 0, running: 0, started: 0, failed: 0 }
    );
   
  }, [items]);

  const riskStats = useMemo(() => {
    let staticAssets = 0;
    let hasQuery = 0;
    for (const item of items) {
      try {
        const parsed = new URL(item.url);
        if (STATIC_ASSET_RE.test(parsed.pathname)) staticAssets += 1;
        if (parsed.searchParams.size > 0) hasQuery += 1;
      } catch {
        // Ignore malformed legacy entries in storage.
      }
    }
    return { staticAssets, hasQuery };
   
  }, [items]);

  const allFilteredSelected = filteredItems.length > 0 && filteredItems.every(item => selectedIds.has(item.id));

  const ingestRawUrls = useCallback((rawInput: string, source: CollectionSource) => {
    const raw = rawInput.trim();
    if (!raw) {
      toast.info('Paste one or more URLs to add them to the collection.');
      return;
    }

    const existing = new Set(items.map(item => item.url));
    const seenInBatch = new Set<string>();
    const parsed = parseUrls(raw);
   
    const invalid: string[] = [];
    let duplicates = 0;
   
    const nextItems: UrlCollectionItem[] = [];

    for (const candidate of parsed) {
      const validation = validateUrl(candidate);
      if (!validation.valid) {
        invalid.push(`${candidate} (${validation.error || 'Invalid URL'})`);
        continue;
      }

      let normalized = '';
      try {
        normalized = normalizeCollectedUrl(candidate);
      } catch {
        invalid.push(`${candidate} (Failed to normalize URL)`);
        continue;
      }

      if (existing.has(normalized) || seenInBatch.has(normalized)) {
        duplicates += 1;
        continue;
      }

      seenInBatch.add(normalized);
      const parsedUrl = new URL(normalized);
      nextItems.push({
        id: createCollectionId(),
        url: normalized,
        hostname: parsedUrl.hostname,
        status: 'new',
        addedAt: new Date().toISOString(),
        source,
      });
    }

    if (nextItems.length > 0) {
   
      setItems(prev => [...nextItems, ...prev]);
      setSelectedIds(prev => {
        const next = new Set(prev);
        nextItems.forEach(item => next.add(item.id));
        return next;
      });
      toast.success(`Added ${nextItems.length} URL${nextItems.length === 1 ? '' : 's'} to collection.`);
    }

    if (duplicates > 0) {
      toast.info(`Skipped ${duplicates} duplicate URL${duplicates === 1 ? '' : 's'}.`);
    }

    if (invalid.length > 0) {
      toast.warning(`Skipped ${invalid.length} invalid URL${invalid.length === 1 ? '' : 's'}.`);
    }

    setImportReport({ added: nextItems.length, duplicates, invalid });
   
  }, [items, setItems, toast]);

  const handleAddUrls = useCallback(() => {
    ingestRawUrls(draftInput, 'manual');
    setDraftInput('');
   
  }, [draftInput, ingestRawUrls]);

  const handleImportFile = useCallback(async (event: ChangeEvent<HTMLInputElement>) => {
   
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      ingestRawUrls(text, 'file');
    } catch {
      toast.error('Failed to read selected file.');
    } finally {
      event.target.value = '';
    }
   
  }, [ingestRawUrls, toast]);

  const toggleItemSelection = useCallback((itemId: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(itemId)) next.delete(itemId);
      else next.add(itemId);
      return next;
    });
  }, []);

  const toggleSelectAllFiltered = useCallback(() => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (allFilteredSelected) {
        filteredItems.forEach(item => next.delete(item.id));
      } else {
        filteredItems.forEach(item => next.add(item.id));
      }
      return next;
    });
   
  }, [allFilteredSelected, filteredItems]);

  const removeSelected = useCallback(() => {
    if (selectedIds.size === 0) {
      toast.info('Select at least one URL to remove it.');
      return;
    }
    setItems(prev => prev.filter(item => !selectedIds.has(item.id)));
    setSelectedIds(new Set());
    toast.success('Selected URLs were removed from collection.');
   
  }, [selectedIds, setItems, toast]);

  const clearCollection = useCallback(() => {
    if (items.length === 0) return;
    if (!window.confirm('Clear all URLs from this collection?')) return;
    setItems([]);
    setSelectedIds(new Set());
    setImportReport(null);
    setProcessingProgress(0);
   
  }, [items.length, setItems]);

  const exportCollection = useCallback(() => {
    if (items.length === 0) {
      toast.info('Collection is empty.');
      return;
    }
    const payload = items.map(item => item.url).join('\n');
   
    const blob = new Blob([payload], { type: 'text/plain;charset=utf-8' });
    const href = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = href;
    a.download = `url-collection-${new Date().toISOString().slice(0, 10)}.txt`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(href);
   
  }, [items, toast]);

  const resetStatuses = useCallback(() => {
    setItems(prev => prev.map(item => ({
      ...item,
      status: 'new',
      lastJobId: undefined,
      processedAt: undefined,
      processingProfile: undefined,
      errorMessage: undefined,
    })));
    setSelectedIds(new Set());
    setProcessingProgress(0);
   
  }, [setItems]);

  const selectFailed = useCallback(() => {
    const failed = items.filter(item => item.status === 'failed').map(item => item.id);
    if (failed.length === 0) {
      toast.info('No failed URLs to select.');
      return;
    }
    setSelectedIds(new Set(failed));
   
  }, [items, toast]);

  const startCollectionScan = useCallback(async () => {
    const targetIds = Array.from(selectedIds);
    if (targetIds.length === 0) {
      toast.info('Select URLs to queue scans.');
      return;
    }

   
    const snapshot = new Map(items.map(item => [item.id, { ...item }]));
    const selectedSet = new Set(targetIds);
    setItems(prev => prev.map(item => (selectedSet.has(item.id)
      ? { ...item, status: 'queued', errorMessage: undefined }
      : item)));

    setIsSubmitting(true);
    setProcessingProgress(0);

    let started = 0;
    let failed = 0;
   
    const failedIds: string[] = [];

    for (let i = 0; i < targetIds.length; i += 1) {
  // eslint-disable-next-line security/detect-object-injection
      const itemId = targetIds[i];
      const item = snapshot.get(itemId);
      if (!item) {
        failed += 1;
        failedIds.push(itemId);
        continue;
      }

      setItems(prev => prev.map(current => (
        current.id === itemId
          ? { ...current, status: 'running', errorMessage: undefined }
          : current
      )));

      // Simulate in-browser processing pipeline without network calls.
      const delayMs = scanMode === 'quick' ? 60 : 140;
      await new Promise<void>(resolve => {
        window.setTimeout(() => resolve(), delayMs);
      });

      try {
        const normalized = normalizeCollectedUrl(item.url);
        const parsedUrl = new URL(normalized);
        if (scanMode === 'full' && STATIC_ASSET_RE.test(parsedUrl.pathname)) {
          throw new Error('Static asset URLs are low-value for full profile.');
        }

        setItems(prev => prev.map(current => (
          current.id === itemId
            ? {
              ...current,
              status: 'started',
              lastJobId: createLocalJobId(parsedUrl.hostname, scanMode),
              processedAt: new Date().toISOString(),
              processingProfile: scanMode,
              errorMessage: undefined,
            }
            : current
        )));
        started += 1;
      } catch (error) {
        failed += 1;
        failedIds.push(itemId);
        setItems(prev => prev.map(current => (
          current.id === itemId
            ? {
              ...current,
              status: 'failed',
              processingProfile: scanMode,
              errorMessage: error instanceof Error ? error.message : 'Local processing failed.',
            }
            : current
        )));
      }

      setProcessingProgress(Math.round(((i + 1) / targetIds.length) * 100));
    }

    setIsSubmitting(false);
    setSelectedIds(new Set(failedIds));

    if (started > 0) {
      toast.success(`Processed ${started} URL${started === 1 ? '' : 's'} locally.`);
    }
    if (failed > 0) {
      toast.warning(`${failed} URL${failed === 1 ? '' : 's'} failed local checks.`);
    }
   
  }, [items, scanMode, selectedIds, setItems, toast]);

  return (
    <section className="card card-padded url-collection-panel" aria-label="URL collection system">
      <div className="url-collection-header">
        <div>
          <h3 className="url-collection-title">URL Collection System</h3>
          <p className="url-collection-subtitle">Collect, normalize, and process URLs entirely in-browser with no external tool calls.</p>
        </div>
        <div className="url-collection-stats" aria-label="URL collection statistics">
          <span className="url-stat">Total: {stats.total}</span>
          <span className="url-stat">New: {stats.new}</span>
          <span className="url-stat">Started: {stats.started}</span>
          <span className="url-stat">Failed: {stats.failed}</span>
          <span className="url-stat">Query URLs: {riskStats.hasQuery}</span>
          <span className="url-stat">Static Assets: {riskStats.staticAssets}</span>
        </div>
      </div>

      <div className="url-collection-ingest">
        <label htmlFor="url-collection-input" className="filter-group-label">Add URLs (comma, newline, or semicolon separated)</label>
        <textarea
          id="url-collection-input"
          value={draftInput}
          onChange={e => setDraftInput(e.target.value)}
          className="form-textarea url-collection-input"
          rows={3}
          placeholder="https://example.com&#10;app.example.com/login&#10;api.example.com/v1/users"
        />
        <div className="url-collection-actions">
          <button type="button" className="btn btn-primary btn-sm" onClick={handleAddUrls}>
            Add to Collection
          </button>
          <button type="button" className="btn btn-secondary btn-sm" onClick={() => fileInputRef.current?.click()}>
            Import File
          </button>
          <button type="button" className="btn btn-secondary btn-sm" onClick={exportCollection}>
            Export
          </button>
          <button type="button" className="btn btn-danger btn-sm" onClick={clearCollection}>
            Clear All
          </button>
        </div>
        <input
          ref={fileInputRef}
          type="file"
          accept=".txt,.csv,.log,.md"
          className="url-collection-file-input"
          onChange={handleImportFile}
        />
      </div>

      {importReport && (
        <div className="url-collection-import-report" role="status">
          <span>Added: {importReport.added}</span>
          <span>Duplicates: {importReport.duplicates}</span>
          <span>Invalid: {importReport.invalid.length}</span>
          {importReport.invalid.length > 0 && (
   
            <span className="url-collection-import-example" title={importReport.invalid[0]}>
  // eslint-disable-next-line security/detect-object-injection
              First error: {importReport.invalid[0]}
            </span>
          )}
        </div>
      )}

      <div className="url-collection-toolbar">
        <input
          type="text"
          className="search-input"
          value={query}
          onChange={e => setQuery(e.target.value)}
          placeholder="Search collected URLs"
          aria-label="Search collected URLs"
        />
        <select
          className="form-input form-input-sm"
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value as 'all' | UrlCollectionStatus)}
          aria-label="Filter URLs by status"
        >
          <option value="all">All Statuses</option>
          <option value="new">New</option>
          <option value="queued">Queued</option>
          <option value="running">Running</option>
          <option value="started">Started</option>
          <option value="failed">Failed</option>
        </select>
        <select
          className="form-input form-input-sm"
          value={sourceFilter}
          onChange={e => setSourceFilter(e.target.value as 'all' | CollectionSource)}
          aria-label="Filter URLs by source"
        >
          <option value="all">All Sources</option>
          <option value="manual">Manual</option>
          <option value="file">File Import</option>
        </select>
        <select
          className="form-input form-input-sm"
          value={scanMode}
          onChange={e => setScanMode(e.target.value as 'quick' | 'full')}
          aria-label="Local processing profile"
        >
          <option value="quick">Quick Profile</option>
          <option value="full">Full Profile</option>
        </select>
        <button type="button" className="btn btn-primary btn-sm" onClick={startCollectionScan} disabled={isSubmitting || selectedIds.size === 0}>
          {isSubmitting ? 'Processing...' : `Process Locally (${selectedIds.size})`}
        </button>
        <button type="button" className="btn btn-secondary btn-sm" onClick={removeSelected}>
          Remove Selected
        </button>
        <button type="button" className="btn btn-secondary btn-sm" onClick={selectFailed}>
          Select Failed
        </button>
        <button type="button" className="btn btn-secondary btn-sm" onClick={resetStatuses}>
          Reset Statuses
        </button>
      </div>

      {isSubmitting && (
        <div className="url-collection-progress" role="status" aria-live="polite">
          <span>Local processing progress: {processingProgress}%</span>
          <div className="url-collection-progress-track" aria-hidden="true">
            <div className="url-collection-progress-fill" style={{ width: `${processingProgress}%` }} />
          </div>
        </div>
      )}

      <div className="url-collection-table-wrap">
        <table className="url-collection-table">
          <thead>
            <tr>
              <th>
                <input
                  type="checkbox"
                  checked={allFilteredSelected}
                  onChange={toggleSelectAllFiltered}
                  aria-label="Select all filtered URLs"
                />
              </th>
              <th>URL</th>
              <th>Host</th>
              <th>Source</th>
              <th>Status</th>
              <th>Profile</th>
              <th>Last Job</th>
              <th>Processed</th>
              <th>Added</th>
            </tr>
          </thead>
          <tbody>
            {filteredItems.length === 0 ? (
              <tr>
                <td colSpan={9} className="url-collection-empty">No URLs in the collection.</td>
              </tr>
            ) : (
              filteredItems.map(item => (
                <tr key={item.id} className={selectedIds.has(item.id) ? 'row-selected' : ''}>
                  <td>
                    <input
                      type="checkbox"
                      checked={selectedIds.has(item.id)}
                      onChange={() => toggleItemSelection(item.id)}
                      aria-label={`Select ${item.url}`}
                    />
                  </td>
                  <td>
                    <div className="url-collection-url-cell" title={item.url}>{item.url}</div>
                    {item.errorMessage && <div className="url-collection-error">{item.errorMessage}</div>}
                  </td>
                  <td>{item.hostname}</td>
                  <td>{item.source === 'manual' ? 'Manual' : 'File'}</td>
                  <td>
                    <span className={`url-status-badge tone-${statusTone(item.status)}`}>
                      {statusLabel(item.status)}
                    </span>
                  </td>
                  <td>{item.processingProfile || '—'}</td>
                  <td>{item.lastJobId || '—'}</td>
                  <td>{item.processedAt ? new Date(item.processedAt).toLocaleString() : '—'}</td>
                  <td>{new Date(item.addedAt).toLocaleString()}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}