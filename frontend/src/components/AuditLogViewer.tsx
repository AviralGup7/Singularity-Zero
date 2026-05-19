import { useState, useEffect, useCallback } from 'react';
import { ShieldCheck, ShieldAlert, RefreshCw, Fingerprint } from 'lucide-react';
import { getBackendAuditEntries, verifyAuditIntegrity, type BackendAuditEntry } from '@/api/audit';
import { useToast } from '@/hooks/useToast';

interface AuditLogViewerProps {
  className?: string;
}

export function AuditLogViewer({ className }: AuditLogViewerProps) {
  const toast = useToast();
   
  const [entries, setEntries] = useState<BackendAuditEntry[]>([]);
   
  const [loading, setLoading] = useState(true);
   
  const [verifying, setVerifying] = useState(false);
   
  const [integrity, setIntegrity] = useState<{ is_valid: boolean; compromised_ids: number[] } | null>(null);
   
  const [filter, setFilter] = useState('');
   
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const fetchEntries = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    try {
      const data = await getBackendAuditEntries({ limit: 200, signal });
      setEntries(data);
    } catch (err) {
       if (!(err instanceof Error && err.name === 'AbortError')) {
         toast.error('Failed to sync audit telemetry');
       }
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    const controller = new AbortController();
    fetchEntries(controller.signal);
    return () => controller.abort();
  }, [fetchEntries]);

  const handleVerify = async () => {
    setVerifying(true);
    try {
      const result = await verifyAuditIntegrity();
      setIntegrity(result);
      if (result.is_valid) {
        toast.success('Audit log integrity verified (HMAC Chain OK)');
      } else {
        toast.error(`TAMPER DETECTED: ${result.compromised_ids.length} entries compromised`);
      }
    } catch {
      toast.error('Integrity verification failed');
    } finally {
      setVerifying(false);
    }
  };

  const filtered = entries.filter((e) => {
    if (!filter) return true;
    const f = filter.toLowerCase();
    return (
      e.event.toLowerCase().includes(f) ||
      (e.user_id?.toLowerCase() || '').includes(f) ||
      (e.resource_id?.toLowerCase() || '').includes(f)
    );
  });

  return (
    <div className={`audit-log-viewer p-6 space-y-6 ${className || ''}`}>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-black uppercase tracking-tighter">Chain-of-Custody Audit Log</h1>
          <p className="text-xs text-muted font-mono uppercase mt-1">Tamper-evident hash chaining active</p>
        </div>
        <div className="flex items-center gap-2">
          <input
            type="text"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="FILTER EVENTS..."
            className="bg-white/5 border border-white/10 rounded px-3 py-1.5 text-xs font-mono uppercase focus:border-accent/40 outline-none"
          />
          <button onClick={() => fetchEntries()} className="btn-secondary btn-small p-2" title="Refresh">
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          </button>
          <button 
            onClick={handleVerify} 
            disabled={verifying}
            className={`btn-small flex items-center gap-2 font-black uppercase tracking-widest text-[9px] px-3 py-2 rounded border transition-all ${
                integrity?.is_valid === false 
                ? 'bg-danger/20 border-danger/40 text-danger' 
                : integrity?.is_valid === true
                ? 'bg-ok/20 border-ok/40 text-ok'
                : 'bg-white/5 border-white/10 text-muted'
            }`}
          >
            {verifying ? 'Verifying...' : (
                <>
                    <Fingerprint size={12} />
                    Verify Integrity
                </>
            )}
          </button>
        </div>
      </div>

      {integrity && !integrity.is_valid && (
          <div className="banner error flex items-center gap-3">
              <ShieldAlert size={18} />
              <div>
                <p className="font-bold">Log Integrity Compromised</p>
                <p className="text-xs opacity-80">Tampering detected at IDs: {integrity.compromised_ids.join(', ')}</p>
              </div>
          </div>
      )}

      {integrity?.is_valid && (
          <div className="banner info flex items-center gap-3 bg-ok/10 border-ok/20 text-ok">
              <ShieldCheck size={18} />
              <p className="font-bold">Audit chain integrity verified via HMAC-SHA256.</p>
          </div>
      )}

      <div className="glass-panel overflow-hidden border border-white/5">
        <div className="grid grid-cols-[80px_1fr_120px_140px] gap-4 px-4 py-2 bg-white/5 text-[9px] font-black uppercase tracking-widest text-muted border-b border-white/5">
           <span>ID</span>
           <span>Event / Resource</span>
           <span>User / IP</span>
           <span className="text-right">Timestamp</span>
        </div>
        
        {loading && entries.length === 0 ? (
            <div className="p-12 text-center text-muted animate-pulse">Synchronizing ledger...</div>
        ) : filtered.length === 0 ? (
          <div className="p-12 text-center text-muted">No matching audit entries.</div>
        ) : (
          <div className="max-h-[600px] overflow-auto">
            {filtered.map(entry => (
              <div
                key={entry.id}
                className={`group border-b border-white/5 last:border-0 hover:bg-white/[0.02] transition-colors ${expandedId === entry.id ? 'bg-white/[0.03]' : ''}`}
              >
                <div 
                    className="grid grid-cols-[80px_1fr_120px_140px] gap-4 px-4 py-3 items-center cursor-pointer"
                    onClick={() => setExpandedId(expandedId === entry.id ? null : entry.id)}
                >
                  <span className="font-mono text-[10px] text-muted">#{entry.id}</span>
                  <div className="min-w-0">
                    <p className="font-bold text-xs truncate uppercase tracking-tight">{entry.event}</p>
                    <p className="text-[10px] text-muted truncate font-mono">{entry.resource_id || '—'}</p>
                  </div>
                  <div className="text-[10px] font-mono">
                    <p className="text-text">{entry.user_id || 'SYSTEM'}</p>
                    <p className="text-muted">{entry.source_ip || '::1'}</p>
                  </div>
                  <span className="text-right text-[10px] text-muted font-mono">{new Date(entry.timestamp).toLocaleString()}</span>
                </div>
                
                {expandedId === entry.id && (
                  <div className="px-4 pb-4 pt-1 space-y-3">
                    <div className="bg-black/40 p-3 rounded border border-white/5">
                        <p className="text-[9px] font-black uppercase text-muted mb-2 tracking-widest">Entry Metadata</p>
                        <div className="grid grid-cols-2 gap-4">
                            <div>
                                <p className="text-[9px] text-muted uppercase">Hash Chain Link</p>
                                <code className="text-[10px] font-mono break-all text-accent/80">{entry.entry_hash}</code>
                            </div>
                            <div>
                                <p className="text-[9px] text-muted uppercase">Severity</p>
                                <span className={`text-[10px] font-bold uppercase ${entry.severity === 'critical' || entry.severity === 'error' ? 'text-danger' : entry.severity === 'warning' ? 'text-warn' : 'text-ok'}`}>
                                    {entry.severity}
                                </span>
                            </div>
                        </div>
                    </div>
                    {entry.details && Object.keys(entry.details).length > 0 && (
                        <div className="bg-black/40 p-3 rounded border border-white/5">
                            <p className="text-[9px] font-black uppercase text-muted mb-2 tracking-widest">Raw Payload</p>
                            <pre className="text-[10px] font-mono text-text overflow-x-auto">
                                {JSON.stringify(entry.details, null, 2)}
                            </pre>
                        </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
