import { useState } from 'react';
import { getComplianceLogs, exportComplianceReport, type ComplianceLogEntry } from '@/utils/complianceLogger';
import { Button } from '@/components/ui/Button';

export function ComplianceLogViewer() {
   
  const [logs] = useState<ComplianceLogEntry[]>(() => getComplianceLogs());
   
  const [filter, setFilter] = useState<'all' | 'success' | 'failure' | 'denied'>('all');

  const filteredLogs = filter === 'all' ? logs : logs.filter((l) => l.outcome === filter);

  const handleExport = (format: 'json' | 'csv') => {
    const data = exportComplianceReport(format);
   
    const blob = new Blob([data], { type: format === 'csv' ? 'text/csv' : 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `compliance-report.${format}`;
    a.click();
    URL.revokeObjectURL(url);
  };



  return (
    <div className="compliance-log-viewer">
      <div className="flex items-center justify-between mb-3">
  // eslint-disable-next-line security/detect-object-injection
        <h3 className="font-mono text-[var(--accent)] text-sm font-bold uppercase tracking-wider">
          Compliance Log ({filteredLogs.length})
        </h3>
        <div className="flex gap-1">
          <Button variant="ghost" onClick={() => handleExport('json')} className="text-xs">
            Export JSON
          </Button>
          <Button variant="ghost" onClick={() => handleExport('csv')} className="text-xs">
            Export CSV
          </Button>
        </div>
      </div>

      <div className="flex gap-2 mb-3">
  // eslint-disable-next-line security/detect-object-injection
        {(['all', 'success', 'failure', 'denied'] as const).map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-2 py-0.5 text-xs font-mono border transition-colors ${
              filter === f
   
                ? 'border-[var(--accent)] text-[var(--accent)] bg-[var(--accent)]/10'
   
                : 'border-[var(--line)] text-[var(--muted)] hover:text-[var(--text)]'
            }`}
          >
            {f.charAt(0).toUpperCase() + f.slice(1)}
          </button>
        ))}
      </div>

      <div className="max-h-96 overflow-y-auto space-y-2 pr-2 scrollbar-cyber">
        {filteredLogs.length === 0 ? (
          <p className="text-muted text-xs italic">No compliance entries.</p>
        ) : (
          filteredLogs.map((entry) => (
            <div key={entry.id} className="p-3 bg-white/5 border border-white/10 rounded-lg flex flex-col md:flex-row md:items-center justify-between gap-2">
              <div className="flex items-start gap-3">
  // eslint-disable-next-line security/detect-object-injection
                <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider ${
                  entry.outcome === 'success' ? 'bg-green-500/20 text-green-400' :
                  entry.outcome === 'denied' ? 'bg-red-500/20 text-red-400' : 'bg-yellow-500/20 text-yellow-400'
                }`}>
                  {entry.outcome}
                </span>
                <div>
                  <div className="text-text text-xs">
                    <span className="font-bold">{entry.action}</span>
                    {' '}on{' '}
                    <span className="text-accent">{entry.resource}</span>
                  </div>
  // eslint-disable-next-line security/detect-object-injection
                  <div className="text-muted text-[10px] mt-1">
                    {entry.reason} — by <span className="text-text/60 font-mono">{entry.user}</span>
                  </div>
                </div>
              </div>
  // eslint-disable-next-line security/detect-object-injection
              <span className="text-muted text-[9px] font-mono whitespace-nowrap">
                {new Date(entry.timestamp).toLocaleString()}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
