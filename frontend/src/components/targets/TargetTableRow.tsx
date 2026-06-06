import { Link } from 'react-router-dom';
import type { Target } from '@/types/api';

interface TargetTableRowProps {
  target: Target;
  selectedTargets: Set<string>;
  toggleTargetSelection: (name: string) => void;
  currentPage: number;
}

export function TargetTableRow({
  target,
  selectedTargets,
  toggleTargetSelection,
  currentPage,
}: TargetTableRowProps) {
  return (
    <tr
      key={target.name || target.href || `target-${currentPage}-${target.name}`}
      className={`transition-all duration-200 hover:-translate-y-0.5 hover:bg-white/5 ${
        selectedTargets.has(target.name || '') ? 'row-selected bg-white/5' : ''
      }`}
    >
      <td className="bulk-select-col">
        <input
          type="checkbox"
          checked={selectedTargets.has(target.name || '')}
          onChange={() => toggleTargetSelection(target.name || '')}
          aria-label={`Select ${target.name || 'unknown'}`}
        />
      </td>
      <td className="target-name-cell">
        <span className="target-name">{target.name || '—'}</span>
        {(target.new_findings || 0) > 0 && <span className="new-badge">+{target.new_findings} new</span>}
      </td>
      <td>{target.latest_run || '—'}</td>
      <td className="findings-cell">
        <span className="findings-count">{target.finding_count ?? '—'}</span>
      </td>
      <td>{target.url_count ?? '—'}</td>
      <td>
        <div className="severity-inline">
          {Object.entries(target.severity_counts || {})
            .filter(([, count]) => count > 0)
            .map(([sev, count]) => (
              <span key={sev} className={`severity-dot severity-${sev}`} aria-label={`${sev}: ${count}`}>
                {sev[0].toUpperCase()}: {count}
              </span>
            ))}
        </div>
      </td>
      <td>{(target.attack_chain_count || 0) > 0 ? `${target.attack_chain_count} (${target.max_attack_chain_confidence || '—'})` : '—'}</td>
      <td>{target.validated_leads ?? '—'}</td>
      <td className="actions-cell">
        {target.name && (
          <div className="flex gap-2">
            <Link to={`/cockpit?target=${target.name}`} className="btn btn-small btn-accent-outline" title="View 3D Threat Graph">
              Cockpit
            </Link>
            <button
              type="button"
              className="btn btn-small btn-secondary"
              title="Download SOC 2 / PCI-DSS Attestation"
              onClick={async () => {
                try {
                  const token = sessionStorage.getItem('auth_token');
                  const headers: Record<string, string> = {};
                  if (token) {
                    headers['Authorization'] = `Bearer ${token}`;
                  }
                  const response = await fetch(`/api/reports/compliance/pdf?target=${encodeURIComponent(target.name!)}`, { headers });
                  if (!response.ok) {
                    throw new Error('Compliance download failed');
                  }
                  const blob = await response.blob();
                  const url = window.URL.createObjectURL(blob);
                  const link = document.createElement('a');
                  link.href = url;
                  link.download = `${target.name}-compliance.pdf`;
                  link.click();
                  window.URL.revokeObjectURL(url);
                } catch (err) {
                  console.error('Failed to download compliance report:', err);
                }
              }}
            >
              Compliance
            </button>
            <button
              className="btn btn-small btn-secondary"
              title="Export CSV Findings"
              onClick={async () => {
                try {
                  const { exportTargetFindings } = await import('@/api/client');
                  const blob = await exportTargetFindings(target.name!, 'csv');
                  const url = window.URL.createObjectURL(blob);
                  const link = document.createElement('a');
                  link.href = url;
                  link.download = `${target.name}-findings.csv`;
                  link.click();
                  window.URL.revokeObjectURL(url);
                } catch (_err) {
                  console.error('Export failed');
                }
              }}
            >
              Export
            </button>
          </div>
        )}
        {target.href && (
          <a href={target.href} className="btn btn-small" target="_blank" rel="noopener noreferrer">
            Runs
          </a>
        )}
        {target.latest_report_href && (
          <a href={target.latest_report_href} className="btn btn-small" target="_blank" rel="noopener noreferrer">
            Report
          </a>
        )}
      </td>
    </tr>
  );
}
