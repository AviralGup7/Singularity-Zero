import { motion, AnimatePresence } from 'framer-motion';
import type { TargetFilters } from '@/hooks/useTargetFilters';

interface TargetsFilterPanelProps {
  filters: TargetFilters;
  toggleSeverity: (sev: string) => void;
  setFilters: (filters: TargetFilters) => void;
}

export function TargetsFilterPanel({ filters, toggleSeverity, setFilters }: TargetsFilterPanelProps) {
  return (
    <div className="card card-padded multi-filter-panel mb-6">
      <div className="multi-filter-grid">
        <div className="filter-group">
          <span className="filter-group-label">Severity</span>
          <div className="filter-checkboxes">
            {SEVERITIES.map((sev) => (
              <label key={sev} className="filter-checkbox-label">
                <input type="checkbox" checked={filters.severities.has(sev)} onChange={() => toggleSeverity(sev)} />
                <span className={`severity-dot severity-${sev}`}>{sev}</span>
              </label>
            ))}
          </div>
        </div>

        <div className="filter-group">
          <span className="filter-group-label">Status</span>
          <div className="filter-radio-group">
            {(['all', 'active', 'inactive'] as const).map((status) => (
              <label key={status} className="filter-radio-label">
                <input
                  type="radio"
                  name="target-status"
                  checked={filters.status === status}
                  onChange={() => setFilters({ ...filters, status })}
                />
                {status.charAt(0).toUpperCase() + status.slice(1)}
              </label>
            ))}
          </div>
        </div>

        <div className="filter-group">
          <span className="filter-group-label">Finding Count</span>
          <div className="filter-range-row">
            <input
              id="filter-min-findings"
              type="number"
              min={0}
              placeholder="Min"
              value={filters.minFindings || ''}
              onChange={(e) => setFilters({ ...filters, minFindings: parseInt(e.target.value, 10) || 0 })}
              className="form-input form-input-sm"
              aria-label="Minimum findings"
            />
            <span className="filter-range-sep">to</span>
            <input
              id="filter-max-findings"
              type="number"
              min={0}
              placeholder="Max"
              value={filters.maxFindings === Infinity ? '' : filters.maxFindings}
              onChange={(e) => setFilters({ ...filters, maxFindings: parseInt(e.target.value, 10) || Infinity })}
              className="form-input form-input-sm"
              aria-label="Maximum findings"
            />
          </div>
        </div>

        <div className="filter-group">
          <span className="filter-group-label">Last Scan Date</span>
          <div className="filter-date-row">
            <input
              type="date"
              value={filters.lastScanAfter}
              onChange={(e) => setFilters({ ...filters, lastScanAfter: e.target.value })}
              className="form-input form-input-sm"
              aria-label="Scan date from"
            />
            <span className="filter-range-sep">to</span>
            <input
              type="date"
              value={filters.lastScanBefore}
              onChange={(e) => setFilters({ ...filters, lastScanBefore: e.target.value })}
              className="form-input form-input-sm"
              aria-label="Scan date to"
            />
          </div>
        </div>
      </div>
    </div>
  );
}
