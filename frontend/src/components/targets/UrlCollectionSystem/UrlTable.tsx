import {  statusTone, statusLabel } from './helpers';
import type {UrlCollectionItem} from './helpers';

interface UrlTableProps {
  items: UrlCollectionItem[];
  selectedIds: Set<string>;
  allSelected: boolean;
  onToggleSelect: (id: string) => void;
  onToggleSelectAll: () => void;
}

export function UrlTable({ items, selectedIds, allSelected, onToggleSelect, onToggleSelectAll }: UrlTableProps) {
  return (
    <div className="url-collection-table-wrap">
      <table className="url-collection-table">
        <thead>
          <tr>
            <th>
              <input type="checkbox" checked={allSelected} onChange={onToggleSelectAll} aria-label="Select all filtered URLs" />
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
          {items.length === 0 ? (
            <tr>
              <td colSpan={9} className="url-collection-empty">No URLs in the collection.</td>
            </tr>
          ) : (
            items.map(item => (
              <tr key={item.id} className={selectedIds.has(item.id) ? 'row-selected' : ''}>
                <td>
                  <input type="checkbox" checked={selectedIds.has(item.id)} onChange={() => onToggleSelect(item.id)} aria-label={`Select ${item.url}`} />
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
                <td>{item.processingProfile || '\u2014'}</td>
                <td>{item.lastJobId || '\u2014'}</td>
                <td>{item.processedAt ? new Date(item.processedAt).toLocaleString() : '\u2014'}</td>
                <td>{new Date(item.addedAt).toLocaleString()}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
