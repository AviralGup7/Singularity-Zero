import { useEffect, useMemo, useState } from 'react';
import { ExternalLink, FileText, ShieldCheck, Download, RefreshCw } from 'lucide-react';

import { getReportLibrary, type ReportLibraryItem } from '@/api/reports';
import { ApiError } from '@/api/core';

function shortHash(value: string): string {
  if (!value) return 'pending';
  return value.length > 16 ? `${value.slice(0, 12)}...${value.slice(-6)}` : value;
}

function formatGeneratedAt(value: string): string {
  if (!value) return 'unknown';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

export function ReportLibraryPage() {
  const [reports, setReports] = useState<ReportLibraryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadReports = async (signal?: AbortSignal) => {
    setLoading(true);
    setError('');
    try {
      const response = await getReportLibrary(signal);
      setReports(response.reports);
    } catch (err) {
      if (err instanceof DOMException && err.name === 'AbortError') return;
      setError(err instanceof ApiError ? err.message : 'Unable to load report library');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const controller = new AbortController();
    void loadReports(controller.signal);
    return () => controller.abort();
  }, []);

  const stats = useMemo(() => {
    const signed = reports.filter(report => report.signature_valid).length;
    const targets = new Set(reports.map(report => report.target)).size;
    return { signed, targets };
  }, [reports]);

  return (
    <div className="space-y-20">
      <section>
        <div className="flex flex-wrap items-center justify-between gap-12">
          <div>
            <p className="text-[11px] uppercase text-muted">Report library</p>
            <h2 className="mt-1 text-xl font-semibold">Signed compliance artefacts</h2>
          </div>
          <button type="button" className="btn btn-secondary btn-sm" onClick={() => void loadReports()}>
            <RefreshCw size={14} aria-hidden="true" />
            Refresh
          </button>
        </div>

        <div className="mt-16 grid gap-12 md:grid-cols-3">
          <div className="card">
            <span className="metric-label">Reports</span>
            <strong className="metric-value">{reports.length}</strong>
          </div>
          <div className="card">
            <span className="metric-label">Valid signatures</span>
            <strong className="metric-value">{stats.signed}</strong>
          </div>
          <div className="card">
            <span className="metric-label">Targets</span>
            <strong className="metric-value">{stats.targets}</strong>
          </div>
        </div>
      </section>

      {error && <div className="banner error" role="alert">{error}</div>}

      <section>
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Target</th>
                <th>Run</th>
                <th>Generated</th>
                <th>Signature</th>
                <th>Manifest</th>
                <th>Artefacts</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr>
                  <td colSpan={6}>Loading report artefacts...</td>
                </tr>
              )}
              {!loading && reports.length === 0 && (
                <tr>
                  <td colSpan={6}>No signed reports have been generated yet.</td>
                </tr>
              )}
              {!loading && reports.map(report => (
                <tr key={`${report.target}-${report.run_id}`}>
                  <td>
                    <div className="font-medium">{report.target}</div>
                    <div className="text-xs text-muted">{report.finding_count} reportable findings</div>
                  </td>
                  <td>
                    <code>{report.run_id}</code>
                    <div className="text-xs text-muted">{report.version}</div>
                  </td>
                  <td>{formatGeneratedAt(report.generated_at)}</td>
                  <td>
                    <span className={`status-badge ${report.signature_valid ? 'status-completed' : 'status-stopped'}`}>
                      <ShieldCheck size={12} aria-hidden="true" />
                      {report.signature_valid ? 'Verified' : 'Review'}
                    </span>
                  </td>
                  <td><code title={report.manifest_sha256}>{shortHash(report.manifest_sha256)}</code></td>
                  <td>
                    <div className="flex flex-wrap gap-8">
                      <a className="btn btn-small" href={report.links.html} target="_blank" rel="noopener noreferrer">
                        <ExternalLink size={13} aria-hidden="true" />
                        HTML
                      </a>
                      <a className="btn btn-small" href={report.links.attestation_pdf} download>
                        <FileText size={13} aria-hidden="true" />
                        PDF
                      </a>
                      <a className="btn btn-small" href={report.links.sbom} download>
                        <Download size={13} aria-hidden="true" />
                        SBOM
                      </a>
                      <a className="btn btn-small" href={report.links.manifest} download>
                        <Download size={13} aria-hidden="true" />
                        Manifest
                      </a>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
