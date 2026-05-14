import { useState, useCallback } from 'react';

interface ExportOptions {
  format: 'csv' | 'json';
  data: Record<string, unknown>[];
  filename: string;
  includePII?: boolean;
}

function hasPII(data: Record<string, unknown>[]): boolean {
  const piiKeys = ['email', 'phone', 'ssn', 'password', 'token', 'api_key', 'secret', 'ip_address', 'username'];
  if (data.length === 0) return false;
  const keys = Object.keys(data[0]).map((k) => k.toLowerCase());
  return piiKeys.some((pii) => keys.some((k) => k.includes(pii)));
}

function stripPII(data: Record<string, unknown>[]): Record<string, unknown>[] {
  // Include 'username' to match hasPII detection (consistency fix)
  const piiKeys = ['email', 'phone', 'ssn', 'password', 'token', 'api_key', 'secret', 'ip_address', 'username'];
  return data.map((row) => {
    const cleaned: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(row)) {
      if (piiKeys.some((pii) => key.toLowerCase().includes(pii))) {
        cleaned[key] = '[REDACTED]';
      } else {
        cleaned[key] = value;
      }
    }
    return cleaned;
  });
}

function exportToCSV(data: Record<string, unknown>[], filename: string): void {
  if (data.length === 0) return;
  // Collect all unique keys across all rows, not just the first
  const headers = [...new Set(data.flatMap(Object.keys))];
  const csvContent = [
    headers.join(','),
    ...data.map((row) =>
      headers.map((h) => {
        const val = row[h];
        const str = val === null || val === undefined ? '' : String(val);
        return str.includes(',') || str.includes('"') || str.includes('\n')
          ? `"${str.replace(/"/g, '""')}"`
          : str;
      }).join(',')
    ),
  ].join('\n');

  downloadFile(csvContent, `${filename}.csv`, 'text/csv');
}

function exportToJSON(data: Record<string, unknown>[], filename: string): void {
  const jsonContent = JSON.stringify(data, null, 2);
  downloadFile(jsonContent, `${filename}.json`, 'application/json');
}

function downloadFile(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function useExport(filename: string, data: Record<string, unknown>[]) {
  const [showPIIWarning, setShowPIIWarning] = useState(false);
  const [pendingFormat, setPendingFormat] = useState<ExportOptions['format'] | null>(null);

  const containsPII = hasPII(data);

  const doExport = useCallback(
    (format: ExportOptions['format'], includePII = false) => {
      const exportData = includePII ? data : stripPII(data);
      switch (format) {
        case 'csv':
          exportToCSV(exportData, filename);
          break;
        case 'json':
          exportToJSON(exportData, filename);
          break;
      }
    },
    [data, filename]
  );

  const handleExport = useCallback(
    (format: ExportOptions['format']) => {
      if (containsPII) {
        setPendingFormat(format);
        setShowPIIWarning(true);
      } else {
        doExport(format, false);
      }
    },
    [containsPII, doExport]
  );

  const confirmWithPII = useCallback(() => {
    if (pendingFormat) {
      doExport(pendingFormat, true);
    }
    setShowPIIWarning(false);
    setPendingFormat(null);
  }, [pendingFormat, doExport]);

  const cancelExport = useCallback(() => {
    if (pendingFormat) {
      doExport(pendingFormat, false);
    }
    setShowPIIWarning(false);
    setPendingFormat(null);
  }, [pendingFormat, doExport]);

  return {
    handleExport,
    showPIIWarning,
    confirmWithPII,
    cancelExport,
    containsPII,
  };
}
