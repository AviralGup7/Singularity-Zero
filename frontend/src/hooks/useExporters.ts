import { useCallback, useState } from 'react';
import type { Finding } from '@/types/api';
import { EXPORTERS, type ExporterFormat, type ExporterContext } from '@/utils/exporters';
import { useToast } from '@/hooks/useToast';

interface UseExportersOptions {
  findings: Finding[];
  filenameBase?: string;
  context?: ExporterContext['context'];
}

export function useExporters({ findings, filenameBase = 'findings', context }: UseExportersOptions) {
  const toast = useToast();
  const [pendingFormat, setPendingFormat] = useState<ExporterFormat | null>(null);
  const [confirming, setConfirming] = useState<ExporterFormat | null>(null);

  const download = useCallback((blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, []);

  const containsPII = useCallback(() => {
    if (findings.length === 0) return false;
    return findings.some((f) => f.metadata && Object.keys(f.metadata).some((k) =>
      ['email', 'phone', 'ssn', 'password', 'token', 'api_key', 'secret', 'ip_address', 'username'].some((pii) => k.toLowerCase().includes(pii))
    ));
  }, [findings]);

  const performExport = useCallback((format: ExporterFormat, includePII: boolean) => {
    // `format` is constrained to the `ExporterFormat` union; safe lookup.
    // eslint-disable-next-line security/detect-object-injection
    const exporter = EXPORTERS[format];
    if (!exporter) {
      toast.error(`Unknown export format: ${format}`);
      return;
    }
    try {
      const artifact = exporter.export({
        findings,
        filename: filenameBase,
        includePII,
        context,
      });
      download(artifact.blob, artifact.filename);
      toast.success(`Exported ${findings.length} findings as ${exporter.label}`);
    } catch (err) {
      console.error('[export] failed', err);
      toast.error('Export failed');
    } finally {
      setPendingFormat(null);
      setConfirming(null);
    }
  }, [findings, filenameBase, context, download, toast]);

  const runExport = useCallback((format: ExporterFormat) => {
    setPendingFormat(format);
    if (containsPII()) {
      setConfirming(format);
      return;
    }
    performExport(format, false);
  }, [containsPII, performExport]);

  const confirmWithPII = useCallback(() => {
    if (confirming) performExport(confirming, true);
  }, [confirming, performExport]);

  const cancelPII = useCallback(() => {
    if (pendingFormat) performExport(pendingFormat, false);
    else {
      setPendingFormat(null);
      setConfirming(null);
    }
  }, [pendingFormat, performExport]);

  return {
    formats: Object.entries(EXPORTERS).map(([key, value]) => ({ key: key as ExporterFormat, ...value })),
    runExport,
    pendingFormat,
    confirming,
    confirmWithPII,
    cancelPII,
  };
}
