import { apiClient } from './core';

export interface SemgrepImportOptions {
  targetName: string;
  file: File;
  signal?: AbortSignal;
}

/**
 * Uploads a Semgrep JSON report and creates a target from its findings.
 * Multipart upload; the backend dedupes on file hash.
 */
export async function importSemgrepReport({ targetName, file, signal }: SemgrepImportOptions): Promise<void> {
  const formData = new FormData();
  formData.append('file', file);
  await apiClient.post(
    `/api/imports/semgrep?target_name=${encodeURIComponent(targetName.trim())}`,
    formData,
    {
      signal,
      headers: { 'Content-Type': 'multipart/form-data' },
    }
  );
}
