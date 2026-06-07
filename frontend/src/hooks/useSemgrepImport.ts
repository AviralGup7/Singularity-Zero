import { useState, useCallback } from 'react';
import { importSemgrepReport } from '@/api/imports';

export function useSemgrepImport() {
  const [showImportModal, setShowImportModal] = useState(false);
  const [importTargetName, setImportTargetName] = useState('');
  const [importFile, setImportFile] = useState<File | null>(null);
  const [isImporting, setIsImporting] = useState(false);

  const handleFileChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setImportFile(file);
    const defaultName = file.name.replace(/\.[^/.]+$/, '');
    setImportTargetName(defaultName);
    setShowImportModal(true);
    e.target.value = '';
  }, []);

  const executeImport = useCallback(
    async (onSuccess: () => void) => {
      if (!importFile || !importTargetName.trim()) return;
      setIsImporting(true);
      const formData = new FormData();
      formData.append('file', importFile);

      try {
        await importSemgrepReport({
          targetName: importTargetName,
          file: importFile,
        });
        onSuccess();
        setShowImportModal(false);
        setImportFile(null);
        setImportTargetName('');
      } catch (err) {
        console.error('Import failed:', err);
      } finally {
        setIsImporting(false);
      }
    },
    [importFile, importTargetName]
  );

  const resetImport = useCallback(() => {
    setShowImportModal(false);
    setImportFile(null);
    setImportTargetName('');
  }, []);

  return {
    showImportModal,
    importTargetName,
    setImportTargetName,
    importFile,
    setImportFile,
    isImporting,
    setIsImporting,
    handleFileChange,
    executeImport,
    resetImport,
  };
}
