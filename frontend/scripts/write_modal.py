p = r'D:\cyber security test pipeline - Copy\frontend\src\components\targets\ImportModal.tsx'
content = '''import { motion, AnimatePresence } from 'framer-motion';
import { X, Upload } from 'lucide-react';

interface ImportModalProps {
  showImportModal: boolean;
  importFile: File | null;
  importTargetName: string;
  setImportTargetName: (name: string) => void;
  onClose: () => void;
  onConfirm: () => void;
  isImporting: boolean;
}

export function ImportModal({
  showImportModal,
  importFile,
  importTargetName,
  setImportTargetName,
  onClose,
  onConfirm,
  isImporting,
}: ImportModalProps) {
  return (
    <AnimatePresence>
      {showImportModal ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => {
              if (!isImporting) {
                onClose();
              }
            }}
            className="absolute inset-0 bg-black/60 backdrop-blur-sm"
          />
          <motion.div
            initial={{ scale: 0.95, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.95, opacity: 0 }}
            transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
            className="relative w-full max-w-md overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--surface)] p-6 shadow-2xl"
            style={{ backdropFilter: 'blur(20px)' }}
          >
            <button
              type="button"
              onClick={onClose}
              disabled={isImporting}
              className="absolute top-4 right-4 text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
            >
              <X size={18} />
            </button>
            <div className="flex items-center gap-3 mb-4">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-[var(--accent-soft)] text-[var(--accent)]">
                <Upload size={20} />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-[var(--text-primary)]">Import Semgrep Results</h3>
                <p className="text-xs text-[var(--text-secondary)]">Upload scan results JSON to create/update target</p>
              </div>
            </div>
            <div className="space-y-4">
              {importFile && (
                <div className="p-3 rounded-lg bg-[var(--surface-2)] border border-[var(--border)] text-xs text-[var(--text-secondary)]">
                  <span className="font-semibold block text-[var(--text-primary)] mb-1">Selected File:</span>
                  <span className="truncate block font-mono">{importFile.name}</span>
                  <span className="text-[10px] text-[var(--text-tertiary)]">({(importFile.size / 1024).toFixed(1)} KB)</span>
                </div>
              )}
              <div className="space-y-1.5">
                <label htmlFor="import-target-name" className="text-xs font-semibold text-[var(--text-secondary)]">Target Name</label>
                <input
                  id="import-target-name"
                  type="text"
                  placeholder="e.g. example.com"
                  value={importTargetName}
                  onChange={(e) => setImportTargetName(e.target.value)}
                  className="w-full bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] focus:border-[var(--accent)] focus:shadow-[0_0_0_2px_var(--accent-soft)] transition-all duration-200"
                  disabled={isImporting}
                />
              </div>
              <div className="flex items-center justify-end gap-2 pt-2">
                <button type="button" onClick={onClose} disabled={isImporting} className="btn btn-sm btn-secondary">Cancel</button>
                <button
                  type="button"
                  onClick={onConfirm}
                  disabled={isImporting || !importTargetName.trim()}
                  className="btn btn-sm btn-primary flex items-center gap-1.5"
                >
                  {isImporting ? (
                    <span className="animate-spin h-3.5 w-3.5 border-2 border-current border-t-transparent rounded-full" />
                  ) : (
                    <Upload size={14} />
                  )}
                  <span>{isImporting ? 'Importing...' : 'Import'}</span>
                </button>
              </div>
            </div>
          </motion.div>
        </div>
      ) : null}
    </AnimatePresence>
  );
}
'''
with open(p, 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)
import os
os.utime(p, None)
print('Wrote', len(content), 'bytes')
