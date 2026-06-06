import { motion, AnimatePresence } from 'framer-motion';
import { RefreshCw } from 'lucide-react';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;

interface TargetsBulkActionBarProps {
  selectedTargets: Set<string>;
  isScanning: boolean;
  onClearSelection: () => void;
  onBulkRescan: () => void;
}

export function TargetsBulkActionBar({
  selectedTargets,
  isScanning,
  onClearSelection,
  onBulkRescan,
}: TargetsBulkActionBarProps) {
  return (
    <AnimatePresence>
      {selectedTargets.size > 0 && (
        <motion.div
          initial={{ y: -20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          exit={{ y: -20, opacity: 0 }}
          transition={{ duration: 0.25, ease: EASE_OUT }}
        >
          <div className="bulk-action-bar">
            <div className="bulk-action-info">
              <span>
                {selectedTargets.size} target{selectedTargets.size > 1 ? 's' : ''} selected
              </span>
              <button className="btn btn-sm btn-primary flex items-center gap-1.5" onClick={onBulkRescan} disabled={isScanning}>
                {isScanning ? (
                  <span className="animate-spin h-3.5 w-3.5 border-2 border-current border-t-transparent rounded-full" />
                ) : (
                  <RefreshCw size={14} />
                )}
                <span>{isScanning ? 'Scanning...' : 'Re-scan Selected'}</span>
              </button>
              <button className="bulk-clear-btn" onClick={onClearSelection}>
                Clear selection
              </button>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
