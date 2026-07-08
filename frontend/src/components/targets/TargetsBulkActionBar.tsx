import { RefreshCw } from 'lucide-react';
import { BulkActionBar } from '@/components/common/BulkActionBar';

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
    <BulkActionBar
      selectedItems={Array.from(selectedTargets).map(id => ({ id }))}
      onClearSelection={onClearSelection}
      label="targets selected"
      actions={[
        {
          label: isScanning ? 'Scanning...' : 'Re-scan Selected',
          icon: isScanning ? (
            <span className="animate-spin h-3.5 w-3.5 border-2 border-current border-t-transparent rounded-full" />
          ) : (
            <RefreshCw size={14} />
          ),
          onClick: () => onBulkRescan(),
          variant: 'default',
        },
      ]}
    />
  );
}
