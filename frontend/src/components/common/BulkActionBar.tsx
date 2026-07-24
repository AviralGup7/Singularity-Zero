import { useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X } from 'lucide-react';
import { Button } from '@/components/ui-shadcn/button';

export interface BulkAction<T> {
  label: string;
  icon?: React.ReactNode;
  variant?: 'default' | 'destructive' | 'outline' | 'secondary' | 'ghost';
  onClick: (selectedItems: T[]) => void;
}

export interface BulkActionBarProps<T> {
  selectedItems: T[];
  onClearSelection: () => void;
  actions: BulkAction<T>[];
  label?: string;
}

export function BulkActionBar<T extends { id?: string }>({
  selectedItems,
  onClearSelection,
  actions,
  label,
}: BulkActionBarProps<T>) {
  useEffect(() => {
    if (selectedItems.length === 0) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClearSelection();
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [selectedItems.length, onClearSelection]);

  return (
    <AnimatePresence>
      {selectedItems.length > 0 && (
        <motion.div
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          exit={{ y: 20, opacity: 0 }}
          transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
          className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 flex items-center gap-4 bg-background/95 backdrop-blur-md px-6 py-3 rounded-full border shadow-2xl"
          role="toolbar"
          aria-label={`Bulk actions: ${selectedItems.length} ${label ?? 'items'} selected`}
          aria-live="polite"
        >
          <span className="text-sm font-semibold text-foreground border-r pr-4 tabular-nums">
            {selectedItems.length} {label ?? 'selected'}
          </span>
          <div className="flex items-center gap-2" role="group" aria-label="Available actions">
            {actions.map((action, idx) => (
              <Button
                key={idx}
                size="sm"
                variant={action.variant ?? 'secondary'}
                onClick={() => action.onClick(selectedItems)}
                className="flex items-center gap-1.5"
                aria-label={action.label}
              >
                {action.icon}
                {action.label}
              </Button>
            ))}
          </div>
          <button
            onClick={onClearSelection}
            className="p-1 hover:bg-muted rounded-full transition-colors text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            title="Clear selection (Esc)"
            aria-label="Clear selection"
          >
            <X className="w-4 h-4" aria-hidden="true" />
          </button>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
