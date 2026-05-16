import { useCallback, useEffect, useRef } from 'react';
import { cn } from '@/lib/utils';

export type ConfirmDialogVariant = 'danger' | 'warning' | 'info';

export interface ConfirmDialogProps {
  isOpen: boolean;
  title: string;
  message: string;
  confirmText?: string;
  cancelText?: string;
  onConfirm: () => void;
  onCancel: () => void;
  variant?: ConfirmDialogVariant;
  className?: string;
}

const variantConfig: Record<ConfirmDialogVariant, { confirmClass: string; icon: string }> = {
   
  danger: { confirmClass: 'bg-[var(--bad)] text-white border-[var(--bad)] hover:opacity-90', icon: '⚠️' },
   
  warning: { confirmClass: 'bg-[var(--warn)] text-[var(--bg)] border-[var(--warn)] hover:opacity-90', icon: '⚡' },
   
  info: { confirmClass: 'bg-[var(--accent)] text-[var(--bg)] border-[var(--accent)] hover:opacity-90', icon: 'ℹ️' },
};

export function ConfirmDialog({
  isOpen,
  title,
  message,
  confirmText = 'Confirm',
  cancelText = 'Cancel',
  onConfirm,
  onCancel,
  variant = 'danger',
  className,
}: ConfirmDialogProps) {
  const triggerRef = useRef<HTMLElement | null>(null);
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const confirmButtonRef = useRef<HTMLButtonElement | null>(null);

  const handleCancel = useCallback(() => {
    onCancel();
   
  }, [onCancel]);

  const handleConfirm = useCallback(() => {
    onConfirm();
   
  }, [onConfirm]);

  useEffect(() => {
    if (isOpen) {
      triggerRef.current = document.activeElement as HTMLElement;
      setTimeout(() => confirmButtonRef.current?.focus(), 0);
      document.body.style.overflow = 'hidden';
    } else if (triggerRef.current) {
      triggerRef.current.focus();
      triggerRef.current = null;
      document.body.style.overflow = '';
    }

    return () => {
      document.body.style.overflow = '';
    };
   
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        handleCancel();
        return;
      }

      if (e.key === 'Tab') {
        const dialog = dialogRef.current;
        if (!dialog) return;

        const focusable = dialog.querySelectorAll<HTMLElement>(
   
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );
   
        const first = focusable[0];
   
        const last = focusable[focusable.length - 1];

        if (e.shiftKey) {
          if (document.activeElement === first) {
            e.preventDefault();
            last.focus();
          }
        } else {
          if (document.activeElement === last) {
            e.preventDefault();
            first.focus();
          }
        }
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
   
  }, [isOpen, handleCancel]);

  if (!isOpen) return null;

  const config = variantConfig[variant];

  return (
    <div
   
      className="fixed inset-0 z-50 flex items-center justify-center bg-[var(--modal-overlay)] p-4"
      onClick={(e) => {
        if (e.target === e.currentTarget) handleCancel();
      }}
    >
      <div
        ref={dialogRef}
        className={cn(
   
          'relative w-full max-w-sm bg-[var(--panel)] border border-[var(--line)] p-6 shadow-[var(--shadow)]',
   
          "[clip-path:polygon(0_0,calc(100%_-_8px)_0,100%_8px,100%_100%,8px_100%,0_calc(100%_-_8px))]",
          className
        )}
        onClick={(e) => e.stopPropagation()}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
        aria-describedby="confirm-dialog-description"
      >
        <h3 id="confirm-dialog-title" className="font-mono text-[length:var(--text-lg)] font-bold text-[var(--text)] mb-2">
          <span className="mr-2" aria-hidden="true">{config.icon}</span>
          {title}
        </h3>
        <p id="confirm-dialog-description" className="text-[var(--muted)] text-[length:var(--text-sm)] mb-4">
          {message}
        </p>
        <div className="flex items-center justify-end gap-2">
          <button
   
            className="px-3 py-1.5 bg-transparent border border-[var(--line)] text-[var(--text)] font-mono text-[length:var(--text-sm)] uppercase tracking-wider hover:bg-[var(--hover-bg)] transition-colors focus:outline-none focus:ring-2 focus:ring-[var(--accent)]"
            onClick={handleCancel}
          >
            {cancelText}
          </button>
          <button
            ref={confirmButtonRef}
            className={cn(
   
              'px-3 py-1.5 border font-mono text-[length:var(--text-sm)] uppercase tracking-wider transition-colors focus:outline-none focus:ring-2 focus:ring-[var(--accent)]',
              config.confirmClass
            )}
            onClick={handleConfirm}
          >
            {confirmText}
          </button>
        </div>
      </div>
    </div>
  );
}
