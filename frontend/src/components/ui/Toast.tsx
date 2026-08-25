import { useState, useCallback, useEffect, useRef  } from 'react';
import type {ReactNode} from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, CheckCircle, AlertTriangle, Info, AlertOctagon, ChevronDown } from 'lucide-react';
import { ToastContext } from '@/hooks/useToast';
import type { Toast } from '@/hooks/useToast';

const MAX_VISIBLE_TOASTS = 3;

export function ToastProvider({ children }: { children: ReactNode }) {
    
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [showAll, setShowAll] = useState(false);
  const timeoutsRef = useRef<Map<string, number>>(new Map());

  const removeToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
    if (timeoutsRef.current.has(id)) {
      clearTimeout(timeoutsRef.current.get(id));
      timeoutsRef.current.delete(id);
    }
  }, []);

    
  const addToast = useCallback((type: Toast['type'], message: string, duration = 5000) => {
    const id = crypto.randomUUID();
    const newToast: Toast = { id, type, message, duration, createdAt: Date.now() };
    
    setToasts(prev => [newToast, ...prev].slice(0, 20));
    if (duration > 0) {
      const timer = window.setTimeout(() => removeToast(id), duration);
      timeoutsRef.current.set(id, timer);
    }
    
  }, [removeToast]);

  const contextValue = {
    success: (msg: string) => addToast('success', msg),
    error: (msg: string) => addToast('error', msg, 10000),
    warn: (msg: string) => addToast('warning', msg),
    warning: (msg: string) => addToast('warning', msg),
    info: (msg: string) => addToast('info', msg),
  };

  useEffect(() => {
    import('@/lib/toastDispatcher').then(m => {
      m.setToastDispatcher((message, type) => {
        addToast(type, message, type === 'error' ? 10000 : 5000);
      });
    });
    
  }, [addToast]);

  const visibleToasts = showAll ? toasts : toasts.slice(0, MAX_VISIBLE_TOASTS);
  const overflowCount = toasts.length - MAX_VISIBLE_TOASTS;

  return (
    <ToastContext.Provider value={contextValue}>
      {children}
      <div className="fixed top-4 right-4 z-[10000] flex flex-col gap-2.5 pointer-events-none w-full max-w-sm"
        style={{ perspective: '800px' }}
      >
        <AnimatePresence>
          {visibleToasts.map((toast, index) => (
            <motion.div
              key={toast.id}
              layout
              initial={{ opacity: 0, x: 60, y: -20, rotateX: -8, scale: 0.92 }}
              animate={{ opacity: 1, x: 0, y: 0, rotateX: 0, scale: 1 }}
              exit={{ opacity: 0, x: 60, scale: 0.92, transition: { duration: 0.18 } }}
              transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
              className="pointer-events-auto"
              style={{ zIndex: 10000 - index }}
            >
              <div
                className="flex items-start gap-3.5 p-4 rounded-xl border shadow-2xl overflow-hidden relative"
                style={{
                  backdropFilter: 'blur(16px)',
                  WebkitBackdropFilter: 'blur(16px)',
                  background:
                    toast.type === 'success' ? 'color-mix(in srgb, var(--ok) 10%, var(--surface))' :
                    toast.type === 'error' ? 'color-mix(in srgb, var(--bad) 10%, var(--surface))' :
                    toast.type === 'warning' ? 'color-mix(in srgb, var(--warn) 10%, var(--surface))' :
                    'color-mix(in srgb, var(--info) 10%, var(--surface))',
                  borderColor:
                    toast.type === 'success' ? 'color-mix(in srgb, var(--ok) 35%, transparent)' :
                    toast.type === 'error' ? 'color-mix(in srgb, var(--bad) 35%, transparent)' :
                    toast.type === 'warning' ? 'color-mix(in srgb, var(--warn) 35%, transparent)' :
                    'color-mix(in srgb, var(--info) 35%, transparent)',
                }}
              >
                <div className="shrink-0 mt-0.5 h-8 w-8 rounded-lg flex items-center justify-center"
                  style={{
                    background: toast.type === 'success' ? 'color-mix(in srgb, var(--ok) 15%, transparent)' :
                      toast.type === 'error' ? 'color-mix(in srgb, var(--bad) 15%, transparent)' :
                      toast.type === 'warning' ? 'color-mix(in srgb, var(--warn) 15%, transparent)' :
                      'color-mix(in srgb, var(--info) 15%, transparent)',
                  }}
                >
                  {toast.type === 'success' && <CheckCircle size={16} className="text-ok" />}
                  {toast.type === 'error' && <AlertOctagon size={16} className="text-bad" />}
                  {toast.type === 'warning' && <AlertTriangle size={16} className="text-warn" />}
                  {toast.type === 'info' && <Info size={16} className="text-info" />}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-[10px] font-bold uppercase tracking-[0.15em] text-text-primary/80 mb-0.5">
                    {toast.type === 'success' ? 'Success' :
                     toast.type === 'error' ? 'Error' :
                     toast.type === 'warning' ? 'Warning' : 'Notice'}
                  </p>
                  <p className="text-xs text-text-secondary leading-relaxed">
                    {toast.message}
                  </p>
                  {toast.duration !== undefined && toast.duration > 0 && (
                    <div className="mt-2.5 h-1 rounded-full overflow-hidden bg-line/50">
                      <div className="h-full rounded-full"
                        style={{
                          background: toast.type === 'success' ? 'var(--ok)' :
                            toast.type === 'error' ? 'var(--bad)' :
                            toast.type === 'warning' ? 'var(--warn)' : 'var(--info)',
                          animation: `toast-drain ${toast.duration ?? 0}ms linear forwards`,
                        }}
                      />
                    </div>
                  )}
                </div>
                <button
                  onClick={() => removeToast(toast.id)}
                  className="shrink-0 h-6 w-6 rounded-md flex items-center justify-center text-text-tertiary hover:bg-surface-hover hover:text-text-primary transition-all duration-150"
                  aria-label="Dismiss notification"
                >
                  <X size={14} />
                </button>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
        {overflowCount > 0 && !showAll && (
          <button
            onClick={() => setShowAll(true)}
            className="pointer-events-auto flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg text-xs font-medium text-text-secondary bg-surface/80 border border-line backdrop-blur-md hover:text-text-primary transition-all"
          >
            <ChevronDown size={14} />
            View {overflowCount} more
          </button>
        )}
        {showAll && toasts.length > MAX_VISIBLE_TOASTS && (
          <button
            onClick={() => setShowAll(false)}
            className="pointer-events-auto flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg text-xs font-medium text-text-secondary bg-surface/80 border border-line backdrop-blur-md hover:text-text-primary transition-all"
          >
            Show less
          </button>
        )}
      </div>
    </ToastContext.Provider>
  );
}
