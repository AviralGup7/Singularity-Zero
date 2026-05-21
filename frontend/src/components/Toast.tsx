import { useState, useCallback, useEffect, useRef, type ReactNode } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, CheckCircle, AlertTriangle, Info, AlertOctagon } from 'lucide-react';
import { ToastContext } from '@/hooks/useToast';
import type { Toast } from '@/hooks/useToast';

export function ToastProvider({ children }: { children: ReactNode }) {
   
  const [toasts, setToasts] = useState<Toast[]>([]);
  const timeoutsRef = useRef<Map<string, number>>(new Map());

  const removeToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
    if (timeoutsRef.current.has(id)) {
      clearTimeout(timeoutsRef.current.get(id));
      timeoutsRef.current.delete(id);
    }
  }, []);

   
  const addToast = useCallback((type: Toast['type'], message: string, duration = 5000) => {
    const id = Math.random().toString(36).substring(2, 9);
    const newToast: Toast = { id, type, message, duration, createdAt: Date.now() };
   
    setToasts(prev => [newToast, ...prev].slice(0, 5));
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

  return (
    <ToastContext.Provider value={contextValue}>
      {children}
      <div className="fixed top-6 right-6 z-[10000] flex flex-col gap-3 pointer-events-none w-full max-w-sm">
        <AnimatePresence>
          {toasts.map(toast => (
            <motion.div
              key={toast.id}
              initial={{ opacity: 0, x: 50, scale: 0.9 }}
              animate={{ opacity: 1, x: 0, scale: 1 }}
              exit={{ opacity: 0, scale: 0.9, transition: { duration: 0.2 } }}
              className="pointer-events-auto"
            >
              <div
                className="flex items-start gap-4 p-4 rounded-xl border shadow-2xl"
                style={{
                  backdropFilter: 'blur(var(--glass-blur))',
                  background:
                    toast.type === 'success' ? 'color-mix(in srgb, var(--ok) 12%, var(--bg))' :
                    toast.type === 'error' ? 'color-mix(in srgb, var(--bad) 12%, var(--bg))' :
                    toast.type === 'warning' ? 'color-mix(in srgb, var(--warn) 12%, var(--bg))' :
                    'color-mix(in srgb, var(--info) 12%, var(--bg))',
                  borderColor:
                    toast.type === 'success' ? 'color-mix(in srgb, var(--ok) 40%, transparent)' :
                    toast.type === 'error' ? 'color-mix(in srgb, var(--bad) 40%, transparent)' :
                    toast.type === 'warning' ? 'color-mix(in srgb, var(--warn) 40%, transparent)' :
                    'color-mix(in srgb, var(--info) 40%, transparent)',
                }}
              >
                <div className="shrink-0 mt-0.5">
                  {toast.type === 'success' && <CheckCircle size={18} style={{ color: 'var(--ok)' }} />}
                  {toast.type === 'error' && <AlertOctagon size={18} style={{ color: 'var(--bad)' }} />}
                  {toast.type === 'warning' && <AlertTriangle size={18} style={{ color: 'var(--warn)' }} />}
                  {toast.type === 'info' && <Info size={18} style={{ color: 'var(--info)' }} />}
                </div>
                <div className="flex-1" style={{ minWidth: 0 }}>
                  <p style={{ fontSize: '10px', fontWeight: 900, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.2em', marginBottom: '4px', opacity: 0.9 }}>
                    {toast.type === 'success' ? 'Operation Success' :
                     toast.type === 'error' ? 'System Error' :
                     toast.type === 'warning' ? 'Security Warning' : 'System Notice'}
                  </p>
                  <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.625, fontFamily: 'var(--font-mono)' }}>
                    {toast.message}
                  </p>
                  {toast.duration > 0 && (
                    <div style={{ marginTop: '8px', height: '2px', background: 'var(--surface-3)', borderRadius: '999px', overflow: 'hidden' }}>
                      <div style={{
                        height: '100%',
                        borderRadius: '999px',
                        background:
                          toast.type === 'success' ? 'var(--ok)' :
                          toast.type === 'error' ? 'var(--bad)' :
                          toast.type === 'warning' ? 'var(--warn)' : 'var(--info)',
                        animation: `toast-drain ${toast.duration}ms linear forwards`,
                      }} />
                    </div>
                  )}
                </div>
                <button
                  onClick={() => removeToast(toast.id)}
                  style={{ color: 'var(--text-tertiary)' }}
                  className="shrink-0 hover:text-text transition-colors"
                  aria-label="Dismiss notification"
                >
                  <X size={16} />
                </button>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  );
}
