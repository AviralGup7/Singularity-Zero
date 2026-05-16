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
  // eslint-disable-next-line security/detect-object-injection
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
              <div className={`
                flex items-start gap-4 p-4 rounded-xl border shadow-2xl backdrop-blur-xl
                ${toast.type === 'success' ? 'bg-green-950/80 border-green-500/50' : ''}
                ${toast.type === 'error' ? 'bg-red-950/80 border-red-500/50' : ''}
                ${toast.type === 'warning' ? 'bg-amber-950/80 border-amber-500/50' : ''}
                ${toast.type === 'info' ? 'bg-blue-950/80 border-blue-500/50' : ''}
              `}>
                <div className="shrink-0 mt-0.5">
                  {toast.type === 'success' && <CheckCircle size={18} className="text-green-400" />}
                  {toast.type === 'error' && <AlertOctagon size={18} className="text-red-400" />}
                  {toast.type === 'warning' && <AlertTriangle size={18} className="text-amber-400" />}
                  {toast.type === 'info' && <Info size={18} className="text-blue-400" />}
                </div>
                <div className="flex-1">
  // eslint-disable-next-line security/detect-object-injection
                  <p className="text-[10px] font-black text-white/90 uppercase tracking-[0.2em] mb-1">
                    {toast.type === 'success' ? 'Operation Success' :
                     toast.type === 'error' ? 'System Error' :
                     toast.type === 'warning' ? 'Security Warning' : 'System Notice'}
                  </p>
                  <p className="text-xs text-white/80 leading-relaxed font-mono">
                    {toast.message}
                  </p>
                </div>
                <button
                  onClick={() => removeToast(toast.id)}
                  className="shrink-0 text-white/30 hover:text-white transition-colors"
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
