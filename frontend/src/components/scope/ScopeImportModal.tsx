import { useState, useMemo, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, ClipboardPaste, FileText, CheckCircle2, AlertCircle, Trash2 } from 'lucide-react';
import { useScopeStore } from '@/stores/scopeStore';
import { useToast } from '@/hooks/useToast';
import { parseScopeText } from '@/utils/scopeParser';
import type { ParsedScope } from '@/utils/scopeParser';
import type React from 'react';

interface ScopeImportModalProps {
  open: boolean;
  onClose: () => void;
}

const SAMPLE_HACKERONE = `In-scope assets
*.shopify.com
shopify.com
myshopify.com
Out-of-scope assets
status.shopify.com
docs.shopify.com - third-party hosting`;

const SAMPLE_BUGCROWD = `Target | Type | Reward Range
*.example-corp.com | Website | $500-$5,000
api.example-corp.com | API | $250-$2,500
example-corp.com | Website | $100-$1,500
Out of scope
blog.example-corp.com - hosted by third party
careers.example-corp.com - linkedin only`;

export function ScopeImportModal({ open, onClose }: ScopeImportModalProps) {
  const toast = useToast();
  const { programHandle, setProgramHandle, raw, importRaw, parsed, clear, importedAt } =
    useScopeStore();

  const [draft, setDraft] = useState<string>(raw);
  const [program, setProgram] = useState<string>(programHandle);
  const [error, setError] = useState<string | null>(null);

  const preview = useMemo(() => {
    if (!draft.trim()) return null;
    try {
      return parseScopeText(draft);
    } catch (err) {
      console.error(err);
      return null;
    }
  }, [draft]);

  const handleImport = useCallback(() => {
    setError(null);
    if (!draft.trim()) {
      setError('Paste the program policy text before importing.');
      return;
    }
    const result = importRaw(draft);
    if (!result) {
      setError('Could not detect any in-scope or out-of-scope assets in the pasted text.');
      return;
    }
    if (program.trim()) setProgramHandle(program.trim());
    toast.success(
      `Imported ${result.in_scope.length} in-scope and ${result.out_of_scope.length} out-of-scope assets`,
    );
    onClose();
  }, [draft, importRaw, onClose, program, setProgramHandle, toast]);

  const handleClear = useCallback(() => {
    clear();
    setDraft('');
    setProgram('');
    setError(null);
    toast.info('Scope cleared');
  }, [clear, toast]);

  const handlePaste = useCallback(async () => {
    try {
      const text = await navigator.clipboard.readText();
      setDraft(text);
    } catch {
      toast.error('Clipboard access denied - paste manually with Ctrl+V');
    }
  }, [toast]);

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="fixed inset-0 z-[10000] flex items-center justify-center bg-black/70 backdrop-blur-sm p-4"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={(e: React.MouseEvent<HTMLDivElement>) => { if (e.target === e.currentTarget) onClose(); }}
          role="dialog"
          aria-modal="true"
          aria-label="Import program scope"
        >
          <motion.div
            initial={{ scale: 0.95, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.95, opacity: 0 }}
            transition={{ type: 'spring', stiffness: 240, damping: 26 }}
            className="w-full max-w-3xl max-h-[90vh] overflow-hidden rounded-xl border border-white/10 bg-[#0b0d12] shadow-2xl"
          >
            <header className="flex items-center justify-between border-b border-white/5 px-6 py-4">
              <div>
                <h2 className="text-sm font-black uppercase tracking-[0.2em] text-accent">
                  Import Program Scope
                </h2>
                <p className="mt-1 text-[10px] font-mono text-muted">
                  Paste a HackerOne / Bugcrowd / Intigriti policy. We extract in-scope
                  and out-of-scope assets automatically.
                </p>
              </div>
              <button
                type="button"
                onClick={onClose}
                aria-label="Close scope import modal"
                className="text-muted transition-colors hover:text-accent"
              >
                <X size={20} />
              </button>
            </header>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-0 max-h-[calc(90vh-160px)] overflow-hidden">
              <div className="flex flex-col border-r border-white/5">
                <div className="flex items-center gap-2 border-b border-white/5 px-4 py-2">
                  <FileText size={14} className="text-muted" />
                  <span className="text-[10px] font-mono uppercase tracking-widest text-muted">
                    Policy text
                  </span>
                  <div className="ml-auto flex items-center gap-1">
                    <button
                      type="button"
                      onClick={handlePaste}
                      className="flex items-center gap-1 rounded border border-white/10 bg-white/5 px-2 py-1 text-[10px] font-bold uppercase tracking-widest text-muted hover:text-white"
                    >
                      <ClipboardPaste size={11} /> Paste
                    </button>
                    <button
                      type="button"
                      onClick={() => setDraft(SAMPLE_HACKERONE)}
                      className="rounded border border-white/10 bg-white/5 px-2 py-1 text-[10px] font-bold uppercase tracking-widest text-muted hover:text-white"
                    >
                      Sample H1
                    </button>
                    <button
                      type="button"
                      onClick={() => setDraft(SAMPLE_BUGCROWD)}
                      className="rounded border border-white/10 bg-white/5 px-2 py-1 text-[10px] font-bold uppercase tracking-widest text-muted hover:text-white"
                    >
                      Sample BC
                    </button>
                  </div>
                </div>
                <textarea
                  value={draft}
                  onChange={(e) => { setDraft(e.target.value); setError(null); }}
                  placeholder="Paste the program policy here. Section headers like 'In-scope' or 'Out of scope' will be detected automatically."
                  className="flex-1 min-h-[280px] resize-none bg-transparent p-4 font-mono text-[11px] text-text outline-none placeholder:text-muted/50"
                  aria-label="Scope policy text"
                />
                {error && (
                  <div className="flex items-center gap-2 border-t border-bad/30 bg-bad/10 px-4 py-2 text-[10px] font-mono text-bad">
                    <AlertCircle size={12} /> {error}
                  </div>
                )}
              </div>

              <div className="flex flex-col bg-black/30">
                <div className="border-b border-white/5 px-4 py-2">
                  <label htmlFor="scope-program-handle" className="block text-[10px] font-mono uppercase tracking-widest text-muted">
                    Program handle
                  </label>
                  <input
                    id="scope-program-handle"
                    value={program}
                    onChange={(e) => setProgram(e.target.value)}
                    placeholder="e.g. hackerone-shopify"
                    className="mt-1 w-full rounded border border-white/10 bg-white/5 px-2 py-1 font-mono text-[11px] text-text outline-none focus:border-accent/40"
                  />
                </div>
                <ScopePreview parsed={preview} />
              </div>
            </div>

            <footer className="flex items-center justify-between gap-2 border-t border-white/5 bg-black/40 px-6 py-3">
              <button
                type="button"
                onClick={handleClear}
                disabled={!parsed}
                className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-widest text-muted hover:text-bad disabled:opacity-30"
              >
                <Trash2 size={12} /> Clear stored scope
              </button>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={onClose}
                  className="rounded border border-white/10 bg-white/5 px-4 py-2 text-[10px] font-black uppercase tracking-widest text-muted hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleImport}
                  className="flex items-center gap-1.5 rounded bg-accent px-4 py-2 text-[10px] font-black uppercase tracking-widest text-black shadow-[0_0_15px_rgba(0,255,244,0.25)] hover:bg-white"
                >
                  <CheckCircle2 size={12} /> Import Scope
                </button>
              </div>
            </footer>

            {importedAt && !draft && (
              <div className="border-t border-white/5 bg-black/30 px-6 py-2 text-[10px] font-mono text-muted">
                Last import: {new Date(importedAt).toLocaleString()}
              </div>
            )}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

function ScopePreview({ parsed }: { parsed: ParsedScope | null }) {
  if (!parsed) {
    return (
      <div className="flex flex-1 items-center justify-center p-8 text-center text-muted">
        <p className="text-[10px] font-mono uppercase tracking-widest">
          Paste policy text to preview
        </p>
      </div>
    );
  }

  return (
    <div className="flex-1 overflow-y-auto p-4 text-[10px] font-mono">
      <div className="mb-3 flex items-center gap-2 text-[10px] uppercase tracking-widest text-muted">
        <span>Source detected:</span>
        <span className="rounded bg-accent/20 px-2 py-0.5 text-accent">{parsed.source}</span>
        <span>·</span>
        <span>{parsed.total_lines} lines, {parsed.unparseable_lines} ignored</span>
      </div>

      <ScopeBucket
        title={`In-scope (${parsed.in_scope.length})`}
        accent="ok"
        entries={parsed.in_scope.slice(0, 200)}
      />
      <ScopeBucket
        title={`Out-of-scope (${parsed.out_of_scope.length})`}
        accent="bad"
        entries={parsed.out_of_scope.slice(0, 200)}
      />
      {parsed.in_scope.length > 200 && (
        <p className="mt-2 text-muted">…and {parsed.in_scope.length - 200} more in-scope entries</p>
      )}
    </div>
  );
}

function ScopeBucket({
  title,
  entries,
  accent,
}: {
  title: string;
  entries: { pattern: string; notes: string; bounty_min_usd?: number; bounty_max_usd?: number }[];
  accent: 'ok' | 'bad';
}) {
  const accentClass = accent === 'ok' ? 'text-ok' : 'text-bad';
  return (
    <div className="mb-4">
      <h3 className={`mb-2 text-[10px] font-black uppercase tracking-widest ${accentClass}`}>
        {title}
      </h3>
      {entries.length === 0 ? (
        <p className="text-muted italic">none</p>
      ) : (
        <ul className="space-y-1">
          {entries.map((e) => (
            <li
              key={e.pattern}
              className="flex items-center gap-2 rounded border border-white/5 bg-white/[0.02] px-2 py-1"
            >
              <span className="truncate text-text">{e.pattern}</span>
              {(e.bounty_min_usd != null || e.bounty_max_usd != null) && (
                <span className="ml-auto whitespace-nowrap text-ok">
                  ${e.bounty_min_usd?.toLocaleString() ?? '?'}–${e.bounty_max_usd?.toLocaleString() ?? '?'}
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
