import { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FileText, ChevronUp, Download } from 'lucide-react';
import { useExporters } from '@/hooks/useExporters';
import type { Finding } from '@/types/api';
import type { ExporterFormat } from '@/utils/exporters';

interface ReportFabProps {
  findings: Finding[];
  filenameBase?: string;
  context?: {
    target?: string;
    program?: string;
    jobId?: string;
  };
  /** Anchor label. Defaults to "Generate Report". */
  label?: string;
  /** When provided, also offers a one-click PDF link via the report library. */
  targetName?: string;
  /** When true, the FAB is shown as an "in-page" action rather than fixed position. */
  inline?: boolean;
}

export function ReportFab({ findings, filenameBase, context, label, targetName, inline }: ReportFabProps) {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);
  const exporter = useExporters({ findings, filenameBase, context });

  useEffect(() => {
    if (!open) return;
    function onClick(e: MouseEvent) {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    window.addEventListener('mousedown', onClick);
    return () => window.removeEventListener('mousedown', onClick);
  }, [open]);

  const handleSelect = (format: ExporterFormat) => {
    setOpen(false);
    exporter.runExport(format);
  };

  const anchor = (
    <button
      type="button"
      className="report-fab"
      onClick={() => setOpen((v) => !v)}
      disabled={findings.length === 0}
      aria-haspopup="menu"
      aria-expanded={open}
      data-testid="report-fab"
    >
      <FileText size={14} />
      <span>{label ?? 'Generate Report'}</span>
      <ChevronUp size={12} className={`transition-transform ${open ? 'rotate-180' : ''}`} />
    </button>
  );

  const menu = (
    <AnimatePresence>
      {open && (
        <motion.ul
          initial={{ opacity: 0, y: 6, scale: 0.98 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: 6, scale: 0.98 }}
          transition={{ duration: 0.14 }}
          className="report-fab-menu"
          role="menu"
        >
          {exporter.formats.map((f) => (
            <li key={f.key}>
              <button
                type="button"
                onClick={() => handleSelect(f.key)}
                className="report-fab-menu-item"
                role="menuitem"
              >
                <Download size={12} className="opacity-60" />
                <span className="font-black text-[11px] uppercase tracking-widest">{f.label}</span>
                <span className="text-[9px] text-muted/80 font-mono normal-case">{f.description}</span>
              </button>
            </li>
          ))}
          {targetName && (
            <li>
              <a
                href={`/api/reports/compliance/pdf?target=${encodeURIComponent(targetName)}`}
                target="_blank"
                rel="noopener noreferrer"
                className="report-fab-menu-item"
                role="menuitem"
                onClick={() => setOpen(false)}
              >
                <FileText size={12} className="opacity-60" />
                <span className="font-black text-[11px] uppercase tracking-widest">Compliance PDF</span>
                <span className="text-[9px] text-muted/80 font-mono normal-case">Signed SOC 2 / PCI-DSS report</span>
              </a>
            </li>
          )}
        </motion.ul>
      )}
    </AnimatePresence>
  );

  if (inline) {
    return (
      <div ref={wrapRef} className="relative inline-block">
        {anchor}
        {menu}
      </div>
    );
  }

  return (
    <div ref={wrapRef} className="report-fab-stack">
      {anchor}
      {menu}
    </div>
  );
}
