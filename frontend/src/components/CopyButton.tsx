import { useState, useCallback, useRef } from 'react';

interface CopyButtonProps {
  text: string;
  size?: 'sm' | 'md';
  className?: string;
}

export function CopyButton({ text, size = 'sm', className = '' }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    setCopied(true);
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => setCopied(false), 2000);
  }, [text]);

  const sz = size === 'md' ? 'min-h-[32px] px-2.5 text-xs' : '';

  return (
    <button
      type="button"
      className={`inline-flex items-center gap-1 rounded text-xs text-muted hover:text-text transition-all duration-200 cursor-pointer select-none ${sz} ${className}`}
      onClick={handleCopy}
      aria-label={copied ? 'Copied to clipboard' : `Copy ${text} to clipboard`}
      title={copied ? 'Copied!' : `Copy: ${text}`}
    >
      {copied ? (
        <span className="text-success" style={{ animation: 'fadeIn 0.2s ease' }}>Copied</span>
      ) : (
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
        </svg>
      )}
    </button>
  );
}
