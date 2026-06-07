import { useEffect, useState } from 'react';
import {
  listPlatformClients,
  pushFindingToPlatform,
  type Platform,
  type PlatformClientSummary,
  type SubmissionResult,
} from '@/api/platforms';

interface SubmitToPlatformDialogProps {
  runId: string;
  findingId: string;
  findingTitle: string;
  open: boolean;
  onClose: () => void;
  onSubmitted?: (result: SubmissionResult) => void;
}

export function SubmitToPlatformDialog({
  runId,
  findingId,
  findingTitle,
  open,
  onClose,
  onSubmitted,
}: SubmitToPlatformDialogProps) {
  const [clients, setClients] = useState<PlatformClientSummary[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Platform | ''>('');
  const [draft, setDraft] = useState(true);
  const [notes, setNotes] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<SubmissionResult | null>(null);

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setClients(null);
    setLoadError(null);
    setResult(null);
    setSelected('');
    listPlatformClients()
      .then((list) => {
        if (cancelled) return;
        setClients(list);
        const firstReady = list.find((c) => c.ready);
        if (firstReady) setSelected(firstReady.platform);
      })
      .catch((err) => {
        if (cancelled) return;
        setLoadError(err instanceof Error ? err.message : String(err));
      });
    return () => {
      cancelled = true;
    };
  }, [open]);

  if (!open) return null;

  const handleSubmit = async () => {
    if (!selected) return;
    setSubmitting(true);
    setResult(null);
    try {
      const res = await pushFindingToPlatform(runId, findingId, selected, {
        draft,
        additionalNotes: notes,
      });
      setResult(res);
      if (res.submitted && onSubmitted) onSubmitted(res);
    } catch (err) {
      setResult({
        platform: selected as Platform,
        submitted: false,
        error: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="submit-platform-title"
    >
      <div className="w-full max-w-lg rounded-lg border border-slate-700 bg-slate-900 p-6 shadow-xl">
        <div className="flex items-start justify-between">
          <div>
            <h2 id="submit-platform-title" className="text-lg font-semibold text-slate-100">
              Submit to bug-bounty platform
            </h2>
            <p className="mt-1 text-sm text-slate-400">
              {findingTitle}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200"
            aria-label="Close"
          >
            ×
          </button>
        </div>

        {loadError ? (
          <div className="mt-4 rounded border border-red-700 bg-red-900/40 p-3 text-sm text-red-200">
            Failed to load platform clients: {loadError}
          </div>
        ) : clients === null ? (
          <div className="mt-4 text-sm text-slate-400">Loading configured platforms…</div>
        ) : clients.length === 0 ? (
          <div className="mt-4 rounded border border-amber-700 bg-amber-900/30 p-3 text-sm text-amber-100">
            No platform clients are configured. Set the API tokens via
            <code className="mx-1 rounded bg-slate-800 px-1.5 py-0.5 text-xs">
              HACKERONE_API_TOKEN
            </code>
            ,
            <code className="mx-1 rounded bg-slate-800 px-1.5 py-0.5 text-xs">
              BUGCROWD_API_TOKEN
            </code>
            ,
            <code className="mx-1 rounded bg-slate-800 px-1.5 py-0.5 text-xs">
              INTIGRITI_API_TOKEN
            </code>
            , or
            <code className="mx-1 rounded bg-slate-800 px-1.5 py-0.5 text-xs">
              SYNACK_API_TOKEN
            </code>
            .
          </div>
        ) : (
          <>
            <fieldset className="mt-4 space-y-2">
              <legend className="text-sm font-medium text-slate-300">Platform</legend>
              {clients.map((client) => (
                <label
                  key={client.platform}
                  className={`flex cursor-pointer items-start gap-3 rounded border p-3 ${
                    selected === client.platform
                      ? 'border-cyan-500 bg-slate-800/60'
                      : 'border-slate-700 bg-slate-800/30 hover:border-slate-500'
                  } ${client.ready ? '' : 'opacity-60'}`}
                >
                  <input
                    type="radio"
                    name="platform"
                    value={client.platform}
                    disabled={!client.ready}
                    checked={selected === client.platform}
                    onChange={() => setSelected(client.platform)}
                    className="mt-1"
                  />
                  <div className="flex-1">
                    <div className="text-sm font-medium text-slate-100">
                      {client.platform}
                      {!client.ready && (
                        <span className="ml-2 rounded bg-amber-900/40 px-1.5 py-0.5 text-[10px] uppercase text-amber-300">
                          Not configured
                        </span>
                      )}
                    </div>
                    {client.last_error && (
                      <div className="mt-1 text-xs text-amber-300">{client.last_error}</div>
                    )}
                  </div>
                </label>
              ))}
            </fieldset>

            <label className="mt-4 flex items-center gap-2 text-sm text-slate-300">
              <input
                type="checkbox"
                checked={draft}
                onChange={(e) => setDraft(e.target.checked)}
              />
              Submit as draft (recommended — verify before publishing)
            </label>

            <label className="mt-3 block text-sm text-slate-300">
              Additional notes (optional)
              <textarea
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                rows={3}
                className="mt-1 w-full rounded border border-slate-700 bg-slate-800 p-2 text-sm text-slate-100"
                placeholder="e.g. Reproduction steps beyond the auto-generated PoC"
              />
            </label>

            {result && (
              <div
                className={`mt-4 rounded border p-3 text-sm ${
                  result.submitted
                    ? 'border-emerald-700 bg-emerald-900/30 text-emerald-100'
                    : 'border-red-700 bg-red-900/30 text-red-100'
                }`}
              >
                {result.submitted ? (
                  <>
                    <div className="font-medium">Submitted to {result.platform}.</div>
                    {result.url && (
                      <a
                        href={result.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-cyan-300 underline"
                      >
                        Open report
                      </a>
                    )}
                    {!result.url && result.report_id && (
                      <div className="text-xs text-slate-300">Report ID: {result.report_id}</div>
                    )}
                  </>
                ) : (
                  <>
                    <div className="font-medium">Submission failed.</div>
                    <div className="text-xs">{result.error}</div>
                  </>
                )}
              </div>
            )}

            <div className="mt-6 flex justify-end gap-2">
              <button
                type="button"
                onClick={onClose}
                className="rounded border border-slate-600 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-800"
              >
                Close
              </button>
              <button
                type="button"
                onClick={handleSubmit}
                disabled={!selected || submitting}
                className="rounded bg-cyan-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-50"
              >
                {submitting ? 'Submitting…' : draft ? 'Save as draft' : 'Submit now'}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default SubmitToPlatformDialog;
