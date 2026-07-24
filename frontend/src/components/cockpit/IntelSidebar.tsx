import type { CockpitNode } from '@/api/cockpit';
import { showErrorToast } from '@/utils/extractErrorMessage';

interface IntelSidebarProps {
  selectedNode: CockpitNode | undefined;
  selectedNodeUrl: string;
  notes: { id: string; author: string; created_at: string; note: string }[];
  newNote: string;
  setNewNote: (note: string) => void;
  onAddNote: () => void;
  onTriggerProbe: () => void;
  onDrillToFinding: (findingId: string) => void;
  onDeleteNote: (noteId: string) => void;
  target: string;
}

export function IntelSidebar({
  selectedNode,
  selectedNodeUrl,
  notes,
  newNote,
  setNewNote,
  onAddNote,
  onTriggerProbe,
  onDrillToFinding,
  onDeleteNote,
  target,
}: IntelSidebarProps) {
  if (!selectedNode) return null;

  const findingId = selectedNode.type === 'finding'
    ? selectedNode.id.replace('finding:', '')
    : selectedNode.metadata?.finding_id;

  return (
    <div className="space-y-8" role="region" aria-label={`Intel for ${selectedNode.label}`}>
      <div>
        <div
          className={`mb-3 inline-block rounded px-2 py-0.5 text-[9px] font-black uppercase tracking-widest ${
            selectedNode.severity === 'high' || selectedNode.severity === 'critical'
              ? 'bg-bad text-text-primary'
              : 'bg-accent text-black'
          }`}
          role="status"
        >
          {selectedNode.type}
        </div>
        <h4 className="mb-2 text-xl font-bold leading-tight text-text-primary">{selectedNode.label}</h4>
        <div className="break-all font-mono text-[10px] text-text-secondary opacity-60" title={(selectedNodeUrl || selectedNode.metadata?.host) ?? ''}>
          {selectedNodeUrl || selectedNode.metadata?.host}
        </div>
      </div>

      <section aria-label="Operations">
        <h5 className="mb-4 text-[10px] font-black uppercase tracking-[0.2em] text-text-tertiary">Operations</h5>
        <div className="grid grid-cols-2 gap-3">
          <button
            type="button"
            onClick={onTriggerProbe}
            disabled={!selectedNodeUrl}
            className="rounded border border-accent/20 bg-accent/10 py-3 text-[10px] font-bold uppercase tracking-widest text-accent transition-all hover:bg-accent/20 disabled:opacity-40 focus-visible:ring-2 focus-visible:ring-accent/50 focus-visible:outline-none"
          >
            Forensic Probe
          </button>
          <button
            type="button"
            onClick={() => findingId && onDrillToFinding(findingId)}
            disabled={!findingId}
            className="rounded border border-line bg-surface-2 py-3 text-[10px] font-bold uppercase tracking-widest text-text-primary transition-all hover:bg-surface-hover disabled:opacity-40 focus-visible:ring-2 focus-visible:ring-accent/50 focus-visible:outline-none"
          >
            Drill To Finding
          </button>
        </div>
      </section>

      <section aria-label="Collaboration notes">
        <h5 className="mb-4 text-[10px] font-black uppercase tracking-[0.2em] text-text-tertiary">Collaboration</h5>
        <div className="mb-6 space-y-3" aria-live="polite">
          {notes.map((note) => (
            <div key={note.id} className="rounded border border-line-muted bg-surface-2 p-4 group" role="article" aria-label={`Note by ${note.author}`}>
              <div className="mb-2 flex items-center justify-between font-mono text-[9px] uppercase opacity-40">
                <span className="text-accent">{note.author}</span>
                <div className="flex items-center gap-2">
                  <time dateTime={note.created_at}>{new Date(note.created_at).toLocaleDateString()}</time>
                  <button
                    className="text-bad opacity-0 group-hover:opacity-100 transition-opacity focus-visible:opacity-100 focus-visible:ring-2 focus-visible:ring-bad/50 focus-visible:outline-none"
                    aria-label={`Delete note by ${note.author}`}
                    onClick={async () => {
                      if (!target) return;
                      try {
                        const { deleteNote } = await import('@/api/notes');
                        await deleteNote(target, note.id);
                        onDeleteNote(note.id);
                      } catch {
                        showErrorToast('Failed to remove note');
                      }
                    }}
                  >
                    x
                  </button>
                </div>
              </div>
              <p className="text-xs leading-relaxed text-text-primary/80">{note.note}</p>
            </div>
          ))}
        </div>
        <label className="block">
          <span className="sr-only">Add a collaboration note</span>
          <textarea
            value={newNote}
            onChange={(event) => setNewNote(event.target.value)}
            placeholder="ENTER DATA..."
            aria-label="New note text"
            className="min-h-[100px] w-full rounded border border-line bg-surface-2 p-4 font-mono text-xs text-text-primary outline-none focus:border-accent/50 focus-visible:ring-2 focus-visible:ring-accent/30"
          />
        </label>
        <button
          type="button"
          onClick={onAddNote}
          disabled={!newNote.trim()}
          className="mt-3 w-full rounded bg-accent py-3 text-[10px] font-black uppercase tracking-[0.2em] text-black transition-colors hover:bg-surface-raised disabled:opacity-40 focus-visible:ring-2 focus-visible:ring-accent/50 focus-visible:outline-none"
        >
          Submit Intel
        </button>
      </section>
    </div>
  );
}
