import { useMemo } from 'react';
import type { CockpitNode } from '@/api/cockpit';

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
    <div className="space-y-8">
      <div>
        <div
          className={`mb-3 inline-block rounded px-2 py-0.5 text-[9px] font-black uppercase tracking-widest ${
            selectedNode.severity === 'high' || selectedNode.severity === 'critical'
              ? 'bg-red-500 text-white'
              : 'bg-accent text-black'
          }`}
        >
          {selectedNode.type}
        </div>
        <h4 className="mb-2 text-xl font-bold leading-tight text-text">{selectedNode.label}</h4>
        <div className="break-all font-mono text-[10px] text-muted opacity-60">
          {selectedNodeUrl || selectedNode.metadata?.host}
        </div>
      </div>

      <section>
        <h5 className="mb-4 text-[10px] font-black uppercase tracking-[0.2em] text-white/30">Operations</h5>
        <div className="grid grid-cols-2 gap-3">
          <button
            type="button"
            onClick={onTriggerProbe}
            disabled={!selectedNodeUrl}
            className="rounded border border-accent/20 bg-accent/10 py-3 text-[10px] font-bold uppercase tracking-widest text-accent transition-all hover:bg-accent/20 disabled:opacity-40"
          >
            Forensic Probe
          </button>
          <button
            type="button"
            onClick={() => findingId && onDrillToFinding(findingId)}
            disabled={!findingId}
            className="rounded border border-white/10 bg-white/5 py-3 text-[10px] font-bold uppercase tracking-widest text-white transition-all hover:bg-white/10 disabled:opacity-40"
          >
            Drill To Finding
          </button>
        </div>
      </section>

      <section>
        <h5 className="mb-4 text-[10px] font-black uppercase tracking-[0.2em] text-white/30">Collaboration</h5>
        <div className="mb-6 space-y-3">
          {notes.map((note) => (
            <div key={note.id} className="rounded border border-white/5 bg-white/5 p-4 group">
              <div className="mb-2 flex items-center justify-between font-mono text-[9px] uppercase opacity-40">
                <span className="text-accent">{note.author}</span>
                <div className="flex items-center gap-2">
                  <span>{new Date(note.created_at).toLocaleDateString()}</span>
                  <button
                    className="text-bad opacity-0 group-hover:opacity-100 transition-opacity"
                    onClick={async () => {
                      if (!target) return;
                      try {
                        const { deleteNote } = await import('@/api/notes');
                        await deleteNote(target, note.id);
                        onDeleteNote(note.id);
                      } catch {
                        console.error('Failed to remove note');
                      }
                    }}
                  >
                    ×
                  </button>
                </div>
              </div>
              <p className="text-xs leading-relaxed text-text/80">{note.note}</p>
            </div>
          ))}
        </div>
        <textarea
          value={newNote}
          onChange={(event) => setNewNote(event.target.value)}
          placeholder="ENTER DATA..."
          className="min-h-[100px] w-full rounded border border-white/10 bg-white/5 p-4 font-mono text-xs text-text outline-none focus:border-accent/50"
        />
        <button
          type="button"
          onClick={onAddNote}
          disabled={!newNote.trim()}
          className="mt-3 w-full rounded bg-accent py-3 text-[10px] font-black uppercase tracking-[0.2em] text-black transition-colors hover:bg-white disabled:opacity-40"
        >
          Submit Intel
        </button>
      </section>
    </div>
  );
}
