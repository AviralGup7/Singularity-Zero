import { memo } from 'react';
import { Icon } from '@/components/ui/Icon';
import type { CockpitNode, ForensicExchange } from '@/api/cockpit';
import { IntelSidebar } from '@/components/cockpit/IntelSidebar';
import { ForensicExchangeItem } from '@/components/cockpit/ForensicExchangeItem';
import { ForensicExchangeDetail } from '@/components/cockpit/ForensicExchangeDetail';
import type { Note } from '@/types/extended';

interface CockpitSidebarProps {
  sidebarOpen: boolean;
  setSidebarOpen: (open: boolean) => void;
  sidebarTab: 'intel' | 'chains' | 'forensics';
  setSidebarTab: (tab: 'intel' | 'chains' | 'forensics') => void;
  selectedNode: CockpitNode | undefined;
  selectedNodeUrl: string;
  notes: Note[];
  newNote: string;
  setNewNote: (note: string) => void;
  onAddNote: () => void;
  onTriggerProbe: () => void;
  onDrillToFinding: (findingId: string) => void;
  onDeleteNote: (noteId: string) => void;
  target: string;
  probing?: boolean;
  selectedExchange: ForensicExchange | null;
  setSelectedExchange: (exchange: ForensicExchange | null) => void;
  exchanges: ForensicExchange[];
  onOpenForensic: (id: string) => void;
}

function CockpitSidebarBase({
  sidebarOpen,
  setSidebarOpen,
  sidebarTab,
  setSidebarTab,
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
  probing: _probing,
  selectedExchange,
  setSelectedExchange,
  exchanges,
  onOpenForensic,
}: CockpitSidebarProps) {
  if (!sidebarOpen) return null;

  return (
    <div className="w-96 flex-shrink-0 z-20 flex flex-col border-l border-line-strong bg-surface/90 backdrop-blur-2xl shadow-2xl" role="complementary" aria-label="Cockpit inspector sidebar">
      <div className="flex items-center justify-between border-b border-line-muted px-6 py-4">
        <h3 className="text-xs font-black uppercase tracking-[0.2em] text-accent">
          Inspector Telemetry
        </h3>
        <button
          type="button"
          onClick={() => setSidebarOpen(false)}
          className="text-text-secondary transition-colors hover:text-accent focus-visible:ring-2 focus-visible:ring-accent/50 focus-visible:outline-none rounded"
          aria-label="Close inspector sidebar"
        >
          <Icon name="x" size={18} aria-hidden="true" />
        </button>
      </div>

      <div className="flex border-b border-line-muted bg-surface-2" role="tablist" aria-label="Inspector tabs">
        {(['intel', 'forensics'] as const).map((tab) => (
          <button
            key={tab}
            type="button"
            onClick={() => setSidebarTab(tab)}
            role="tab"
            aria-selected={sidebarTab === tab}
            aria-controls={`sidebar-panel-${tab}`}
            className={`flex-1 text-center py-3 font-mono text-[10px] font-black uppercase tracking-wider transition-all border-b-2 ${
              sidebarTab === tab ? 'border-accent text-text-primary' : 'border-transparent text-text-secondary hover:text-text-primary'
            }`}
          >
            {tab === 'intel' ? 'Findings' : 'Forensics'}
          </button>
        ))}
      </div>

      <div className="scrollbar-cyber flex-1 overflow-y-auto p-6" role="tabpanel" id={`sidebar-panel-${sidebarTab}`}>
        {sidebarTab === 'intel' && selectedNode && (
          <IntelSidebar
            selectedNode={selectedNode}
            selectedNodeUrl={selectedNodeUrl}
            notes={notes}
            newNote={newNote}
            setNewNote={setNewNote}
            onAddNote={onAddNote}
            onTriggerProbe={onTriggerProbe}
            onDrillToFinding={onDrillToFinding}
            onDeleteNote={onDeleteNote}
            target={target}
          />
        )}

        {sidebarTab === 'forensics' && (
          <div className="space-y-4">
            {selectedExchange ? (
              <ForensicExchangeDetail
                exchange={selectedExchange}
                onBack={() => setSelectedExchange(null)}
              />
            ) : (
              exchanges.map((exchange) => (
                <ForensicExchangeItem
                  key={exchange.exchange_id}
                  exchange={exchange}
                  onOpen={onOpenForensic}
                />
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export const CockpitSidebar = memo(CockpitSidebarBase);
