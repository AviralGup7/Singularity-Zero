import type { DetailTab } from './helpers';

interface TabDef {
  id: DetailTab;
  label: string;
  hide?: boolean;
}

interface DetailTabsProps {
  tabs: TabDef[];
  activeTab: DetailTab;
  onTabChange: (tab: DetailTab) => void;
}

export function DetailTabs({ tabs, activeTab, onTabChange }: DetailTabsProps) {
  return (
    <div className="flex gap-6 border-b border-line overflow-x-auto" role="tablist" aria-label="Finding detail sections">
      {tabs.map(
        (tab) =>
          !tab.hide && (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={activeTab === tab.id}
              onClick={() => onTabChange(tab.id)}
              className={`pb-4 text-[10px] font-black uppercase tracking-widest border-b-2 transition-all whitespace-nowrap ${
                activeTab === tab.id ? 'border-accent text-text-primary' : 'border-transparent text-muted hover:text-text'
              }`}
            >
              {tab.label}
            </button>
          ),
      )}
    </div>
  );
}

export function buildTabs(
  chainSimulation: unknown,
  isLogicBreach: boolean,
): Array<{ id: DetailTab; label: string; hide?: boolean }> {
  return [
    { id: 'csi', label: 'Analysis' },
    { id: 'bounty', label: 'Bounty & Submission' },
    { id: 'evidence', label: 'Evidence' },
    { id: 'custody', label: 'Custody' },
    { id: 'simulation', label: 'Simulation', hide: !chainSimulation },
    { id: 'request', label: 'Payloads' },
    { id: 'logic', label: 'Logic Diff', hide: !isLogicBreach },
    { id: 'risk', label: 'Risk' },
    { id: 'activity', label: 'Activity' },
    { id: 'comments', label: 'Intelligence' },
  ];
}
