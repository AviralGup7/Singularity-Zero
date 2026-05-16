import { useState, createContext, useContext, type ReactNode } from 'react';
import { Tabs as ShadcnTabs, TabsList as ShadcnTabsList, TabsTrigger as ShadcnTabsTrigger, TabsContent as ShadcnTabsContent } from '../ui-shadcn/tabs';

// Adapters preserving the existing api/prop names so any existing or future consumers keep working.
// Under the hood: fully delegates to Radix-based shadcn implementation.

interface TabsContextValue {
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

const TabsContext = createContext<TabsContextValue | null>(null);

function useTabsContext() {
  const ctx = useContext(TabsContext);
  if (!ctx) throw new Error('Tab components must be used within Tabs');
  return ctx;
}

interface TabsProps {
  children: ReactNode;
  defaultTab?: string;
  className?: string;
}

export function Tabs({ children, defaultTab = '', className }: TabsProps) {
   
  const [activeTab, setActiveTab] = useState(defaultTab);

  return (
    <TabsContext.Provider value={{ activeTab, setActiveTab }}>
      <ShadcnTabs
        value={defaultTab}
        onValueChange={setActiveTab}
        className={className}
      >
        {children}
      </ShadcnTabs>
    </TabsContext.Provider>
  );
}

interface TabListProps {
  children: ReactNode;
  className?: string;
}

export function TabList({ children, className }: TabListProps) {
  return (
    <ShadcnTabsList className={className}>
      {children}
    </ShadcnTabsList>
  );
}

interface TabProps {
  tabId: string;
  children: ReactNode;
  className?: string;
}

export function Tab({ tabId, children, className }: TabProps) {
  const { setActiveTab } = useTabsContext();

  return (
    <ShadcnTabsTrigger
      value={tabId}
      className={className}
      onClick={() => setActiveTab(tabId)}
    >
      {children}
    </ShadcnTabsTrigger>
  );
}

interface TabPanelProps {
  tabId: string;
  children: ReactNode;
  className?: string;
}

export function TabPanel({ tabId, children, className }: TabPanelProps) {
  return (
    <ShadcnTabsContent value={tabId} className={className}>
      {children}
    </ShadcnTabsContent>
  );
}
