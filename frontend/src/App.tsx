import { CoreProviders } from '@/context/CoreProviders';
import { JobsProvider } from '@/context/JobsContext';
import { TargetsProvider } from '@/context/TargetsContext';
import { AppLayout } from '@/components/layout/AppLayout';
import { RouteConfig } from '@/RouteConfig';
import { BootEffects } from '@/BootEffects';
import { useAuth } from '@/hooks/useAuth';

function Shell() {
  const { user } = useAuth();
  const tree = (
    <AppLayout>
      <RouteConfig />
    </AppLayout>
  );

  if (!user) return tree;

  return (
    <JobsProvider>
      <TargetsProvider>
        {tree}
      </TargetsProvider>
    </JobsProvider>
  );
}

export default function App() {
  return (
    <CoreProviders>
      <BootEffects />
      <Shell />
    </CoreProviders>
  );
}
