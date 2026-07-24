import { CoreProviders } from '@/context/CoreProviders';
import { JobsProvider } from '@/context/JobsContext';
import { TargetsProvider } from '@/context/TargetsContext';
import { AppLayout } from '@/components/layout/AppLayout';
import { RouteConfig } from '@/RouteConfig';
import { BootEffects } from '@/BootEffects';
import { useAuth } from '@/hooks/useAuth';

function AuthenticatedApp() {
  return (
    <JobsProvider>
      <TargetsProvider>
        <BootEffects />
        <AppLayout>
          <RouteConfig />
        </AppLayout>
      </TargetsProvider>
    </JobsProvider>
  );
}

function UnauthApp() {
  return (
    <>
      <BootEffects />
      <AppLayout>
        <RouteConfig />
      </AppLayout>
    </>
  );
}

export default function App() {
  const { user } = useAuth();

  return (
    <CoreProviders>
      {user ? <AuthenticatedApp /> : <UnauthApp />}
    </CoreProviders>
  );
}
