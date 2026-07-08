import { CoreProviders } from '@/context/CoreProviders';
import { AppLayout } from '@/components/layout/AppLayout';
import { RouteConfig } from '@/RouteConfig';
import { BootEffects } from '@/BootEffects';

export default function App() {
  return (
    <CoreProviders>
      <BootEffects />
      <AppLayout>
        <RouteConfig />
      </AppLayout>
    </CoreProviders>
  );
}
