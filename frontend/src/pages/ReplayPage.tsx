import ReplayInterface from '@/components/ReplayInterface';
import { Breadcrumbs } from '@/components/ui/Breadcrumbs';
import { useAutoBreadcrumbs } from '@/hooks/useAutoBreadcrumbs';

export function ReplayPage() {
  const crumbs = useAutoBreadcrumbs();
  return (
    <div className="replay-page">
      <h1 className="sr-only" data-focus-heading>Replay Request</h1>
      <Breadcrumbs items={crumbs} />
      <ReplayInterface />
    </div>
  );
}
