import { Skeleton } from '@/components/ui-shadcn/skeleton';
import { cn } from '@/lib/utils';

const shimmerAnimation =
  'relative overflow-hidden bg-surface-2 before:absolute before:inset-0 before:-translate-x-full before:animate-[shimmer_2s_infinite] before:bg-gradient-to-r before:from-transparent before:via-white/[0.06] before:to-transparent';

interface TabFallbackProps {
  className?: string;
}

export function TabFallback({ className }: TabFallbackProps) {
  return (
    <div
      className={cn('flex flex-col items-center justify-center py-20 gap-4', className)}
      role="status"
      aria-label="Loading tab content"
    >
      <Skeleton className={cn(shimmerAnimation, 'h-4 w-48 rounded-sm')} />
      <Skeleton className={cn(shimmerAnimation, 'h-3 w-32 rounded-sm')} />
      <p className="text-xs text-muted font-mono uppercase tracking-widest animate-pulse mt-2">
        Loading...
      </p>
    </div>
  );
}
