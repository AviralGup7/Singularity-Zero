import { cn } from '@/lib/utils';
import { Skeleton as ShadcnSkeleton } from '@/components/ui-shadcn/skeleton';

export interface SkeletonProps {
  variant?: 'text' | 'card' | 'stat' | 'table' | 'circle';
  width?: string;
  height?: string;
  lines?: number;
  className?: string;
}

const shimmerAnimation =
  'relative overflow-hidden bg-[var(--panel-2)] before:absolute before:inset-0 before:-translate-x-full before:animate-[shimmer_2s_infinite] before:bg-gradient-to-r before:from-transparent before:via-white/[0.06] before:to-transparent';

export function Skeleton({ variant = 'text', width, height, lines = 1, className }: SkeletonProps) {
  if (variant === 'card') {
    return (
      <div className={cn('p-4 border border-[var(--line)] bg-[var(--panel)] rounded-sm', className)}>
        <ShadcnSkeleton className={cn(shimmerAnimation, 'h-4 w-3/4 mb-3 rounded-sm')} />
        <ShadcnSkeleton className={cn(shimmerAnimation, 'h-3 w-full mb-2 rounded-sm')} />
        <ShadcnSkeleton className={cn(shimmerAnimation, 'h-3 w-1/2 rounded-sm')} />
      </div>
    );
  }

  if (variant === 'stat') {
    return (
      <div className={cn('text-center', className)}>
        <ShadcnSkeleton className={cn(shimmerAnimation, 'h-6 w-16 mx-auto mb-1 rounded-sm')} />
        <ShadcnSkeleton className={cn(shimmerAnimation, 'h-3 w-12 mx-auto rounded-sm')} />
      </div>
    );
  }

  if (variant === 'table') {
    return (
      <div className={cn('space-y-2', className)}>
        {Array.from({ length: lines }).map((_, i) => (
          <div key={i} className="flex gap-2">
            <ShadcnSkeleton className={cn(shimmerAnimation, 'h-4 flex-[2] rounded-sm')} />
            <ShadcnSkeleton className={cn(shimmerAnimation, 'h-4 flex-1 rounded-sm')} />
            <ShadcnSkeleton className={cn(shimmerAnimation, 'h-4 flex-1 rounded-sm')} />
          </div>
        ))}
      </div>
    );
  }

  if (variant === 'circle') {
    return (
      <ShadcnSkeleton
        className={cn(shimmerAnimation, 'rounded-full', className)}
        style={{ width: width || '40px', height: height || '40px' }}
      />
    );
  }

  if (lines > 1) {
    return (
      <div className={cn('space-y-2', className)}>
        {Array.from({ length: lines }).map((_, i) => (
          <ShadcnSkeleton
            key={i}
            className={cn(shimmerAnimation, 'h-3 rounded-sm')}
            style={{ width: i === lines - 1 ? '70%' : '100%' }}
          />
        ))}
      </div>
    );
  }

  return (
    <ShadcnSkeleton
      className={cn(shimmerAnimation, 'h-3 rounded-sm inline-block', className)}
      style={{ width: width || '100%', height: height || '1em' }}
    />
  );
}

export function SkeletonCard({ className }: { className?: string }) {
  return <Skeleton variant="card" className={className} />;
}

export function SkeletonStat({ className }: { className?: string }) {
  return <Skeleton variant="stat" className={className} />;
}

export function SkeletonText({ lines = 3, className }: { lines?: number; className?: string }) {
  return <Skeleton variant="text" lines={lines} className={className} />;
}

export function SkeletonTable({ rows = 5, className }: { rows?: number; className?: string }) {
  return <Skeleton variant="table" lines={rows} className={className} />;
}

export function PageSkeleton({ className }: { className?: string }) {
  return (
    <div className={cn('space-y-6', className)} aria-label="Loading page content" role="status">
      <div className="flex items-center justify-between pb-4 border-b border-[var(--border-soft)]">
        <div className="flex items-center gap-3">
          <ShadcnSkeleton className={cn(shimmerAnimation, 'h-10 w-10 rounded-xl shrink-0')} />
          <div className="space-y-1.5">
            <ShadcnSkeleton className={cn(shimmerAnimation, 'h-5 w-40 rounded-sm')} />
            <ShadcnSkeleton className={cn(shimmerAnimation, 'h-3 w-56 rounded-sm')} />
          </div>
        </div>
        <ShadcnSkeleton className={cn(shimmerAnimation, 'h-9 w-28 rounded-lg')} />
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="rounded-xl border border-[var(--glass-border)] bg-[var(--glass-bg)] backdrop-blur-[var(--glass-blur)] shadow-[var(--glass-shadow)] p-5">
            <ShadcnSkeleton className={cn(shimmerAnimation, 'h-3 w-20 mb-3 rounded-sm')} />
            <ShadcnSkeleton className={cn(shimmerAnimation, 'h-7 w-14 rounded-sm')} />
          </div>
        ))}
      </div>
      <div className="rounded-xl border border-[var(--glass-border)] bg-[var(--glass-bg)] backdrop-blur-[var(--glass-blur)] shadow-[var(--glass-shadow)] p-5">
        <ShadcnSkeleton className={cn(shimmerAnimation, 'h-4 w-1/3 mb-4 rounded-sm')} />
        <div className="space-y-3">
          <Skeleton variant="card" />
          <Skeleton variant="card" />
        </div>
      </div>
    </div>
  );
}

function SkeletonGlassCard({ className }: { className?: string }) {
  return (
    <div
      className={cn(
        'rounded-xl border border-[var(--glass-border)] bg-[var(--glass-bg)]',
        'backdrop-blur-[var(--glass-blur)] shadow-[var(--glass-shadow)]',
        'p-5',
        className
      )}
    >
      <div className="flex items-center justify-between mb-3">
        <ShadcnSkeleton className={cn(shimmerAnimation, 'h-3 w-24 rounded-sm')} />
        <ShadcnSkeleton className={cn(shimmerAnimation, 'h-4 w-4 rounded-sm')} />
      </div>
      <div className="flex items-end gap-2">
        <ShadcnSkeleton className={cn(shimmerAnimation, 'h-8 w-16 rounded-sm')} />
        <ShadcnSkeleton className={cn(shimmerAnimation, 'h-3 w-12 rounded-sm mb-1')} />
      </div>
    </div>
  );
}

export function DashboardSkeleton({ className }: { className?: string }) {
  return (
    <div className={cn('space-y-6', className)} aria-label="Loading dashboard" role="status">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <SkeletonGlassCard key={i} />
        ))}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-4">
          <div className="rounded-xl border border-[var(--glass-border)] bg-[var(--glass-bg)] backdrop-blur-[var(--glass-blur)] shadow-[var(--glass-shadow)] p-5">
            <div className="flex items-center justify-between mb-6">
              <ShadcnSkeleton className={cn(shimmerAnimation, 'h-4 w-40 rounded-sm')} />
              <ShadcnSkeleton className={cn(shimmerAnimation, 'h-3 w-16 rounded-sm')} />
            </div>
            <div className="space-y-4">
              {Array.from({ length: 4 }).map((_, i) => (
                <div key={i} className="flex items-center gap-4">
                  <ShadcnSkeleton className={cn(shimmerAnimation, 'h-2.5 w-2.5 rounded-full shrink-0')} />
                  <div className="flex-1 space-y-1.5">
                    <ShadcnSkeleton className={cn(shimmerAnimation, 'h-3 w-32 rounded-sm')} />
                    <ShadcnSkeleton className={cn(shimmerAnimation, 'h-2.5 w-24 rounded-sm')} />
                  </div>
                  <ShadcnSkeleton className={cn(shimmerAnimation, 'h-2 w-24 rounded-sm')} />
                </div>
              ))}
            </div>
          </div>
        </div>
        <div className="space-y-6">
          <SkeletonGlassCard />
          <div className="rounded-xl border border-[var(--glass-border)] bg-[var(--glass-bg)] backdrop-blur-[var(--glass-blur)] shadow-[var(--glass-shadow)] p-5">
            <ShadcnSkeleton className={cn(shimmerAnimation, 'h-3 w-28 mb-4 rounded-sm')} />
            <div className="space-y-3">
              {Array.from({ length: 2 }).map((_, i) => (
                <div key={i} className={cn(shimmerAnimation, 'h-10 w-full rounded-lg')} />
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export function TableSkeleton({ rows = 5, className }: { rows?: number; className?: string }) {
  return (
    <div className={cn('space-y-4', className)} aria-label="Loading table data" role="status">
      <div className="flex items-center justify-between">
        <ShadcnSkeleton className={cn(shimmerAnimation, 'h-5 w-32 rounded-sm')} />
        <div className="flex gap-2">
          <ShadcnSkeleton className={cn(shimmerAnimation, 'h-8 w-24 rounded-lg')} />
          <ShadcnSkeleton className={cn(shimmerAnimation, 'h-8 w-24 rounded-lg')} />
        </div>
      </div>
      <div className="rounded-xl border border-[var(--glass-border)] bg-[var(--glass-bg)] backdrop-blur-[var(--glass-blur)] shadow-[var(--glass-shadow)] overflow-hidden">
        <div className="grid grid-cols-5 gap-4 p-4 border-b border-[var(--border)]">
          {Array.from({ length: 5 }).map((_, i) => (
            <ShadcnSkeleton key={i} className={cn(shimmerAnimation, 'h-3 rounded-sm')} style={{ width: `${60 + i * 8}px` }} />
          ))}
        </div>
        <div className="p-4 space-y-3">
          <SkeletonTable rows={rows} />
        </div>
      </div>
    </div>
  );
}

export function DetailSkeleton({ className }: { className?: string }) {
  return (
    <div className={cn('detail-skeleton', className)} aria-label="Loading details" role="status">
      <div className="skeleton-page-header">
        <ShadcnSkeleton className={cn(shimmerAnimation, 'h-4 w-1/4 mb-4 rounded-sm')} />
        <div className="flex gap-4">
          <ShadcnSkeleton className={cn(shimmerAnimation, 'h-9 w-[80px] rounded-sm')} />
          <ShadcnSkeleton className={cn(shimmerAnimation, 'h-9 w-[80px] rounded-sm')} />
        </div>
      </div>
      <div className="skeleton skeleton-card">
        <ShadcnSkeleton className={cn(shimmerAnimation, 'h-4 w-1/3 mb-4 rounded-sm')} />
        <div className="skeleton-info-grid">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="skeleton-info-item">
              <ShadcnSkeleton className={cn(shimmerAnimation, 'h-3 w-[80px] mb-1 rounded-sm')} />
              <ShadcnSkeleton className={cn(shimmerAnimation, 'h-3 w-[150px] rounded-sm')} />
            </div>
          ))}
        </div>
      </div>
      <div className="skeleton skeleton-card">
        <ShadcnSkeleton className={cn(shimmerAnimation, 'h-4 w-1/3 mb-4 rounded-sm')} />
        <ShadcnSkeleton className={cn(shimmerAnimation, 'h-3 w-full mb-2 rounded-sm')} />
        <ShadcnSkeleton className={cn(shimmerAnimation, 'h-3 w-full mb-2 rounded-sm')} />
        <ShadcnSkeleton className={cn(shimmerAnimation, 'h-3 w-3/5 rounded-sm')} />
      </div>
    </div>
  );
}

export function FindingsSkeleton({ rows = 5, className }: { rows?: number; className?: string }) {
  return (
    <div className={cn('findings-skeleton', className)} aria-label="Loading findings" role="status">
      <div className="skeleton-page-header">
        <ShadcnSkeleton className={cn(shimmerAnimation, 'h-4 w-1/5 mb-4 rounded-sm')} />
      </div>
      <div className="skeleton-filters">
        {Array.from({ length: 3 }).map((_, i) => (
   
          <ShadcnSkeleton key={i} className={cn(shimmerAnimation, 'h-9 w-[120px] rounded-sm')} />
        ))}
      </div>
      <SkeletonTable rows={rows} />
    </div>
  );
}
