import { cn } from '@/lib/utils';

export interface SkeletonProps {
  variant?: 'text' | 'card' | 'stat' | 'table' | 'circle';
  width?: string;
  height?: string;
  lines?: number;
  className?: string;
}

const shimmerAnimation =
   
  'relative overflow-hidden bg-[var(--panel-2)] before:absolute before:inset-0 before:-translate-x-full before:animate-[shimmer_2s_infinite] before:bg-gradient-to-r before:from-transparent before:via-[var(--panel-3)]/50 before:to-transparent';

export function Skeleton({ variant = 'text', width, height, lines = 1, className }: SkeletonProps) {
  if (variant === 'card') {
    return (
   
      <div className={cn('p-4 border border-[var(--line)] bg-[var(--panel)] rounded-sm', className)}>
        <div className={cn(shimmerAnimation, 'h-4 w-3/4 mb-3 rounded-sm')} />
        <div className={cn(shimmerAnimation, 'h-3 w-full mb-2 rounded-sm')} />
        <div className={cn(shimmerAnimation, 'h-3 w-1/2 rounded-sm')} />
      </div>
    );
  }

  if (variant === 'stat') {
    return (
      <div className={cn('text-center', className)}>
        <div className={cn(shimmerAnimation, 'h-6 w-16 mx-auto mb-1 rounded-sm')} />
        <div className={cn(shimmerAnimation, 'h-3 w-12 mx-auto rounded-sm')} />
      </div>
    );
  }

  if (variant === 'table') {
    return (
      <div className={cn('space-y-2', className)}>
        {Array.from({ length: lines }).map((_, i) => (
          <div key={i} className="flex gap-2">
  // eslint-disable-next-line security/detect-object-injection
            <div className={cn(shimmerAnimation, 'h-4 flex-[2] rounded-sm')} />
            <div className={cn(shimmerAnimation, 'h-4 flex-1 rounded-sm')} />
            <div className={cn(shimmerAnimation, 'h-4 flex-1 rounded-sm')} />
          </div>
        ))}
      </div>
    );
  }

  if (variant === 'circle') {
    return (
      <div
        className={cn(shimmerAnimation, 'rounded-full', className)}
        style={{ width: width || '40px', height: height || '40px' }}
      />
    );
  }

  if (lines > 1) {
    return (
      <div className={cn('space-y-2', className)}>
        {Array.from({ length: lines }).map((_, i) => (
          <div
            key={i}
            className={cn(shimmerAnimation, 'h-3 rounded-sm')}
            style={{ width: i === lines - 1 ? '70%' : '100%' }}
          />
        ))}
      </div>
    );
  }

  return (
    <div
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
    <div className={cn('page-skeleton', className)} aria-label="Loading page content" role="status">
      <div className="skeleton-page-header">
        <div className={cn(shimmerAnimation, 'h-4 w-2/5 mb-4 rounded-sm')} />
        <div className="flex gap-4">
          {Array.from({ length: 3 }).map((_, i) => (
   
            <div key={i} className={cn(shimmerAnimation, 'h-8 w-[60px] rounded-sm')} />
          ))}
        </div>
      </div>
      <div className="skeleton-page-content">
        <Skeleton variant="card" />
        <Skeleton variant="card" />
      </div>
    </div>
  );
}

export function DashboardSkeleton({ className }: { className?: string }) {
  return (
    <div className={cn('dashboard-skeleton', className)} aria-label="Loading dashboard" role="status">
      <div className="hero-stats skeleton-hero-stats">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} variant="stat" />
        ))}
      </div>
      <div className="quick-links skeleton-quick-links">
        <Skeleton variant="card" />
        <Skeleton variant="card" />
      </div>
      <Skeleton variant="card" />
      <SkeletonTable rows={3} />
      <SkeletonTable rows={3} />
    </div>
  );
}

export function TableSkeleton({ rows = 5, className }: { rows?: number; className?: string }) {
  return (
    <div className={cn('table-skeleton', className)} aria-label="Loading table data" role="status">
      <div className="skeleton-page-header">
  // eslint-disable-next-line security/detect-object-injection
        <div className={cn(shimmerAnimation, 'h-4 w-[30%] mb-4 rounded-sm')} />
  // eslint-disable-next-line security/detect-object-injection
        <div className={cn(shimmerAnimation, 'h-9 w-[200px] rounded-sm')} />
      </div>
      <div className="skeleton-table-wrapper">
        <div className="skeleton-table-header">
          {Array.from({ length: 5 }).map((_, i) => (
   
            <div key={i} className={cn(shimmerAnimation, `h-4 w-[${60 + i * 20}px] rounded-sm`)} />
          ))}
        </div>
        <SkeletonTable rows={rows} />
      </div>
    </div>
  );
}

export function DetailSkeleton({ className }: { className?: string }) {
  return (
    <div className={cn('detail-skeleton', className)} aria-label="Loading details" role="status">
      <div className="skeleton-page-header">
        <div className={cn(shimmerAnimation, 'h-4 w-1/4 mb-4 rounded-sm')} />
        <div className="flex gap-4">
  // eslint-disable-next-line security/detect-object-injection
          <div className={cn(shimmerAnimation, 'h-9 w-[80px] rounded-sm')} />
  // eslint-disable-next-line security/detect-object-injection
          <div className={cn(shimmerAnimation, 'h-9 w-[80px] rounded-sm')} />
        </div>
      </div>
      <div className="skeleton skeleton-card">
        <div className={cn(shimmerAnimation, 'h-4 w-1/3 mb-4 rounded-sm')} />
        <div className="skeleton-info-grid">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="skeleton-info-item">
  // eslint-disable-next-line security/detect-object-injection
              <div className={cn(shimmerAnimation, 'h-3 w-[80px] mb-1 rounded-sm')} />
  // eslint-disable-next-line security/detect-object-injection
              <div className={cn(shimmerAnimation, 'h-3 w-[150px] rounded-sm')} />
            </div>
          ))}
        </div>
      </div>
      <div className="skeleton skeleton-card">
        <div className={cn(shimmerAnimation, 'h-4 w-1/3 mb-4 rounded-sm')} />
        <div className={cn(shimmerAnimation, 'h-3 w-full mb-2 rounded-sm')} />
        <div className={cn(shimmerAnimation, 'h-3 w-full mb-2 rounded-sm')} />
        <div className={cn(shimmerAnimation, 'h-3 w-3/5 rounded-sm')} />
      </div>
    </div>
  );
}

export function FindingsSkeleton({ rows = 5, className }: { rows?: number; className?: string }) {
  return (
    <div className={cn('findings-skeleton', className)} aria-label="Loading findings" role="status">
      <div className="skeleton-page-header">
        <div className={cn(shimmerAnimation, 'h-4 w-1/5 mb-4 rounded-sm')} />
      </div>
      <div className="skeleton-filters">
        {Array.from({ length: 3 }).map((_, i) => (
   
          <div key={i} className={cn(shimmerAnimation, 'h-9 w-[120px] rounded-sm')} />
        ))}
      </div>
      <SkeletonTable rows={rows} />
    </div>
  );
}
