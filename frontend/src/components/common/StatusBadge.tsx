import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const statusBadgeVariants = cva(
  "inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold tracking-wide transition-colors",
  {
    variants: {
      status: {
        critical: "bg-rose-500/15 text-rose-300 border border-rose-500/30",
        high: "bg-orange-500/15 text-orange-300 border border-orange-500/30",
        medium: "bg-amber-500/15 text-amber-300 border border-amber-500/30",
        low: "bg-blue-500/15 text-blue-300 border border-blue-500/30",
        info: "bg-slate-500/15 text-slate-300 border border-slate-500/30",
        success: "bg-emerald-500/15 text-emerald-500 border border-emerald-500/30",
        active: "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30",
        warning: "bg-amber-500/15 text-amber-400 border border-amber-500/30",
        danger: "bg-rose-500/15 text-rose-400 border border-rose-500/30",
        neutral: "bg-muted text-muted-foreground border border-border",
      },
    },
    defaultVariants: {
      status: "info",
    },
  }
);

export interface StatusBadgeProps extends React.HTMLAttributes<HTMLSpanElement>, VariantProps<typeof statusBadgeVariants> {
  label?: string;
  showDot?: boolean;
}

export function StatusBadge({ status, label, showDot = true, className, children, ...props }: StatusBadgeProps) {
  return (
    <span className={cn(statusBadgeVariants({ status }), className)} {...props}>
      {showDot && <span className="w-1.5 h-1.5 rounded-full bg-current" />}
      {label || children}
    </span>
  );
}
