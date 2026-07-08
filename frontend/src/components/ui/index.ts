// ── Core UI Primitives ─────────────────────────────────────
export { Button, type ButtonProps, type ButtonVariant, type ButtonSize } from './Button';
export { Badge, type BadgeProps, type BadgeVariant } from './Badge';
export { Input, type InputProps } from './Input';
export { ConfirmDialog, type ConfirmDialogProps, type ConfirmDialogVariant } from './ConfirmDialog';
export { SeverityBadge, type SeverityBadgeProps, type SeverityLevel } from './SeverityBadge';
export { DataTable, type DataTableProps, type Column } from './DataTable';
export { Skeleton, SkeletonCard, SkeletonStat, SkeletonText, SkeletonTable, DashboardSkeleton, PageSkeleton, TableSkeleton, type SkeletonProps } from './Skeleton';
export { EmptyState, type EmptyStateProps } from './EmptyState';
export { Breadcrumbs, type BreadcrumbsProps, type BreadcrumbItem } from './Breadcrumbs';
// Re-export shadcn primitives in place of deleted legacy wrappers
export { Tooltip, TooltipTrigger, TooltipContent, TooltipProvider } from '@/components/ui-shadcn/tooltip';
export { Select, SelectGroup, SelectValue, SelectTrigger, SelectContent, SelectLabel, SelectItem, SelectSeparator } from '@/components/ui-shadcn/select';
export { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui-shadcn/tabs';
export { DropdownMenu as Dropdown, DropdownMenuTrigger as DropdownTrigger, DropdownMenuContent as DropdownContent, DropdownMenuItem as DropdownItem, DropdownMenuSeparator as DropdownDivider } from '@/components/ui-shadcn/dropdown-menu';

// ── Data Display Components ────────────────────────────────
export { Progress, type ProgressProps } from './Progress';
export { Pagination, type PaginationProps } from './Pagination';
export { GlassCard, type GlassCardProps } from './GlassCard';
export { AnimatedCounter, type AnimatedCounterProps } from './AnimatedCounter';
export { GlowProgress, type GlowProgressProps } from './GlowProgress';
export { PageHeader, type PageHeaderProps } from './PageHeader';

// ── Radix-based UI Primitives (ui-shadcn) ──────────────────
// Import directly: import { Dialog, Sheet, Command } from '@/components/ui-shadcn'

// ── Overhaul Auto-exports ──────────────────────────────────
export * from './Toast';
export * from './FormField';
export * from './CopyButton';
export * from './AccessibleEmoji';
export * from './Icon';
export * from './FocusTrap';
export * from './ErrorBoundary';
export * from './ErrorOverlayView';
