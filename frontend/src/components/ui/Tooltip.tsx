// Re-export of Radix-based shadcn Tooltip.
// Preserves: TooltipProvider, Tooltip
// New: TooltipTrigger, TooltipContent (use these instead of content prop)
// Removed: useTooltip (imperative API), shortcut prop, position prop
// Migration: Replace <Tooltip content="..." /> with <TooltipProvider><TooltipTrigger><button /><TooltipContent>...</TooltipContent></TooltipTrigger></TooltipProvider>

import {
  TooltipProvider as ShadcnTooltipProvider,
  Tooltip as ShadcnTooltip,
  TooltipTrigger as ShadcnTooltipTrigger,
  TooltipContent as ShadcnTooltipContent,
} from '../ui-shadcn/tooltip';
import type { ReactNode } from 'react';

export { ShadcnTooltipProvider as TooltipProvider };
export { ShadcnTooltip as Tooltip };
export { ShadcnTooltipTrigger as TooltipTrigger };
export { ShadcnTooltipContent as TooltipContent };

// Legacy adapter: single-prop Tooltip for backward compatibility
interface LegacyTooltipProps {
  content: string;
  shortcut?: string;
  children: ReactNode;
  className?: string;
  position?: 'top' | 'bottom' | 'left' | 'right';
}

export function LegacyTooltip({ content, shortcut, children, className, position = 'top' }: LegacyTooltipProps) {
  const sideMap = { top: 'top', bottom: 'bottom', left: 'left', right: 'right' } as const;
  return (
    <ShadcnTooltip>
      <ShadcnTooltipTrigger asChild>
        <span className={className} tabIndex={0}>{children}</span>
      </ShadcnTooltipTrigger>
      <ShadcnTooltipContent side={sideMap[position]}>
        <p>{content}{shortcut && <kbd className="ml-1 text-xs opacity-60">{shortcut}</kbd>}</p>
      </ShadcnTooltipContent>
    </ShadcnTooltip>
  );
}

// useTooltip is removed — the old imperative show/hide API has no shadcn equivalent.
// If you need imperative control, use a state variable + open prop on Tooltip.
