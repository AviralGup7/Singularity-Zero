// Dropdown adapter — preserves the old trigger/children API but uses Radix dropdown-menu underneath.
// 0 consumers currently. Kept for backward compatibility.
import type { ReactNode } from 'react';
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuLabel,
} from '../ui-shadcn/dropdown-menu';

interface DropdownProps {
  trigger: ReactNode;
  children: ReactNode;
  align?: 'left' | 'right' | 'center';
  className?: string;
}

export function Dropdown({ trigger, children, align = 'left', className }: DropdownProps) {
  const alignMap = { left: 'start', right: 'end', center: 'center' } as const;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <span className="inline-block">{trigger}</span>
      </DropdownMenuTrigger>
  // eslint-disable-next-line security/detect-object-injection
      <DropdownMenuContent align={alignMap[align]} className={className}>
        {children}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

interface DropdownItemProps {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  className?: string;
}

export function DropdownItem({ children, onClick, disabled, className }: DropdownItemProps) {
  return (
    <DropdownMenuItem onClick={onClick} disabled={disabled} className={className}>
      {children}
    </DropdownMenuItem>
  );
}

export function DropdownDivider() {
  return <DropdownMenuSeparator />;
}

export { DropdownMenuLabel as DropdownLabel };
