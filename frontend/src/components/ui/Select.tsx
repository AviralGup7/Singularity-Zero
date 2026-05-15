// Select adapter — preserves the old Select/Option API but uses Radix select underneath.
// 0 consumers currently. Kept for backward compatibility.
import type { ReactNode } from 'react';
import {
  Select as ShadcnSelect,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '../ui-shadcn/select';

interface SelectProps<T extends string = string> {
  children: ReactNode;
  value: T;
  onChange: (value: T) => void;
  className?: string;
  ariaLabel?: string;
  placeholder?: string;
}

export function Select<T extends string = string>({
  children,
  value,
  onChange,
  className,
  ariaLabel,
  placeholder = 'Select...',
}: SelectProps<T>) {
  // Children should be Option elements — we render them via ShadcnSelectItem
  return (
    <ShadcnSelect value={value} onValueChange={onChange}>
      <SelectTrigger className={className} aria-label={ariaLabel}>
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent>{children}</SelectContent>
    </ShadcnSelect>
  );
}

interface OptionProps {
  value: string;
  children: ReactNode;
  disabled?: boolean;
}

export function Option({ value, children, disabled }: OptionProps) {
  return (
    <SelectItem value={value} disabled={disabled}>
      {children}
    </SelectItem>
  );
}
