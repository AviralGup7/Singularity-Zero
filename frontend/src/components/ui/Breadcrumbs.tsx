// Breadcrumbs adapter — preserves the array-based items API but uses Radix breadcrumb underneath.
// 0 consumers currently. Kept for backward compatibility.
import { Link } from 'react-router-dom';
import { cn } from '@/lib/utils';
import {
  Breadcrumb,
  BreadcrumbList,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbSeparator,
  BreadcrumbPage,
  BreadcrumbEllipsis,
} from '../ui-shadcn/breadcrumb';

export interface BreadcrumbItem {
  label: string;
  href?: string;
  isCurrent?: boolean;
}

export interface BreadcrumbsProps {
  items: BreadcrumbItem[];
  className?: string;
  homeHref?: string;
  showHome?: boolean;
}

export function Breadcrumbs({ items, className, homeHref = '/', showHome = true }: BreadcrumbsProps) {
  if (items.length === 0 && !showHome) return null;

   
  const allItems: BreadcrumbItem[] = [];
  if (showHome) allItems.push({ label: 'Home', href: homeHref });
  allItems.push(...items);
  if (allItems.length <= 1) return null;

  const lastIndex = allItems.length - 1;

  return (
   
    <Breadcrumb className={cn('font-mono text-[length:var(--text-sm)]', className)}>
      <BreadcrumbList>
        {allItems.map((item, i) => (
          <BreadcrumbItem key={i}>
            {i === lastIndex || item.isCurrent ? (
              <BreadcrumbPage>{item.label}</BreadcrumbPage>
            ) : item.href ? (
              <BreadcrumbLink asChild>
                <Link to={item.href}>{item.label}</Link>
              </BreadcrumbLink>
            ) : (
              <BreadcrumbLink>{item.label}</BreadcrumbLink>
            )}
            {i < lastIndex && <BreadcrumbSeparator />}
          </BreadcrumbItem>
        ))}
      </BreadcrumbList>
    </Breadcrumb>
  );
}

export { BreadcrumbEllipsis };
