import { forwardRef } from 'react';
import { Slot } from '@radix-ui/react-slot';
import { cn } from '@/lib/utils';
import { buttonVariants } from '@/components/ui-shadcn/button';

export type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'ghost' | 'gradient';
export type ButtonSize = 'sm' | 'md' | 'lg';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  asChild?: boolean;
  children: React.ReactNode;
}

const variantToShadcn: Record<ButtonVariant, 'default' | 'secondary' | 'destructive' | 'ghost'> = {
  primary: 'default',
  secondary: 'secondary',
  danger: 'destructive',
  ghost: 'ghost',
  gradient: 'default',
};

const sizeToShadcn: Record<ButtonSize, 'default' | 'sm' | 'lg'> = {
  sm: 'sm',
  md: 'default',
  lg: 'lg',
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      variant = 'primary',
      size = 'md',
      loading = false,
      asChild = false,
      className,
      children,
      disabled,
      type = 'button',
      ...props
    },
    ref
  ) => {
    const Comp = asChild ? Slot : 'button';
    return (
      <Comp
        ref={ref}
        type={asChild ? undefined : type}
        disabled={asChild ? undefined : disabled || loading}
        className={cn(
          buttonVariants({ variant: variantToShadcn[variant], size: sizeToShadcn[size] }),
          variant === 'gradient' && 'text-white border-0 bg-[linear-gradient(135deg,var(--neon-cyan),var(--accent),var(--accent-2))] [background-size:200%_200%] hover:[background-position:100%_100%] hover:shadow-[0_0_20px_rgba(59,130,246,0.3)]',
          loading && 'relative',
          className
        )}
        aria-busy={loading}
        {...props}
      >
        {loading && (
          <span
            className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent"
            aria-hidden="true"
          />
        )}
        {children}
      </Comp>
    );
  }
);

Button.displayName = 'Button';
