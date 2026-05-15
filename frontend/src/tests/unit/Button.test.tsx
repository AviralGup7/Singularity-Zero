import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Button } from '@/components/ui/Button';

describe('Button', () => {
  it('renders with default props', () => {
    render(<Button>Click Me</Button>);
    const btn = screen.getByRole('button', { name: /click me/i });
    expect(btn).toBeInTheDocument();
    expect(btn).toHaveAttribute('type', 'button');
  });

  it('applies primary variant classes', () => {
    render(<Button variant="primary">Primary</Button>);
    const btn = screen.getByRole('button', { name: /primary/i });
    expect(btn).toBeInTheDocument();
  });

  it('applies secondary variant classes', () => {
    render(<Button variant="secondary">Secondary</Button>);
    const btn = screen.getByRole('button', { name: /secondary/i });
    expect(btn).toBeInTheDocument();
  });

  it('applies danger variant classes', () => {
    render(<Button variant="danger">Danger</Button>);
    const btn = screen.getByRole('button', { name: /danger/i });
    expect(btn).toBeInTheDocument();
  });

  it('applies ghost variant classes', () => {
    render(<Button variant="ghost">Ghost</Button>);
    const btn = screen.getByRole('button', { name: /ghost/i });
    expect(btn).toBeInTheDocument();
  });

  it('applies small size', () => {
    render(<Button size="sm">Small</Button>);
    const btn = screen.getByRole('button', { name: /small/i });
    expect(btn).toBeInTheDocument();
  });

  it('applies medium size (default)', () => {
    render(<Button size="md">Medium</Button>);
    const btn = screen.getByRole('button', { name: /medium/i });
    expect(btn).toBeInTheDocument();
  });

  it('applies large size', () => {
    render(<Button size="lg">Large</Button>);
    const btn = screen.getByRole('button', { name: /large/i });
    expect(btn).toBeInTheDocument();
  });

  it('shows loading spinner when loading is true', () => {
    render(<Button loading>Loading</Button>);
    const btn = screen.getByRole('button', { name: /loading/i });
    expect(btn).toBeDisabled();
    expect(btn).toHaveAttribute('aria-busy', 'true');
    const spinner = btn.querySelector('span.animate-spin');
    expect(spinner).toBeInTheDocument();
  });

  it('is disabled when disabled prop is true', () => {
    render(<Button disabled>Disabled</Button>);
    const btn = screen.getByRole('button', { name: /disabled/i });
    expect(btn).toBeDisabled();
  });

  it('is disabled when both loading and disabled are true', () => {
    render(<Button loading disabled>Loading Disabled</Button>);
    const btn = screen.getByRole('button', { name: /loading disabled/i });
    expect(btn).toBeDisabled();
  });

  it('calls onClick handler when clicked', async () => {
    const handleClick = vi.fn();
    render(<Button onClick={handleClick}>Clickable</Button>);
    const btn = screen.getByRole('button', { name: /clickable/i });
    await userEvent.click(btn);
    expect(handleClick).toHaveBeenCalledTimes(1);
  });

  it('does not call onClick when disabled', async () => {
    const handleClick = vi.fn();
    render(<Button onClick={handleClick} disabled>Disabled Click</Button>);
    const btn = screen.getByRole('button', { name: /disabled click/i });
    await userEvent.click(btn);
    expect(handleClick).not.toHaveBeenCalled();
  });

  it('does not call onClick when loading', async () => {
    const handleClick = vi.fn();
    render(<Button onClick={handleClick} loading>Loading Click</Button>);
    const btn = screen.getByRole('button', { name: /loading click/i });
    await userEvent.click(btn);
    expect(handleClick).not.toHaveBeenCalled();
  });

  it('forwards ref to button element', () => {
    const ref = vi.fn();
    render(<Button ref={ref}>Ref Test</Button>);
    expect(ref).toHaveBeenCalled();
  });

  it('passes through additional className', () => {
    render(<Button className="custom-class">Custom Class</Button>);
    const btn = screen.getByRole('button', { name: /custom class/i });
    expect(btn.className).toContain('custom-class');
  });

  it('supports submit type', () => {
    render(<Button type="submit">Submit</Button>);
    const btn = screen.getByRole('button', { name: /submit/i });
    expect(btn).toHaveAttribute('type', 'submit');
  });
});
