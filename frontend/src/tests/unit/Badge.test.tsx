import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Badge } from '@/components/ui/Badge';

describe('Badge', () => {
  it('renders children', () => {
    render(<Badge>Test Badge</Badge>);
    expect(screen.getByText('Test Badge')).toBeInTheDocument();
  });

  it('renders with critical variant', () => {
    render(<Badge variant="critical">Critical</Badge>);
    const badge = screen.getByText('Critical');
    expect(badge).toHaveAttribute('role', 'status');
  });

  it('renders with high variant', () => {
    render(<Badge variant="high">High</Badge>);
    expect(screen.getByText('High')).toBeInTheDocument();
  });

  it('renders with medium variant', () => {
    render(<Badge variant="medium">Medium</Badge>);
    expect(screen.getByText('Medium')).toBeInTheDocument();
  });

  it('renders with low variant', () => {
    render(<Badge variant="low">Low</Badge>);
    expect(screen.getByText('Low')).toBeInTheDocument();
  });

  it('renders with info variant (default)', () => {
    render(<Badge>Info</Badge>);
    expect(screen.getByText('Info')).toBeInTheDocument();
  });

  it('renders with status variant - running', () => {
    render(<Badge variant="status" status="running">Running</Badge>);
    expect(screen.getByText('Running')).toBeInTheDocument();
  });

  it('renders with status variant - completed', () => {
    render(<Badge variant="status" status="completed">Completed</Badge>);
    expect(screen.getByText('Completed')).toBeInTheDocument();
  });

  it('renders with status variant - failed', () => {
    render(<Badge variant="status" status="failed">Failed</Badge>);
    expect(screen.getByText('Failed')).toBeInTheDocument();
  });

  it('renders with status variant - stopped', () => {
    render(<Badge variant="status" status="stopped">Stopped</Badge>);
    expect(screen.getByText('Stopped')).toBeInTheDocument();
  });

  it('renders with status variant - queued', () => {
    render(<Badge variant="status" status="queued">Queued</Badge>);
    expect(screen.getByText('Queued')).toBeInTheDocument();
  });

  it('applies custom className', () => {
    render(<Badge className="custom-badge">Custom</Badge>);
    const badge = screen.getByText('Custom');
    expect(badge.className).toContain('custom-badge');
  });
});
