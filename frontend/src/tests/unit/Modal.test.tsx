import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui-shadcn/dialog';

describe('Dialog primitives', () => {
  it('renders content and title when open', () => {
    render(
      <Dialog open>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Dialog Title</DialogTitle>
            <DialogDescription>Dialog Description</DialogDescription>
          </DialogHeader>
          <p>Dialog Content</p>
        </DialogContent>
      </Dialog>
    );

    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.getByText('Dialog Title')).toBeInTheDocument();
    expect(screen.getByText('Dialog Content')).toBeInTheDocument();
  });

  it('does not render content when closed', () => {
    render(
      <Dialog open={false}>
        <DialogContent>
          <DialogTitle>Hidden Title</DialogTitle>
        </DialogContent>
      </Dialog>
    );

    expect(screen.queryByText('Hidden Title')).not.toBeInTheDocument();
  });

  it('applies custom className on DialogContent', () => {
    render(
      <Dialog open>
        <DialogContent className="custom-dialog-content">
          <DialogTitle>Custom Class Dialog</DialogTitle>
          <DialogDescription>Dialog used for className testing.</DialogDescription>
        </DialogContent>
      </Dialog>
    );

    const panel = document.querySelector('.custom-dialog-content');
    expect(panel).not.toBeNull();
  });
});

describe('DialogHeader', () => {
  it('renders children', () => {
    render(
      <DialogHeader>
        <h2>Header</h2>
      </DialogHeader>
    );
    expect(screen.getByText('Header')).toBeInTheDocument();
  });

  it('applies custom className', () => {
    render(
      <DialogHeader className="custom-header">
        <h2>Custom Header</h2>
      </DialogHeader>
    );
    expect(screen.getByText('Custom Header').parentElement?.className).toContain('custom-header');
  });
});

describe('DialogFooter', () => {
  it('renders children', () => {
    render(
      <DialogFooter>
        <button>Action</button>
      </DialogFooter>
    );
    expect(screen.getByRole('button', { name: /action/i })).toBeInTheDocument();
  });

  it('applies custom className', () => {
    render(
      <DialogFooter className="custom-footer">
        <p>Footer</p>
      </DialogFooter>
    );
    expect(screen.getByText('Footer').parentElement?.className).toContain('custom-footer');
  });
});
