import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Input } from './Input';

describe('Input', () => {
  it('renders input element', () => {
    render(<Input id="test" />);
    expect(screen.getByRole('textbox')).toBeInTheDocument();
  });

  it('renders label when provided', () => {
    render(<Input id="test" label="Test Label" />);
    expect(screen.getByText('Test Label')).toBeInTheDocument();
  });

  it('associates label with input', () => {
    render(<Input id="test" label="Test Label" />);
    const label = screen.getByText('Test Label');
    const input = screen.getByRole('textbox');
    expect(label).toHaveAttribute('for', 'test');
    expect(input).toHaveAttribute('id', 'test');
  });

  it('shows required indicator when required', () => {
    render(<Input id="test" label="Required" required />);
    expect(screen.getByText('*', { selector: 'span' })).toHaveClass('text-[var(--bad)]');
  });

  it('displays error message', () => {
    render(<Input id="test" error="This is an error" />);
    expect(screen.getByText('This is an error')).toBeInTheDocument();
    expect(screen.getByText('This is an error')).toHaveAttribute('role', 'alert');
  });

  it('applies error styling', () => {
    render(<Input id="test" error="Error" />);
    expect(screen.getByRole('textbox')).toHaveClass('border-[var(--bad)]');
  });

  it('shows helper text when no error', () => {
    render(<Input id="test" helperText="Helpful info" />);
    expect(screen.getByText('Helpful info')).toBeInTheDocument();
  });

  it('hides helper text when error present', () => {
    render(<Input id="test" helperText="Help" error="Error" />);
    expect(screen.queryByText('Help')).not.toBeInTheDocument();
    expect(screen.getByText('Error')).toBeInTheDocument();
  });

  it('sets aria-invalid when error', () => {
    render(<Input id="test" error="Invalid" />);
    expect(screen.getByRole('textbox')).toHaveAttribute('aria-invalid', 'true');
  });

  it('forwards ref to input element', () => {
    const ref = { current: null as HTMLInputElement | null };
    render(<Input id="test" ref={ref} />);
    expect(ref.current).toBeInstanceOf(HTMLInputElement);
  });

  it('accepts user input', async () => {
    const user = userEvent.setup();
    render(<Input id="test" />);
    const input = screen.getByRole('textbox');
    await user.type(input, 'hello');
    expect(input).toHaveValue('hello');
  });

  it('passes through additional props', () => {
    render(<Input id="test" placeholder="Enter text" />);
    expect(screen.getByRole('textbox')).toHaveAttribute('placeholder', 'Enter text');
  });

  it('applies custom className', () => {
    render(<Input id="test" className="custom-class" />);
    expect(screen.getByRole('textbox')).toHaveClass('custom-class');
  });
});
