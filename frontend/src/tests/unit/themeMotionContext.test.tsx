import { render, screen, fireEvent } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { ThemeProvider, useTheme } from '@/context/ThemeContext';

function MotionContextProbe() {
  const { theme, updater } = useTheme();
  return (
    <div>
      <span data-testid="intensity">{theme.motionIntensity}</span>
      <span data-testid="capability">{theme.effectCapability}</span>
      <button onClick={() => updater.setMotionIntensity('low')}>set-low</button>
      <button onClick={() => updater.setEffectCapability('reduced')}>set-reduced</button>
    </div>
  );
}

describe('ThemeContext motion controls', () => {
  it('updates motion intensity and capability and writes DOM attributes', () => {
    render(
      <ThemeProvider>
        <MotionContextProbe />
      </ThemeProvider>
    );

    expect(screen.getByTestId('intensity').textContent).toBe('high');
    expect(screen.getByTestId('capability').textContent).toBe('auto');

    fireEvent.click(screen.getByText('set-low'));
    fireEvent.click(screen.getByText('set-reduced'));

    expect(screen.getByTestId('intensity').textContent).toBe('low');
    expect(screen.getByTestId('capability').textContent).toBe('reduced');
    expect(document.documentElement.getAttribute('data-motion-intensity')).toBe('low');
    expect(document.documentElement.getAttribute('data-effect-capability')).toBe('reduced');
  });
});
