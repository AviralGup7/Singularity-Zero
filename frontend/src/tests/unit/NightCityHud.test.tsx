import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { NightCityHud } from '@/components/layout/NightCityHud';
import { APP_VERSION } from '@/config';

describe('NightCityHud', () => {
  it('paints generated stills as the world layer, minimap, and boot sequence', () => {
    const { container } = render(
      <NightCityHud
        sector="OPS"
        district="Dashboard"
        jobTitle="PIPELINE LIVE"
        jobObjective="Triage findings. Keep scans live."
        ready
      />,
    );

    const skyline = container.querySelector('.nc-world img');
    expect(skyline).toHaveAttribute('src', '/night-city/skyline.jpg');

    const circuit = container.querySelector('.nc-minimap img');
    expect(circuit).toHaveAttribute('src', '/night-city/circuit.jpg');

    const boot = container.querySelector('.nc-boot-art');
    expect(boot).toHaveAttribute('src', '/night-city/loading.jpg');

    const ring = container.querySelector('.nc-boot-ring');
    expect(ring).toHaveAttribute('src', '/night-city/hud-ring.jpg');
  });

  it('binds HUD chrome to console copy instead of a fake quest', () => {
    render(
      <NightCityHud
        sector="OPS"
        district="Dashboard"
        jobTitle="PIPELINE LIVE"
        jobObjective="Triage findings. Keep scans live."
        ready
      />,
    );

    expect(screen.getByText('Dashboard')).toBeTruthy();
    expect(screen.getByText('PIPELINE LIVE')).toBeTruthy();
    expect(screen.getByText('Triage findings. Keep scans live.')).toBeTruthy();
    expect(screen.getByText('Command Palette')).toBeTruthy();
    expect(screen.getByText(APP_VERSION)).toBeTruthy();
    expect(screen.getByText('LIVE')).toBeTruthy();
    expect(screen.queryByText('Meet Hanako at Embers.')).toBeNull();
  });
});
