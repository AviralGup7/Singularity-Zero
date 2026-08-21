import { describe, expect, it } from 'vitest';
import { useThemeStore } from '@/stores/themeStore';

describe('themeStore first-run default', () => {
  it('opens on Night City so generated stills are the first surface', () => {
    const preset = useThemeStore.getState().theme.preset;
    expect(preset).toBe('night-city');
    expect(useThemeStore.getState().theme.mode).toBe('dark');
  });
});
