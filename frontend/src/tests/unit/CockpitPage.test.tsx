import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { CockpitPage } from '@/pages/CockpitPage';
import React from 'react';

// Mock react-router-dom
const mockNavigate = vi.fn();
let mockSearchParams = new URLSearchParams();
vi.mock('react-router-dom', () => ({
  useNavigate: () => mockNavigate,
  useSearchParams: () => [mockSearchParams],
}));

// Mock useToast hook
vi.mock('@/hooks/useToast', () => ({
  useToast: () => ({
    success: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
    warning: vi.fn(),
  }),
}));

// Mock hooks
const mockUseCockpitData = vi.fn();
vi.mock('@/hooks/useCockpitData', () => ({
  useCockpitData: (opts: unknown) => mockUseCockpitData(opts),
  useActiveJob: (_id?: unknown) => ({
    activeJob: null,
    activeJobId: undefined,
    setActiveJobId: vi.fn(),
    setActiveJob: vi.fn(),
  }),
}));

// Mock 3D chart component
vi.mock('@/components/charts', () => ({
  AttackChainGraph3D: () => <div data-testid="attack-chain-graph-3d" />,
}));

// Mock layout/legend/sub-components
vi.mock('@/components/cockpit/GraphLegend', () => ({
  GraphLegend: () => <div data-testid="graph-legend" />,
}));
vi.mock('@/components/scope/ScopeComplianceBadge', () => ({
  ScopeWarningBanner: () => <div data-testid="scope-warning-banner" />,
}));

describe('CockpitPage', () => {
  it('renders standby view when target is empty', () => {
    mockSearchParams = new URLSearchParams(); // empty
    mockUseCockpitData.mockReturnValue({
      nodes: [],
      edges: [],
      chains: [],
      loading: false,
      applyGraph: vi.fn(),
      notes: [],
      setNotes: vi.fn(),
      exchanges: [],
      setExchanges: vi.fn(),
      meshHealth: null,
      migrations: [],
      handleMeshHealth: vi.fn(),
      handleMigrationEvent: vi.fn(),
    });

    render(<CockpitPage />);

    expect(screen.getByText('CYBER STEERING COCKPIT')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('e.g. https://example.com')).toBeInTheDocument();
    expect(screen.getByText('ENGAGE PIPELINE ENGINE')).toBeInTheDocument();
  });

  it('renders active dashboard when target is provided', () => {
    mockSearchParams = new URLSearchParams('target=https://example.com');
    mockUseCockpitData.mockReturnValue({
      nodes: [
        { id: 'node-1', type: 'finding', label: 'SQL Injection', severity: 'critical' },
      ],
      edges: [],
      chains: [],
      loading: false,
      applyGraph: vi.fn(),
      notes: [],
      setNotes: vi.fn(),
      exchanges: [],
      setExchanges: vi.fn(),
      meshHealth: null,
      migrations: [],
      handleMeshHealth: vi.fn(),
      handleMigrationEvent: vi.fn(),
    });

    render(<CockpitPage />);

    expect(screen.getByText('Steering Cockpit')).toBeInTheDocument();
    
    // Switch to 2D tab to view node labels as DOM text elements
    fireEvent.click(screen.getByText('[ 2D Node Grid ]'));
    expect(screen.getByText('SQL Injection')).toBeInTheDocument();
    expect(screen.getByText('[ 3D Threat Topology ]')).toBeInTheDocument();
  });
});
