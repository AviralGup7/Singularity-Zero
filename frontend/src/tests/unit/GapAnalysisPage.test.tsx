import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { GapAnalysisPage } from '../../pages/GapAnalysisPage';

const getGapAnalysisMock = vi.fn();
const refreshGapAnalysisMock = vi.fn();
const getTargetsMock = vi.fn();

vi.mock('../../api/client', () => ({
  getGapAnalysis: (...args: unknown[]) => getGapAnalysisMock(...args),
  refreshGapAnalysis: (...args: unknown[]) => refreshGapAnalysisMock(...args),
  getTargets: (...args: unknown[]) => getTargetsMock(...args),
  apiClient: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    interceptors: {
      request: { use: vi.fn(), eject: vi.fn() },
      response: { use: vi.fn(), eject: vi.fn() },
    },
  },
}));

// Mock Framer Motion to prevent animation timers in tests
vi.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: Record<string, unknown>) => <div {...props}>{children as React.ReactNode}</div>,
  },
  AnimatePresence: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

const mockGapData = {
  target: 'all',
  overall_coverage: 75,
  total_modules: 3,
  modules_with_gaps: 2,
  results: [
    {
      module: 'ssrf_candidate_finder',
      category: 'ssrf',
      total_checks: 4,
      covered_checks: 2,
      missing_checks: 2,
      coverage_percent: 50,
      status: 'partial',
      missing_check_details: ['Cloud metadata API check', 'DNS Rebinding check'],
    },
    {
      module: 'reflected_xss_probe',
      category: 'xss',
      total_checks: 8,
      covered_checks: 8,
      missing_checks: 0,
      coverage_percent: 100,
      status: 'complete',
      missing_check_details: [],
    },
    {
      module: 'idor_validation',
      category: 'idor',
      total_checks: 5,
      covered_checks: 0,
      missing_checks: 5,
      coverage_percent: 0,
      status: 'missing',
      missing_check_details: ['Cross-tenant harvesting check', 'UUID randomness check'],
    },
  ],
};

const mockTargets = {
  targets: [
    { name: 'example.com' },
    { name: 'test.org' },
  ],
};

describe('GapAnalysisPage Component', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    getTargetsMock.mockResolvedValue(mockTargets);
    getGapAnalysisMock.mockResolvedValue(mockGapData);
  });

  it('renders loading skeleton on mount', async () => {
    // Delay resolution to capture loading skeleton
    let resolveGap: (value: unknown) => void;
    const promise = new Promise((resolve) => {
      resolveGap = resolve;
    });
    getGapAnalysisMock.mockReturnValue(promise);

    let result: ReturnType<typeof render>;
    await act(async () => {
      result = render(<GapAnalysisPage />);
    });

    // Skeletons are rendered by default
    const skeletons = document.querySelectorAll('[class*="bg-[var(--panel-2)]"]');
    expect(skeletons.length).toBeGreaterThan(0);

    // Clean up
    resolveGap!(mockGapData);
    await act(async () => {});
    result!.unmount();
  });

  it('renders stats card data and target choices successfully', async () => {
    render(<GapAnalysisPage />);

    await waitFor(() => {
      expect(screen.getByText('Detection Gap Analysis')).toBeInTheDocument();
    });

    expect(screen.getByText('75%')).toBeInTheDocument();
    expect(screen.getByText('1')).toBeInTheDocument(); // 3 - 2 OK = 1
    expect(screen.getByText('2')).toBeInTheDocument(); // Modules with gaps count

    expect(screen.getByText('ssrf_candidate_finder')).toBeInTheDocument();
    expect(screen.getByText('reflected_xss_probe')).toBeInTheDocument();
    expect(screen.getByText('idor_validation')).toBeInTheDocument();
  });

  it('filters rows based on search query', async () => {
    render(<GapAnalysisPage />);

    await waitFor(() => {
      expect(screen.getByText('ssrf_candidate_finder')).toBeInTheDocument();
    });

    const searchInput = screen.getByPlaceholderText('Filter by module or category...');
    fireEvent.change(searchInput, { target: { value: 'idor' } });

    await waitFor(() => {
      expect(screen.queryByText('ssrf_candidate_finder')).not.toBeInTheDocument();
      expect(screen.queryByText('reflected_xss_probe')).not.toBeInTheDocument();
      expect(screen.getByText('idor_validation')).toBeInTheDocument();
    });
  });

  it('filters rows based on status dropdown selection', async () => {
    render(<GapAnalysisPage />);

    await waitFor(() => {
      expect(screen.getByText('ssrf_candidate_finder')).toBeInTheDocument();
    });

    const statusDropdown = screen.getByLabelText('Filter Status');
    fireEvent.change(statusDropdown, { target: { value: 'complete' } });

    await waitFor(() => {
      expect(screen.queryByText('ssrf_candidate_finder')).not.toBeInTheDocument();
      expect(screen.getByText('reflected_xss_probe')).toBeInTheDocument();
      expect(screen.queryByText('idor_validation')).not.toBeInTheDocument();
    });
  });

  it('sorts rows when column headers are clicked', async () => {
    render(<GapAnalysisPage />);

    await waitFor(() => {
      expect(screen.getByText('ssrf_candidate_finder')).toBeInTheDocument();
    });

    // Default sorting is by module name alphabetically
    const firstRowText = document.querySelector('tbody tr td div')?.textContent;
    expect(firstRowText).toBe('idor_validation'); // 'i' comes first

    const moduleHeader = screen.getByRole('columnheader', { name: /^Module/i });
    // Click module header to reverse sort order
    fireEvent.click(moduleHeader);

    const reversedRowText = document.querySelector('tbody tr td div')?.textContent;
    expect(reversedRowText).toBe('ssrf_candidate_finder'); // 's' comes last
  });

  it('handles API errors gracefully and lets users trigger recovery with try again button', async () => {
    getGapAnalysisMock.mockRejectedValueOnce(new Error('API Rate Limit reached'));

    render(<GapAnalysisPage />);

    await waitFor(() => {
      expect(screen.getByText(/Failed to load gap analysis data/i)).toBeInTheDocument();
    });

    // Empty state should NOT be displayed when error alert is visible
    expect(screen.queryByText(/No modules found/i)).not.toBeInTheDocument();

    // Now Mock successful resolution on the retry
    getGapAnalysisMock.mockResolvedValue(mockGapData);

    const retryBtn = screen.getByRole('button', { name: /Try Again/i });
    fireEvent.click(retryBtn);

    await waitFor(() => {
      expect(screen.getByText('ssrf_candidate_finder')).toBeInTheDocument();
    });

    expect(screen.queryByText(/Failed to load gap analysis data/i)).not.toBeInTheDocument();
  });

  it('triggers gap analysis refresh successfully', async () => {
    refreshGapAnalysisMock.mockResolvedValue({ status: 'Analysis refresh triggered' });

    await act(async () => {
      render(<GapAnalysisPage />);
    });

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Refresh Analysis/i })).toBeInTheDocument();
    });

    await act(async () => {
      const refreshBtn = screen.getByRole('button', { name: /Refresh Analysis/i });
      fireEvent.click(refreshBtn);
    });

    expect(refreshGapAnalysisMock).toHaveBeenCalledTimes(1);
  });
});
