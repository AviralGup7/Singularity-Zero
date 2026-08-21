import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { FindingsTablePane } from '@/features/findings/components/FindingsTablePane';
import type { Finding } from '@/types/api';

vi.mock('@/hooks/useToast', () => ({
  useToast: () => ({ success: vi.fn(), error: vi.fn(), info: vi.fn(), warning: vi.fn() }),
}));

vi.mock('@/api/client', () => ({
  bulkUpdateFindings: vi.fn().mockResolvedValue({}),
}));

function sampleFinding(id: string): Finding {
  return {
    id,
    type: 'xss',
    title: `Finding ${id}`,
    description: 'desc',
    severity: 'high',
    confidence: 0.8,
    timestamp: 1_700_000_000,
    lifecycle_state: 'detected',
    target: 'https://app.test',
    status: 'open',
  };
}

describe('FindingsTablePane', () => {
  it('renders table rows instead of a grid list', async () => {
    const onToggle = vi.fn();
    render(
      <FindingsTablePane
        findings={[sampleFinding('f1'), sampleFinding('f2')]}
        selectedIds={new Set()}
        onToggleSelect={onToggle}
        onSelectAll={vi.fn()}
        onClearSelection={vi.fn()}
        onOpenDetail={vi.fn()}
        bulkActionMode={null}
        setBulkActionMode={vi.fn()}
        bulkAssignee=""
        setBulkAssignee={vi.fn()}
        handleBulkStatus={vi.fn()}
        handleBulkFalsePositive={vi.fn()}
        handleBulkAssign={vi.fn()}
        handleBulkDelete={vi.fn()}
        sortKey="severity"
        sortDir="desc"
        onSort={vi.fn()}
      />,
    );

    expect(screen.getByRole('table')).toBeInTheDocument();
    expect(screen.getAllByRole('row').length).toBeGreaterThan(2);
    await userEvent.click(screen.getByLabelText('Select finding f1'));
    expect(onToggle).toHaveBeenCalledWith('f1');
  });
});
