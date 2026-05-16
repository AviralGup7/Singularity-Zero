import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DataTable } from '@/components/ui/DataTable';

interface TestItem {
  id: string;
  name: string;
  status: string;
  priority: number;
}

const testColumns = [
  { key: 'id', header: 'ID', sortable: true },
  { key: 'name', header: 'Name', sortable: true },
  { key: 'status', header: 'Status' },
  { key: 'priority', header: 'Priority', sortable: true },
];

const testData: TestItem[] = [
  { id: '1', name: 'Alpha', status: 'active', priority: 1 },
  { id: '2', name: 'Beta', status: 'inactive', priority: 2 },
  { id: '3', name: 'Gamma', status: 'active', priority: 3 },
];

describe('DataTable', () => {
  it('renders column headers', () => {
    render(
      <DataTable
        columns={testColumns}
        data={testData}
        getRowKey={(item) => item.id}
      />
    );
    expect(screen.getByText('ID')).toBeInTheDocument();
    expect(screen.getByText('Name')).toBeInTheDocument();
    expect(screen.getByText('Status')).toBeInTheDocument();
    expect(screen.getByText('Priority')).toBeInTheDocument();
  });

  it('renders data rows', () => {
    render(
      <DataTable
        columns={testColumns}
        data={testData}
        getRowKey={(item) => item.id}
      />
    );
    expect(screen.getByText('Alpha')).toBeInTheDocument();
    expect(screen.getByText('Beta')).toBeInTheDocument();
    expect(screen.getByText('Gamma')).toBeInTheDocument();
  });

  it('shows empty message when no data', () => {
    render(
      <DataTable
        columns={testColumns}
        data={[]}
        getRowKey={(item: TestItem) => item.id}
        emptyMessage="No items found"
      />
    );
    expect(screen.getByText('No items found')).toBeInTheDocument();
  });

  it('shows loading skeleton when loading', () => {
    render(
      <DataTable
        columns={testColumns}
        data={testData}
        getRowKey={(item) => item.id}
        loading={true}
      />
    );
    expect(screen.getByRole('status')).toBeInTheDocument();
  });

  it('sorts data when sortable column is clicked', async () => {
    render(
      <DataTable
        columns={testColumns}
        data={testData}
        getRowKey={(item) => item.id}
      />
    );
    const nameHeader = screen.getByText('Name');
    await userEvent.click(nameHeader);
    const rows = screen.getAllByRole('row');
   
    expect(rows[1]).toHaveTextContent('Alpha');
  });

  it('paginates data', () => {
    const largeData: TestItem[] = Array.from({ length: 25 }, (_, i) => ({
      id: String(i + 1),
      name: `Item ${i + 1}`,
      status: 'active',
      priority: i + 1,
    }));

    render(
      <DataTable
        columns={testColumns}
        data={largeData}
        getRowKey={(item) => item.id}
        pageSize={10}
      />
    );

    expect(screen.getByText('Page 1 of 3')).toBeInTheDocument();
    expect(screen.getByText('(25 items)')).toBeInTheDocument();
  });

  it('navigates between pages', async () => {
    const largeData: TestItem[] = Array.from({ length: 15 }, (_, i) => ({
      id: String(i + 1),
      name: `Item ${i + 1}`,
      status: 'active',
      priority: i + 1,
    }));

    render(
      <DataTable
        columns={testColumns}
        data={largeData}
        getRowKey={(item) => item.id}
        pageSize={10}
      />
    );

    const nextButton = screen.getByLabelText('Next page');
    await userEvent.click(nextButton);
    expect(screen.getByText('Page 2 of 2')).toBeInTheDocument();
  });

  it('handles row click', async () => {
    const handleRowClick = vi.fn();
    render(
      <DataTable
        columns={testColumns}
        data={testData}
        getRowKey={(item) => item.id}
        onRowClick={handleRowClick}
      />
    );

    const firstRow = screen.getByText('Alpha').closest('tr');
    if (firstRow) {
      await userEvent.click(firstRow);
    }
   
    expect(handleRowClick).toHaveBeenCalledWith(testData[0]);
  });

  it('renders custom cell content with render function', () => {
    const columnsWithRender = [
      {
        key: 'name',
        header: 'Name',
        render: (item: TestItem) => `Custom: ${item.name}`,
      },
    ];

    render(
      <DataTable
        columns={columnsWithRender}
        data={testData}
        getRowKey={(item) => item.id}
      />
    );

    expect(screen.getByText('Custom: Alpha')).toBeInTheDocument();
  });

  it('applies custom className', () => {
    render(
      <DataTable
        columns={testColumns}
        data={testData}
        getRowKey={(item) => item.id}
        className="custom-table"
      />
    );
    const container = screen.getByText('ID').closest('.custom-table');
    expect(container).not.toBeNull();
  });
});
