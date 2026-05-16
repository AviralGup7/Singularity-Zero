import type { Meta, StoryObj } from '@storybook/react-vite';
import { SeverityBadge } from './SeverityBadge';

const meta = {
  title: 'UI/SeverityBadge',
  component: SeverityBadge,
  parameters: {
    layout: 'centered',
  },
   
  tags: ['autodocs'],
  argTypes: {
    severity: {
      control: 'select',
   
      options: ['critical', 'high', 'medium', 'low', 'info'],
    },
    count: {
      control: 'number',
    },
    showIcon: {
      control: 'boolean',
    },
  },
} satisfies Meta<typeof SeverityBadge>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Critical: Story = {
  args: {
    severity: 'critical',
    count: 5,
  },
};

export const High: Story = {
  args: {
    severity: 'high',
    count: 12,
  },
};

export const Medium: Story = {
  args: {
    severity: 'medium',
    count: 23,
  },
};

export const Low: Story = {
  args: {
    severity: 'low',
    count: 8,
  },
};

export const Info: Story = {
  args: {
    severity: 'info',
    count: 42,
  },
};

export const AllSeverities: Story = {
  args: { severity: 'critical', count: 5 },
  render: () => (
    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
      <SeverityBadge severity="critical" count={5} />
      <SeverityBadge severity="high" count={12} />
      <SeverityBadge severity="medium" count={23} />
      <SeverityBadge severity="low" count={8} />
      <SeverityBadge severity="info" count={42} />
    </div>
  ),
};

export const WithoutCount: Story = {
  args: {
    severity: 'critical',
  },
};
