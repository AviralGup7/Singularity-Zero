import type { Meta, StoryObj } from '@storybook/react-vite';
import { Input } from './Input';

const meta = {
  title: 'UI/Input',
  component: Input,
  parameters: {
    layout: 'centered',
  },
  tags: ['autodocs'],
  argTypes: {
    disabled: {
      control: 'boolean',
    },
  },
} satisfies Meta<typeof Input>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Basic: Story = {
  args: {
    id: 'basic-input',
    placeholder: 'Enter target URL...',
  },
};

export const WithLabel: Story = {
  args: {
    id: 'labeled-input',
    label: 'Target URL',
    placeholder: 'https://example.com',
  },
};

export const Required: Story = {
  args: {
    id: 'required-input',
    label: 'Target URL',
    required: true,
    placeholder: 'https://example.com',
  },
};

export const WithError: Story = {
  args: {
    id: 'error-input',
    label: 'Target URL',
    error: 'Invalid URL format',
    defaultValue: 'not-a-url',
  },
};

export const WithHelperText: Story = {
  args: {
    id: 'helper-input',
    label: 'Scan Depth',
    helperText: 'Maximum depth for recursive scanning (1-10)',
    placeholder: '5',
  },
};

export const Disabled: Story = {
  args: {
    id: 'disabled-input',
    label: 'API Key',
    value: 'sk-xxxxxxxxxxxx',
    disabled: true,
  },
};
