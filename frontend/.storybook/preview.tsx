import type { Preview } from '@storybook/react-vite'
import '../src/styles/index.css'

const preview: Preview = {
  parameters: {
    controls: {
      matchers: {
       color: /(background|color)$/i,
       date: /Date$/i,
      },
    },

    a11y: {
      test: 'todo'
    },

    backgrounds: {
      default: 'cyberpunk-dark',
      values: [
        { name: 'cyberpunk-dark', value: '#030014' },
        { name: 'cyberpunk-panel', value: 'rgba(5, 5, 20, 0.8)' },
        { name: 'light', value: '#faf6f1' },
      ],
    },
  },

  decorators: [
    (Story) => (
      <div style={{
        background: 'var(--bg)',
        color: 'var(--text)',
        minHeight: '100vh',
        padding: '20px',
        fontFamily: "'Rajdhani', 'Segoe UI', sans-serif",
      }}>
        <Story />
      </div>
    ),
  ],

  tags: ['autodocs'],
};

export default preview;
