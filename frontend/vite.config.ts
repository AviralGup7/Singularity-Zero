import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
// import { visualizer } from 'rollup-plugin-visualizer'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    /* visualizer({
      filename: 'dist/stats.html',
      open: false,
      gzipSize: true,
      brotliSize: true,
    }), */
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5000,
    // SECURITY: bind to localhost by default. ``0.0.0.0`` and
    // ``allowedHosts: true`` together let any host on the network reach
    // the dev server. The VITE_BIND_HOST env var is still honored for
    // sandboxed environments (Replit, Codespaces) where the platform
    // needs to forward a port.
    host: process.env.VITE_BIND_HOST || '127.0.0.1',
    allowedHosts: process.env.VITE_ALLOWED_HOSTS
      ? process.env.VITE_ALLOWED_HOSTS.split(',')
      : ['localhost', '127.0.0.1'],
    watch: {
      ignored: [],
    },
    // Security: add security headers in dev server
    headers: {
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    },
    proxy: {
      // Proxy all /api requests to the Python backend
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
  build: {
    minify: 'esbuild',
    cssMinify: true,
    rollupOptions: {
      external: ['hls.js'],
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            // 1. Three.js / 3D Graphics Vendor Group
            if (
              id.includes('three') ||
              id.includes('@react-three') ||
              id.includes('@react-three/fiber') ||
              id.includes('@react-three/drei') ||
              id.includes('@react-three/postprocessing')
            ) {
              return 'three-vendor';
            }
            // 2. Data Visualization & State Management Group
            if (
              id.includes('d3') ||
              id.includes('d3-') ||
              id.includes('recharts') ||
              id.includes('@tanstack/react-query')
            ) {
              return 'data-vendor';
            }
            // 3. UI Primitives, Micro-Animations, and Design Tokens
            if (
              id.includes('framer-motion') ||
              id.includes('@radix-ui') ||
              id.includes('lucide-react') ||
              id.includes('cmdk') ||
              id.includes('vaul') ||
              id.includes('embla-carousel-react') ||
              id.includes('@formkit/auto-animate')
            ) {
              return 'ui-vendor';
            }
            // 4. Core React Platform dependencies
            if (
              id.includes('react') ||
              id.includes('react-dom') ||
              id.includes('react-router-dom') ||
              id.includes('react-router') ||
              id.includes('react-is')
            ) {
              return 'react-vendor';
            }
          }
        },
      },
    },
    reportCompressedSize: true,
  },
})
