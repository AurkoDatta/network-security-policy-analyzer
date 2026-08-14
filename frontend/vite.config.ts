/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: './tests/setup.ts',
    coverage: {
      exclude: [
        '**/*.config.js',
        '**/*.config.ts',
        'dist/**',
        'src/main.tsx',
        'src/types/**',
        'src/vite-env.d.ts',
      ],
    },
  },
});
