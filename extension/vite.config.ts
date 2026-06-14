import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';

/**
 * Vite configuration for Chrome Extension (Manifest V3).
 *
 * Multi-entry build: service worker, content script, popup, options page.
 * Output goes to extension/dist/ which is loaded as unpacked extension.
 */
export default defineConfig({
  plugins: [react()],
  root: resolve(__dirname),
  publicDir: resolve(__dirname, 'public'),
  build: {
    outDir: resolve(__dirname, 'dist'),
    emptyOutDir: true,
    rollupOptions: {
      input: {
        serviceWorker: resolve(__dirname, 'src/background/serviceWorker.ts'),
        contentScript: resolve(__dirname, 'src/content/contentScript.ts'),
        popup: resolve(__dirname, 'src/popup/popup.html'),
        options: resolve(__dirname, 'src/options/options.html'),
      },
      output: {
        entryFileNames: (chunkInfo) => {
          if (chunkInfo.name === 'serviceWorker') return 'src/background/serviceWorker.js';
          if (chunkInfo.name === 'contentScript') return 'src/content/contentScript.js';
          return 'assets/[name]-[hash].js';
        },
        chunkFileNames: 'assets/chunks/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
    target: 'chrome120',
    minify: false,
    sourcemap: true,
  },
  resolve: {
    alias: {
      '@extension': resolve(__dirname, 'src'),
    },
  },
  define: {
    'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV || 'production'),
  },
});
