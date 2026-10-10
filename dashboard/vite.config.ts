import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

// The dev server and preview server both use port 3000 on purpose: it is the
// default origin the SecureTrap API allows through CORS
// (SECURETRAP_CORS_ORIGINS defaults to http://localhost:3000), so the
// dashboard can talk to a locally running API with no extra setup.
export default defineConfig({
  plugins: [react()],
  server: { port: 3000, strictPort: true },
  preview: { port: 3000, strictPort: true },
  test: {
    // jsdom, but keeping Node's AbortController/AbortSignal so fetch accepts
    // them (see the comment in the file for why this is needed).
    environment: './src/test/jsdom-node-abort-environment.ts',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    restoreMocks: true,
    // A fixed, fake API origin for tests only. Every request in the test
    // suite is answered by mock handlers; nothing touches a real network.
    env: { VITE_API_BASE_URL: 'http://api.test' },
  },
});
