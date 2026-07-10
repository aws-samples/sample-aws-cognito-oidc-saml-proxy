import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// amazon-cognito-identity-js references the `global` object, which does not
// exist in the browser. Map it to globalThis so the SDK works in a SPA bundle.
export default defineConfig({
  plugins: [react()],
  define: {
    global: 'globalThis',
  },
  server: {
    port: 5174,
  },
});
