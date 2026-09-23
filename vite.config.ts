import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Tauri expects a fixed port and must fail rather than silently pick another,
// because the Rust side hardcodes devUrl.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: { ignored: ['**/src-tauri/**'] },
  },
  build: {
    // Tauri v2 ships a Chromium-based WebView2 on Windows / WKWebView elsewhere.
    target: 'es2022',
    sourcemap: process.env.TAURI_ENV_DEBUG === 'true',
    rollupOptions: {
      output: {
        // xterm plus the WebGL renderer is ~450 kB of the bundle. In a Tauri
        // app these assets load from local disk, so this is a parse-time and
        // cache-granularity concern, not a download one — splitting keeps an
        // app-code edit from invalidating the vendor chunk.
        manualChunks: {
          xterm: ['@xterm/xterm', '@xterm/addon-fit', '@xterm/addon-webgl'],
          react: ['react', 'react-dom'],
        },
      },
    },
  },
})
