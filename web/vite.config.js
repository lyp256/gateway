import { defineConfig } from 'vite'
import { fileURLToPath, URL } from 'node:url'

export default defineConfig({
  base: './',
  resolve: {
    alias: {
      vue: 'vue/dist/vue.esm-bundler.js',
    },
  },
  server: {
    host: '0.0.0.0',
    allowedHosts: true,
    proxy: {
      '/api': process.env.GATEWAY_API_URL || 'http://127.0.0.1:80',
    },
  },
  build: {
    outDir: fileURLToPath(new URL('dist/', import.meta.url)),
    emptyOutDir: true,
    assetsDir: 'assets',
  },
})
