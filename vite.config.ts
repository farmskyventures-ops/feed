import build from '@hono/vite-build/cloudflare-pages'
import devServer from '@hono/vite-dev-server'
import adapter from '@hono/vite-dev-server/cloudflare'
import { defineConfig } from 'vite'

export default defineConfig({
  // Frontend static assets live in ./frontend (served at web root, e.g. /static/*).
  publicDir: 'frontend',
  plugins: [
    build(),
    devServer({
      adapter,
      entry: 'backend/index.tsx'
    })
  ]
})
