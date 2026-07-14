import build from '@hono/vite-build/cloudflare-pages'
import devServer from '@hono/vite-dev-server'
import adapter from '@hono/vite-dev-server/cloudflare'
import { defineConfig } from 'vite'

export default defineConfig({
  // Frontend static assets live in ./frontend (served at web root, e.g. /static/*).
  publicDir: 'frontend',
  plugins: [
    // The backend entry is backend/index.tsx (not the plugin default src/index.tsx),
    // so it must be passed explicitly or the Workers bundle ships with no routes.
    build({ entry: 'backend/index.tsx' }),
    devServer({
      adapter,
      entry: 'backend/index.tsx'
    })
  ]
})
