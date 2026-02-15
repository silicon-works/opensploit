import { defineConfig, PluginOption, Plugin } from "vite"
import { solidStart } from "@solidjs/start/config"
import { nitro } from "nitro/vite"
import { viteBrand } from "./src/plugins/vite-brand"

const REGISTRY_BASE =
  "https://github.com/silicon-works/mcp-tools/releases/download/registry-latest"

const REGISTRY_ROUTES: Record<string, { cache: number; contentType: string }> = {
  "/registry.yaml": { cache: 300, contentType: "text/yaml; charset=utf-8" },
  "/registry.sha256": { cache: 60, contentType: "text/plain; charset=utf-8" },
  "/registry.lance.tar.gz": { cache: 300, contentType: "application/octet-stream" },
}

function registryProxy(): Plugin {
  return {
    name: "registry-proxy",
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        const entry = REGISTRY_ROUTES[req.url!]
        if (!entry) return next()
        try {
          const filename = req.url!.slice(1)
          const upstream = await fetch(`${REGISTRY_BASE}/${filename}`, { redirect: "follow" })
          if (!upstream.ok) {
            res.writeHead(upstream.status, { "content-type": "text/plain" })
            res.end("upstream error")
            return
          }
          res.writeHead(200, {
            "content-type": entry.contentType,
            "cache-control": `public, max-age=${entry.cache}`,
            "access-control-allow-origin": "*",
            "access-control-allow-methods": "GET, HEAD, OPTIONS",
          })
          const body = Buffer.from(await upstream.arrayBuffer())
          res.end(body)
        } catch {
          res.writeHead(502, { "content-type": "text/plain" })
          res.end("proxy error")
        }
      })
    },
  }
}

export default defineConfig({
  plugins: [
    registryProxy(),
    viteBrand(),
    solidStart({
      middleware: "./src/middleware.ts",
    }) as PluginOption,
    nitro({
      compatibilityDate: "2024-09-19",
      preset: "cloudflare_module",
      cloudflare: {
        nodeCompat: true,
      },
      routeRules: {
        "/registry.yaml": {
          proxy: `${REGISTRY_BASE}/registry.yaml`,
          headers: { "content-type": "text/yaml; charset=utf-8", "cache-control": "public, max-age=300", "access-control-allow-origin": "*" },
        },
        "/registry.sha256": {
          proxy: `${REGISTRY_BASE}/registry.sha256`,
          headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "public, max-age=60", "access-control-allow-origin": "*" },
        },
        "/registry.lance.tar.gz": {
          proxy: `${REGISTRY_BASE}/registry.lance.tar.gz`,
          headers: { "content-type": "application/octet-stream", "cache-control": "public, max-age=300", "access-control-allow-origin": "*" },
        },
      },
    }),
  ],
  server: {
    allowedHosts: true,
  },
  build: {
    rollupOptions: {
      external: ["cloudflare:workers"],
    },
    minify: false,
  },
})
