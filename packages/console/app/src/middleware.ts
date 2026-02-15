import { createMiddleware } from "@solidjs/start/middleware"
import { LOCALE_HEADER, cookie, fromPathname, strip } from "~/lib/language"

const REGISTRY_BASE =
  "https://github.com/silicon-works/mcp-tools/releases/download/registry-latest"

const REGISTRY_ROUTES: Record<string, { cache: number; contentType: string }> = {
  "/registry.yaml": { cache: 300, contentType: "text/yaml; charset=utf-8" },
  "/registry.sha256": { cache: 60, contentType: "text/plain; charset=utf-8" },
  "/registry.lance.tar.gz": { cache: 300, contentType: "application/octet-stream" },
}

export default createMiddleware({
  async onRequest(event) {
    const url = new URL(event.request.url)

    // Registry proxy — fetch from GitHub Releases with correct content-type
    const registry = REGISTRY_ROUTES[url.pathname]
    if (registry) {
      const filename = url.pathname.slice(1)
      const upstream = await fetch(`${REGISTRY_BASE}/${filename}`, { redirect: "follow" })
      if (!upstream.ok) {
        return new Response("upstream error", { status: upstream.status })
      }
      return new Response(await upstream.arrayBuffer(), {
        status: 200,
        headers: {
          "content-type": registry.contentType,
          "cache-control": `public, max-age=${registry.cache}`,
          "access-control-allow-origin": "*",
          "access-control-allow-methods": "GET, HEAD, OPTIONS",
        },
      })
    }

    const locale = fromPathname(url.pathname)
    if (!locale) return

    url.pathname = strip(url.pathname)
    const request = new Request(url, event.request)
    request.headers.set(LOCALE_HEADER, locale)
    event.request = request
    event.response.headers.append("set-cookie", cookie(locale))
  },
})
