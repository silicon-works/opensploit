import { defineMiddleware } from "astro:middleware"
import { matchLocale, localeAlias } from "./i18n/locales"

function matchLocaleExact(value: string): string | null {
  const key = value.toLowerCase()
  if (key in localeAlias) {
    return localeAlias[key as keyof typeof localeAlias]
  }
  return null
}

function docsAlias(pathname: string) {
  const hit = /^\/docs\/([^/]+)(\/.*)?$/.exec(pathname)
  if (!hit) return null

  const value = hit[1] ?? ""
  const tail = hit[2] ?? ""
  // Use exact locale matching for URL paths — not fuzzy startsWith matching.
  // "troubleshooting" must not match "tr", "rules" must not match "ru".
  const locale = matchLocaleExact(value)
  if (!locale) return null
  if (locale === "root") return `/docs${tail}`
  if (value === locale) return null

  return `/docs/${locale}${tail}`
}

function localeFromCookie(header: string | null) {
  if (!header) return null
  const raw = header
    .split(";")
    .map((x) => x.trim())
    .find((x) => x.startsWith("oc_locale="))
    ?.slice("oc_locale=".length)
  if (!raw) return null
  return matchLocale(raw)
}

function localeFromAcceptLanguage(header: string | null) {
  if (!header) return "root"

  const items = header
    .split(",")
    .map((raw) => raw.trim())
    .filter(Boolean)
    .map((raw) => {
      const parts = raw.split(";").map((x) => x.trim())
      const lang = parts[0] ?? ""
      const q = parts
        .slice(1)
        .find((x) => x.startsWith("q="))
        ?.slice(2)
      return {
        lang,
        q: q ? Number.parseFloat(q) : 1,
      }
    })
    .sort((a, b) => b.q - a.q)

  const locale = items
    .map((item) => item.lang)
    .filter((lang) => lang && lang !== "*")
    .map((lang) => matchLocale(lang))
    .find((lang) => lang)

  return locale ?? "root"
}

const REGISTRY_BASE =
  "https://github.com/silicon-works/mcp-tools/releases/download/registry-latest"

const REGISTRY_FILES: Record<string, { cache: number; contentType: string }> = {
  "/registry.yaml": { cache: 300, contentType: "text/yaml; charset=utf-8" },
  "/registry.sha256": { cache: 60, contentType: "text/plain; charset=utf-8" },
  "/registry.lance.tar.gz": { cache: 300, contentType: "application/octet-stream" },
}

const CORS_HEADERS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, HEAD, OPTIONS",
}

async function proxyRegistry(pathname: string): Promise<Response | null> {
  const entry = REGISTRY_FILES[pathname]
  if (!entry) return null

  try {
    const filename = pathname.slice(1)
    const upstream = await fetch(`${REGISTRY_BASE}/${filename}`, { redirect: "follow" })
    if (!upstream.ok) {
      return new Response("upstream error", {
        status: upstream.status,
        headers: CORS_HEADERS,
      })
    }

    const headers = new Headers(CORS_HEADERS)
    headers.set("cache-control", `public, max-age=${entry.cache}`)
    headers.set("content-type", entry.contentType)

    return new Response(upstream.body, { status: 200, headers })
  } catch {
    return new Response("proxy error", { status: 502, headers: CORS_HEADERS })
  }
}

export const onRequest = defineMiddleware(async (ctx, next) => {
  // Redirect /favicon.ico to /docs/favicon.ico (browsers hardcode this request)
  if (ctx.url.pathname === "/favicon.ico") {
    const url = new URL(ctx.request.url)
    url.pathname = "/docs/favicon.ico"
    return ctx.redirect(url.toString(), 301)
  }

  // Registry proxy (before locale routing)
  if (ctx.request.method === "OPTIONS" && REGISTRY_FILES[ctx.url.pathname]) {
    return new Response(null, { status: 204, headers: CORS_HEADERS })
  }
  const registryResponse = await proxyRegistry(ctx.url.pathname)
  if (registryResponse) return registryResponse

  const alias = docsAlias(ctx.url.pathname)
  if (alias) {
    const url = new URL(ctx.request.url)
    url.pathname = alias
    return ctx.redirect(url.toString(), 302)
  }

  if (ctx.url.pathname !== "/docs" && ctx.url.pathname !== "/docs/") return next()

  const locale =
    localeFromCookie(ctx.request.headers.get("cookie")) ??
    localeFromAcceptLanguage(ctx.request.headers.get("accept-language"))
  if (!locale || locale === "root") return next()

  const url = new URL(ctx.request.url)
  url.pathname = `/docs/${locale}/`
  return ctx.redirect(url.toString(), 302)
})
