import z from "zod"
import { Tool } from "./tool"
import TurndownService from "turndown"
import DESCRIPTION from "./webfetch.txt"
import { Config } from "../config/config"
import { Permission } from "../permission"
import { Readability } from "@mozilla/readability"
import { parseHTML } from "linkedom"

const MAX_RESPONSE_SIZE = 5 * 1024 * 1024 // 5MB
const DEFAULT_TIMEOUT = 30 * 1000 // 30 seconds
const MAX_TIMEOUT = 120 * 1000 // 2 minutes

export const WebFetchTool = Tool.define("webfetch", {
  description: DESCRIPTION,
  parameters: z.object({
    url: z.string().describe("The URL to fetch content from"),
    format: z
      .enum(["text", "markdown", "html"])
      .describe("The format to return the content in (text, markdown, or html)"),
    timeout: z.number().describe("Optional timeout in seconds (max 120)").optional(),
    extract_main_content: z
      .boolean()
      .optional()
      .default(true)
      .describe(
        "Use Readability to extract only the main article content, removing navigation, headers, footers, ads, etc. Highly recommended for cleaner output.",
      ),
  }),
  async execute(params, ctx) {
    // Validate URL
    if (!params.url.startsWith("http://") && !params.url.startsWith("https://")) {
      throw new Error("URL must start with http:// or https://")
    }

    const cfg = await Config.get()
    if (cfg.permission?.webfetch === "ask")
      await Permission.ask({
        type: "webfetch",
        sessionID: ctx.sessionID,
        messageID: ctx.messageID,
        callID: ctx.callID,
        title: "Fetch content from: " + params.url,
        metadata: {
          url: params.url,
          format: params.format,
          timeout: params.timeout,
        },
      })

    const timeout = Math.min((params.timeout ?? DEFAULT_TIMEOUT / 1000) * 1000, MAX_TIMEOUT)

    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), timeout)

    // Build Accept header based on requested format with q parameters for fallbacks
    let acceptHeader = "*/*"
    switch (params.format) {
      case "markdown":
        acceptHeader = "text/markdown;q=1.0, text/x-markdown;q=0.9, text/plain;q=0.8, text/html;q=0.7, */*;q=0.1"
        break
      case "text":
        acceptHeader = "text/plain;q=1.0, text/markdown;q=0.9, text/html;q=0.8, */*;q=0.1"
        break
      case "html":
        acceptHeader = "text/html;q=1.0, application/xhtml+xml;q=0.9, text/plain;q=0.8, text/markdown;q=0.7, */*;q=0.1"
        break
      default:
        acceptHeader =
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
    }

    const response = await fetch(params.url, {
      signal: AbortSignal.any([controller.signal, ctx.abort]),
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        Accept: acceptHeader,
        "Accept-Language": "en-US,en;q=0.9",
      },
    })

    clearTimeout(timeoutId)

    if (!response.ok) {
      throw new Error(`Request failed with status code: ${response.status}`)
    }

    // Check content length
    const contentLength = response.headers.get("content-length")
    if (contentLength && parseInt(contentLength) > MAX_RESPONSE_SIZE) {
      throw new Error("Response too large (exceeds 5MB limit)")
    }

    const arrayBuffer = await response.arrayBuffer()
    if (arrayBuffer.byteLength > MAX_RESPONSE_SIZE) {
      throw new Error("Response too large (exceeds 5MB limit)")
    }

    const content = new TextDecoder().decode(arrayBuffer)
    const contentType = response.headers.get("content-type") || ""

    const title = `${params.url} (${contentType})`

    // Handle content based on requested format and actual content type
    switch (params.format) {
      case "markdown":
        if (contentType.includes("text/html")) {
          // Use Readability extraction if enabled
          const htmlToProcess = params.extract_main_content ? extractMainContent(content, params.url) : content
          const markdown = convertHTMLToMarkdown(htmlToProcess)
          return {
            output: markdown,
            title,
            metadata: {
              readability_extracted: params.extract_main_content,
            },
          }
        }
        return {
          output: content,
          title,
          metadata: {
            readability_extracted: false,
          },
        }

      case "text":
        if (contentType.includes("text/html")) {
          // Use Readability extraction if enabled
          const htmlToProcess = params.extract_main_content ? extractMainContent(content, params.url) : content
          const text = await extractTextFromHTML(htmlToProcess)
          return {
            output: text,
            title,
            metadata: {
              readability_extracted: params.extract_main_content,
            },
          }
        }
        return {
          output: content,
          title,
          metadata: {
            readability_extracted: false,
          },
        }

      case "html":
        if (params.extract_main_content && contentType.includes("text/html")) {
          const cleanedHtml = extractMainContent(content, params.url)
          return {
            output: cleanedHtml,
            title,
            metadata: {
              readability_extracted: true,
            },
          }
        }
        return {
          output: content,
          title,
          metadata: {
            readability_extracted: false,
          },
        }

      default:
        return {
          output: content,
          title,
          metadata: {
            readability_extracted: false,
          },
        }
    }
  },
})

/**
 * Extract main article content using Mozilla's Readability algorithm.
 * This removes navigation, headers, footers, sidebars, ads, etc.
 * and returns only the primary content of the page.
 */
function extractMainContent(html: string, url: string): string {
  try {
    const { document } = parseHTML(html)

    // Set the document URL for Readability
    // This helps with resolving relative URLs
    const baseUrl = new URL(url)

    // Clone the document for Readability (it modifies the DOM)
    const reader = new Readability(document as unknown as Document, {
      charThreshold: 50, // Lower threshold to catch smaller articles
      keepClasses: true, // Keep classes for code highlighting
    })

    const article = reader.parse()

    if (article && article.content) {
      // Build a clean HTML structure with the extracted content
      const cleanHtml = `
<!DOCTYPE html>
<html>
<head>
  <title>${article.title || "Article"}</title>
  <base href="${baseUrl.origin}">
</head>
<body>
  <article>
    <h1>${article.title || ""}</h1>
    ${article.byline ? `<p class="byline">${article.byline}</p>` : ""}
    ${article.content}
  </article>
</body>
</html>`
      return cleanHtml
    }

    // If Readability couldn't extract content, try fallback extraction
    return fallbackExtraction(html)
  } catch (error) {
    // If Readability fails, return original HTML
    console.error("Readability extraction failed:", error)
    return html
  }
}

/**
 * Fallback extraction when Readability can't parse the page.
 * Tries to extract content from common article containers.
 */
function fallbackExtraction(html: string): string {
  try {
    const { document } = parseHTML(html)

    // Remove known non-content elements
    const removeSelectors = [
      "script",
      "style",
      "noscript",
      "iframe",
      "nav",
      "header",
      "footer",
      "aside",
      ".sidebar",
      ".nav",
      ".menu",
      ".advertisement",
      ".ad",
      ".ads",
      ".social-share",
      ".comments",
      "#comments",
      ".related-posts",
    ]

    for (const selector of removeSelectors) {
      const elements = document.querySelectorAll(selector)
      for (const el of elements) {
        el.remove()
      }
    }

    // Try to find main content container
    const mainSelectors = ["article", "main", ".post-content", ".article-content", ".entry-content", "#content", ".content"]

    for (const selector of mainSelectors) {
      const main = document.querySelector(selector)
      if (main && main.textContent && main.textContent.trim().length > 200) {
        return main.outerHTML || html
      }
    }

    // If no main container found, return the body
    const body = document.querySelector("body")
    return body?.innerHTML || html
  } catch {
    return html
  }
}

async function extractTextFromHTML(html: string) {
  let text = ""
  let skipContent = false

  const rewriter = new HTMLRewriter()
    .on("script, style, noscript, iframe, object, embed", {
      element() {
        skipContent = true
      },
      text() {
        // Skip text content inside these elements
      },
    })
    .on("*", {
      element(element) {
        // Reset skip flag when entering other elements
        if (!["script", "style", "noscript", "iframe", "object", "embed"].includes(element.tagName)) {
          skipContent = false
        }
      },
      text(input) {
        if (!skipContent) {
          text += input.text
        }
      },
    })
    .transform(new Response(html))

  await rewriter.text()
  return text.trim()
}

function convertHTMLToMarkdown(html: string): string {
  const turndownService = new TurndownService({
    headingStyle: "atx",
    hr: "---",
    bulletListMarker: "-",
    codeBlockStyle: "fenced",
    emDelimiter: "*",
  })
  turndownService.remove(["script", "style", "meta", "link"])
  return turndownService.turndown(html)
}
