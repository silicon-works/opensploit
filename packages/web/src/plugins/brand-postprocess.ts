import { readdir, readFile, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { replaceText } from "./rehype-brand.ts"

async function* walkDir(dir: string): AsyncGenerator<string> {
  const entries = await readdir(dir, { withFileTypes: true })
  for (const entry of entries) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) yield* walkDir(full)
    else if (entry.name.endsWith(".html")) yield full
  }
}

function replaceHtml(html: string): string {
  // Replace text between tags (>text<)
  let result = html.replace(/>([^<]+)</g, (_m, text: string) => {
    return `>${replaceText(text)}<`
  })
  // Replace key attribute values that may contain opencode references
  // Covers: content, data-code, id, href fragment anchors
  result = result.replace(/(content|data-code|id)="([^"]*)"/g, (_m, attr: string, val: string) => {
    return `${attr}="${replaceText(val)}"`
  })
  // Fix anchor hrefs that reference heading IDs
  result = result.replace(/href="#([^"]*)"/g, (_m, fragment: string) => {
    return `href="#${replaceText(fragment)}"`
  })
  return result
}

export function brandPostprocess() {
  return {
    name: "brand-postprocess",
    hooks: {
      "astro:build:done": async ({ dir }: { dir: URL }) => {
        let count = 0
        for await (const file of walkDir(dir.pathname)) {
          const original = await readFile(file, "utf-8")
          const replaced = replaceHtml(original)
          if (replaced !== original) {
            await writeFile(file, replaced)
            count++
          }
        }
        console.log(`brand-postprocess: updated ${count} HTML files`)
      },
    },
  }
}
