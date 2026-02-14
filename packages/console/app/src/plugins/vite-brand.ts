import type { Plugin } from "vite"

const PROTECT = [
  /OPENCODE_\w*/g,
  /@opencode-ai\//g,
  /packages\/opencode/g,
  // Protect file paths: opencode preceded by / or ./ (import paths, asset refs)
  /(?:\.\.?\/)[^\s'"]*opencode[^\s'"]*/g,
  // Protect fork attribution phrases
  /built on OpenCode/g,
  /fork of OpenCode/g,
]

const REPLACEMENTS: [RegExp, string][] = [
  [/opencode\.ai/g, "opensploit.ai"],
  [/anomalyco\/tap\/opencode/g, "silicon-works/tap/opensploit"],
  [/ghcr\.io\/anomalyco\/opencode/g, "ghcr.io/silicon-works/opensploit"],
  [/anomalyco\/opencode/g, "silicon-works/opensploit"],
  [/anomalyco/g, "silicon-works"],
  [/opencode-ai/g, "opensploit"],
  [/opencode-bin/g, "opensploit-bin"],
  [/OpenCode/g, "OpenSploit"],
  [/opencode/g, "opensploit"],
  [/Anomaly Innovations/g, "Silicon Works Ltd"],
  [/Anomaly/g, "Silicon Works"],
  [/anoma\.ly/g, "opensploit.ai"],
]

function replaceText(text: string): string {
  const saved: string[] = []
  let s = text
  for (const re of PROTECT) {
    s = s.replace(re, (match) => {
      const idx = saved.length
      saved.push(match)
      return `\x00P${idx}\x00`
    })
  }
  for (const [pattern, replacement] of REPLACEMENTS) {
    s = s.replace(pattern, replacement)
  }
  for (let i = 0; i < saved.length; i++) {
    s = s.replaceAll(`\x00P${i}\x00`, saved[i]!)
  }
  return s
}

export function viteBrand(): Plugin {
  return {
    name: "vite-brand",
    enforce: "pre",
    transform(code, id) {
      if (id.includes("node_modules")) return
      if (!/\.(tsx?|jsx?|css|json)(\?|$)/.test(id)) return
      if (!/(opencode|OpenCode|anomalyco|anomaly|anoma\.ly)/i.test(code)) return
      return { code: replaceText(code), map: null }
    },
    transformIndexHtml(html) {
      return replaceText(html)
    },
  }
}
