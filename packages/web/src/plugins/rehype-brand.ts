interface HastNode {
  type: string
  value?: string
  properties?: Record<string, unknown>
  children?: HastNode[]
}

// Patterns to protect from replacement (env vars, npm scope, internal paths, attribution)
const PROTECT_PATTERNS = [
  /OPENCODE_\w*/g,
  /@opencode-ai\//g,
  /packages\/opencode/g,
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
  [/\bOpencode\b/g, "OpenSploit"],
  [/OpenCode/g, "OpenSploit"],
  [/opencode/g, "opensploit"],
  [/Anomaly Innovations/g, "Silicon Works Ltd"],
  [/Anomaly/g, "Silicon Works"],
  [/anoma\.ly/g, "opensploit.ai"],
]

export function replaceText(text: string): string {
  // Protect skip patterns with null-byte placeholders
  const saved: string[] = []
  let s = text
  for (const re of PROTECT_PATTERNS) {
    s = s.replace(re, (match) => {
      const idx = saved.length
      saved.push(match)
      return `\x00P${idx}\x00`
    })
  }

  // Apply brand replacements
  for (const [pattern, replacement] of REPLACEMENTS) {
    s = s.replace(pattern, replacement)
  }

  // Restore protected patterns
  for (let i = 0; i < saved.length; i++) {
    s = s.replaceAll(`\x00P${i}\x00`, saved[i]!)
  }

  return s
}

const ATTR_KEYS = ["href", "src", "content", "title", "alt", "aria-label", "data-command", "data-code"]

function walk(node: HastNode) {
  if (node.type === "text" && typeof node.value === "string") {
    node.value = replaceText(node.value)
  }

  if (node.type === "raw" && typeof node.value === "string") {
    node.value = replaceRawHtml(node.value)
  }

  if (node.type === "element" && node.properties) {
    for (const key of ATTR_KEYS) {
      const val = node.properties[key]
      if (typeof val === "string") {
        node.properties[key] = replaceText(val)
      }
    }
  }

  if (node.children) {
    for (const child of node.children) {
      walk(child)
    }
  }
}

function replaceRawHtml(html: string): string {
  return html.replace(/>([^<]+)</g, (_match, text: string) => {
    return `>${replaceText(text)}<`
  }).replace(/data-code="([^"]*)"/g, (_match, val: string) => {
    return `data-code="${replaceText(val)}"`
  })
}

export function rehypeBrand() {
  return (tree: HastNode) => {
    walk(tree)
  }
}
