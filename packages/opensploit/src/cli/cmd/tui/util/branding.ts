/**
 * Branding utilities for display name mapping.
 * Maps internal provider IDs/names to opensploit branding.
 */

const PROVIDER_NAME_MAP: Record<string, string> = {
  opencode: "opensploit",
  "opencode zen": "opensploit zen",
  "opencode:dev": "opensploit:dev",
  "opencode local": "opensploit local",
  "OpenCode": "OpenSploit",
  "OpenCode Zen": "OpenSploit Zen",
}

/**
 * Maps a provider name or ID to the opensploit branding.
 * Case-insensitive matching with case-preserved output.
 */
export function mapProviderName(name: string): string {
  // Direct match
  if (PROVIDER_NAME_MAP[name]) {
    return PROVIDER_NAME_MAP[name]
  }

  // Case-insensitive match
  const lowerName = name.toLowerCase()
  for (const [key, value] of Object.entries(PROVIDER_NAME_MAP)) {
    if (key.toLowerCase() === lowerName) {
      return value
    }
  }

  // Replace "opensploit" substring (case-insensitive)
  return name.replace(/opencode/gi, (match) => {
    // Preserve case pattern
    if (match === "opencode") return "opensploit"
    if (match === "OpenCode") return "OpenSploit"
    if (match === "OPENCODE") return "OPENSPLOIT"
    if (match === "Opencode") return "Opensploit"
    return "opensploit"
  })
}

/**
 * Maps a provider ID to opensploit branding for display purposes.
 * The actual ID remains unchanged for API compatibility.
 */
export function mapProviderDisplayName(provider: { id: string; name: string }): string {
  return mapProviderName(provider.name)
}
