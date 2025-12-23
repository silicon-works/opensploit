import { APIEvent } from "@solidjs/start"
import { DownloadPlatform } from "./types"

const assetNames: Record<string, string> = {
  "darwin-aarch64-dmg": "opensploit-desktop-darwin-aarch64.dmg",
  "darwin-x64-dmg": "opensploit-desktop-darwin-x64.dmg",
  "windows-x64-nsis": "opensploit-desktop-windows-x64.exe",
  "linux-x64-deb": "opensploit-desktop-linux-amd64.deb",
  "linux-x64-appimage": "opensploit-desktop-linux-amd64.AppImage",
  "linux-x64-rpm": "opensploit-desktop-linux-x86_64.rpm",
} satisfies Record<DownloadPlatform, string>

// Doing this on the server lets us preserve the original name for platforms we don't care to rename for
const downloadNames: Record<string, string> = {
  "darwin-aarch64-dmg": "OpenSploit Desktop.dmg",
  "darwin-x64-dmg": "OpenSploit Desktop.dmg",
  "windows-x64-nsis": "OpenSploit Desktop Installer.exe",
} satisfies { [K in DownloadPlatform]?: string }

export async function GET({ params: { platform } }: APIEvent) {
  const assetName = assetNames[platform]
  if (!assetName) return new Response("Not Found", { status: 404 })

  const resp = await fetch(`https://github.com/silicon-works/opensploit/releases/latest/download/${assetName}`, {
    cf: {
      // in case gh releases has rate limits
      cacheTtl: 60 * 60 * 24,
      cacheEverything: true,
    },
  } as any)

  const downloadName = downloadNames[platform]

  const headers = new Headers(resp.headers)
  if (downloadName) headers.set("content-disposition", `attachment; filename="${downloadName}"`)

  return new Response(resp.body, { ...resp, headers })
}
