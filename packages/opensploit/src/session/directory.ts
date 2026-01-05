/**
 * Session Working Directory
 *
 * Manages session-scoped temporary directories for engagement documents,
 * findings, and artifacts. Uses OS temp location for automatic cleanup.
 *
 * Requirements:
 * - REQ-SES-001: Create session-scoped temp directory at parent session start
 * - REQ-SES-002: Use OS temp location for automatic cleanup
 * - REQ-SES-003: Sub-agents share the root session's temp directory
 * - REQ-SES-004: Standard structure (findings/, artifacts/)
 * - REQ-SES-005: Cleanup when session is deleted
 */

import { tmpdir } from "os"
import { mkdirSync, rmSync, existsSync, writeFileSync, readFileSync } from "fs"
import { join } from "path"
import { Log } from "../util/log"

const log = Log.create({ service: "session.directory" })

export namespace SessionDirectory {
  const SESSION_DIR_PREFIX = "opensploit-session-"

  /**
   * Create a temp directory for a session with standard structure
   */
  export function create(sessionID: string): string {
    const dir = join(tmpdir(), `${SESSION_DIR_PREFIX}${sessionID}`)

    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true })

      // Create standard subdirectories
      mkdirSync(join(dir, "findings"), { recursive: true })
      mkdirSync(join(dir, "artifacts"), { recursive: true })
      mkdirSync(join(dir, "artifacts", "screenshots"), { recursive: true })
      mkdirSync(join(dir, "artifacts", "loot"), { recursive: true })

      log.info("created", { sessionID, dir })
    }

    return dir
  }

  /**
   * Get the session directory path (does not create)
   */
  export function get(sessionID: string): string {
    return join(tmpdir(), `${SESSION_DIR_PREFIX}${sessionID}`)
  }

  /**
   * Check if session directory exists
   */
  export function exists(sessionID: string): boolean {
    return existsSync(get(sessionID))
  }

  /**
   * Cleanup session directory
   */
  export function cleanup(sessionID: string): void {
    const dir = get(sessionID)
    if (existsSync(dir)) {
      rmSync(dir, { recursive: true, force: true })
      log.info("cleanup", { sessionID, dir })
    }
  }

  /**
   * Get path to a specific file in session directory
   */
  export function filePath(sessionID: string, ...segments: string[]): string {
    return join(get(sessionID), ...segments)
  }

  /**
   * Get findings directory path
   */
  export function findingsDir(sessionID: string): string {
    return join(get(sessionID), "findings")
  }

  /**
   * Get artifacts directory path
   */
  export function artifactsDir(sessionID: string): string {
    return join(get(sessionID), "artifacts")
  }

  /**
   * Write a findings file
   */
  export function writeFinding(sessionID: string, phase: string, content: string): void {
    const dir = findingsDir(sessionID)
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true })
    }
    const path = join(dir, `${phase}.md`)
    writeFileSync(path, content, "utf-8")
    log.info("wrote_finding", { sessionID, phase, path })
  }

  /**
   * Read a findings file
   */
  export function readFinding(sessionID: string, phase: string): string | null {
    const path = join(findingsDir(sessionID), `${phase}.md`)
    if (!existsSync(path)) return null
    return readFileSync(path, "utf-8")
  }

  /**
   * Directory structure documentation:
   *
   * /tmp/opensploit-session-{id}/
   * ├── state.yaml              # Engagement state (target, ports, creds, vulns)
   * ├── findings/
   * │   ├── recon.md            # Reconnaissance findings
   * │   ├── enum.md             # Enumeration findings
   * │   └── exploit.md          # Exploitation findings
   * └── artifacts/
   *     ├── screenshots/        # Screenshot evidence
   *     └── loot/               # Captured files, credentials
   */
}
