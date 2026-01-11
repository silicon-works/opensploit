/**
 * Engagement State
 *
 * Manages shared state across sub-agents during a penetration test engagement.
 * State is stored in the session working directory and injected into sub-agent context.
 *
 * Requirements:
 * - REQ-AGT-010: Sub-agents receive current engagement state at spawn
 * - REQ-AGT-011: State includes target info, ports, credentials, vulnerabilities
 * - REQ-AGT-012: Sub-agents write discoveries to shared state file
 * - REQ-AGT-013: Context injection includes session working directory path
 */

import { SessionDirectory } from "./directory"
import { readFileSync, writeFileSync, existsSync } from "fs"
import { join } from "path"
import { Log } from "../util/log"
import yaml from "js-yaml"

const log = Log.create({ service: "session.engagement-state" })

export namespace EngagementState {
  /**
   * Target information
   */
  export interface Target {
    ip?: string
    hostname?: string
    os?: string
    osVersion?: string
  }

  /**
   * Discovered port/service
   */
  export interface Port {
    port: number
    protocol: "tcp" | "udp"
    service: string
    version?: string
    banner?: string // Service banner if grabbed
    state: "open" | "filtered" | "closed"
  }

  /**
   * Discovered credential
   */
  export interface Credential {
    username: string
    password?: string
    hash?: string
    key?: string // SSH key or similar
    source: string // Where it was found (e.g., "config file", "database dump")
    validated: boolean // Has it been tested?
    privileged?: boolean // Is this a root/admin account?
    validFor?: string[] // Services it works on
  }

  /**
   * Identified vulnerability
   */
  export interface Vulnerability {
    name: string
    severity: "critical" | "high" | "medium" | "low" | "info"
    service: string
    port?: number
    cve?: string
    exploitAvailable: boolean
    exploited?: boolean // Has this been successfully exploited?
    accessGained?: "none" | "user" | "root" // What access did exploitation provide?
    notes?: string
  }

  /**
   * Active shell session (REQ-FUN-123)
   */
  export interface Session {
    id: string // Unique identifier for this session
    type: "ssh" | "reverse" | "webshell" | "meterpreter" | "other"
    user: string // User the session is running as
    privileged: boolean // Is this root/admin?
    target?: string // IP or hostname
    established: string // ISO timestamp when established
    notes?: string
  }

  /**
   * File of interest found during engagement (REQ-FUN-125)
   */
  export interface FileOfInterest {
    path: string
    type: "config" | "credential" | "flag" | "suid" | "writable" | "interesting"
    content?: string // File content if small/relevant
    notes?: string
  }

  /**
   * Complete engagement state
   */
  export interface State {
    target?: Target
    ports?: Port[]
    credentials?: Credential[]
    vulnerabilities?: Vulnerability[]
    sessions?: Session[] // Active shell sessions (REQ-FUN-123)
    files?: FileOfInterest[] // Files of interest found (REQ-FUN-125)
    phase?: "reconnaissance" | "enumeration" | "exploitation" | "post-exploitation" | "reporting"
    notes?: string[]
    flags?: string[] // Captured flags (for CTF)
    accessLevel?: "none" | "user" | "root"
  }

  /**
   * Get state file path for a session
   */
  function statePath(sessionID: string): string {
    return join(SessionDirectory.get(sessionID), "state.yaml")
  }

  /**
   * Read engagement state from session directory
   */
  export function read(sessionID: string): State | null {
    const path = statePath(sessionID)
    if (!existsSync(path)) return null

    try {
      const content = readFileSync(path, "utf-8")
      return yaml.load(content) as State
    } catch (e) {
      log.error("failed to read state", { sessionID, error: e })
      return null
    }
  }

  /**
   * Write engagement state to session directory
   */
  export function write(sessionID: string, state: State): void {
    const path = statePath(sessionID)
    try {
      writeFileSync(path, yaml.dump(state), "utf-8")
      log.info("wrote state", { sessionID, path })
    } catch (e) {
      log.error("failed to write state", { sessionID, error: e })
    }
  }

  /**
   * Update engagement state (merge with existing)
   */
  export function update(sessionID: string, updates: Partial<State>): State {
    const current = read(sessionID) || {}
    const merged: State = {
      ...current,
      ...updates,
      // Merge arrays instead of replacing
      ports: mergeArrays(current.ports, updates.ports, (a, b) => a.port === b.port && a.protocol === b.protocol),
      credentials: mergeArrays(
        current.credentials,
        updates.credentials,
        (a, b) => a.username === b.username && a.source === b.source
      ),
      vulnerabilities: mergeArrays(
        current.vulnerabilities,
        updates.vulnerabilities,
        (a, b) => a.name === b.name && a.service === b.service
      ),
      sessions: mergeArrays(current.sessions, updates.sessions, (a, b) => a.id === b.id),
      files: mergeArrays(current.files, updates.files, (a, b) => a.path === b.path),
      notes: [...(current.notes || []), ...(updates.notes || [])],
      flags: [...new Set([...(current.flags || []), ...(updates.flags || [])])],
    }
    write(sessionID, merged)
    return merged
  }

  /**
   * Merge two arrays, deduplicating by a key function
   */
  function mergeArrays<T>(existing: T[] | undefined, updates: T[] | undefined, isDuplicate: (a: T, b: T) => boolean): T[] {
    if (!existing && !updates) return []
    if (!existing) return updates || []
    if (!updates) return existing

    const result = [...existing]
    for (const item of updates) {
      if (!result.some((e) => isDuplicate(e, item))) {
        result.push(item)
      }
    }
    return result
  }

  /**
   * Add a discovered port
   */
  export function addPort(sessionID: string, port: Port): void {
    update(sessionID, { ports: [port] })
  }

  /**
   * Add a discovered credential
   */
  export function addCredential(sessionID: string, credential: Credential): void {
    update(sessionID, { credentials: [credential] })
  }

  /**
   * Add an identified vulnerability
   */
  export function addVulnerability(sessionID: string, vulnerability: Vulnerability): void {
    update(sessionID, { vulnerabilities: [vulnerability] })
  }

  /**
   * Set the current phase
   */
  export function setPhase(sessionID: string, phase: State["phase"]): void {
    update(sessionID, { phase })
  }

  /**
   * Add a captured flag
   */
  export function addFlag(sessionID: string, flag: string): void {
    update(sessionID, { flags: [flag] })
  }

  /**
   * Add an active session (REQ-FUN-123)
   */
  export function addSession(sessionID: string, session: Session): void {
    update(sessionID, { sessions: [session] })
  }

  /**
   * Add a file of interest (REQ-FUN-125)
   */
  export function addFile(sessionID: string, file: FileOfInterest): void {
    update(sessionID, { files: [file] })
  }

  /**
   * Format state for injection into sub-agent prompt
   */
  export function formatForPrompt(sessionID: string, sessionDir: string): string {
    const state = read(sessionID)
    const lines: string[] = []

    // Session directory info
    lines.push("## Session Working Directory")
    lines.push(`All engagement documents should be written to: ${sessionDir}`)
    lines.push(`- Findings: ${sessionDir}/findings/`)
    lines.push(`- Artifacts: ${sessionDir}/artifacts/`)
    lines.push("")

    if (!state) {
      lines.push("## Engagement State")
      lines.push("No prior state found. This may be the first agent in this engagement.")
      lines.push("")
      return lines.join("\n")
    }

    lines.push("## Current Engagement State")
    lines.push("")

    // Target info
    if (state.target) {
      lines.push("### Target")
      if (state.target.ip) lines.push(`- **IP**: ${state.target.ip}`)
      if (state.target.hostname) lines.push(`- **Hostname**: ${state.target.hostname}`)
      if (state.target.os) lines.push(`- **OS**: ${state.target.os}${state.target.osVersion ? ` ${state.target.osVersion}` : ""}`)
      lines.push("")
    }

    // Discovered ports
    if (state.ports?.length) {
      lines.push("### Discovered Ports")
      lines.push("| Port | Protocol | Service | Version | State |")
      lines.push("|------|----------|---------|---------|-------|")
      for (const p of state.ports) {
        lines.push(`| ${p.port} | ${p.protocol} | ${p.service} | ${p.version || "-"} | ${p.state} |`)
      }
      lines.push("")
    }

    // Credentials
    if (state.credentials?.length) {
      lines.push("### Credentials Found")
      for (const c of state.credentials) {
        const status = c.validated ? "**validated**" : "unvalidated"
        const cred = c.password ? `${c.username}:${c.password}` : `${c.username}:${c.hash || "???"}`
        const validFor = c.validFor?.length ? ` (works on: ${c.validFor.join(", ")})` : ""
        lines.push(`- \`${cred}\` from ${c.source} [${status}]${validFor}`)
      }
      lines.push("")
    }

    // Vulnerabilities
    if (state.vulnerabilities?.length) {
      lines.push("### Vulnerabilities Identified")
      for (const v of state.vulnerabilities) {
        const exploit = v.exploitAvailable ? "exploit available" : "no exploit"
        const exploited = v.exploited ? " **[EXPLOITED]**" : ""
        const access = v.accessGained && v.accessGained !== "none" ? ` → ${v.accessGained} access` : ""
        const cve = v.cve ? ` (${v.cve})` : ""
        lines.push(`- [**${v.severity.toUpperCase()}**] ${v.name} on ${v.service}${v.port ? `:${v.port}` : ""}${cve} - ${exploit}${exploited}${access}`)
        if (v.notes) lines.push(`  - ${v.notes}`)
      }
      lines.push("")
    }

    // Active sessions
    if (state.sessions?.length) {
      lines.push("### Active Sessions")
      for (const s of state.sessions) {
        const priv = s.privileged ? "**privileged**" : "unprivileged"
        const target = s.target ? ` on ${s.target}` : ""
        lines.push(`- [${s.id}] ${s.type} as \`${s.user}\` (${priv})${target}`)
        if (s.notes) lines.push(`  - ${s.notes}`)
      }
      lines.push("")
    }

    // Files of interest
    if (state.files?.length) {
      lines.push("### Files of Interest")
      for (const f of state.files) {
        lines.push(`- [${f.type}] \`${f.path}\``)
        if (f.notes) lines.push(`  - ${f.notes}`)
      }
      lines.push("")
    }

    // Current phase
    if (state.phase) {
      lines.push(`### Current Phase: ${state.phase}`)
      lines.push("")
    }

    // Access level
    if (state.accessLevel && state.accessLevel !== "none") {
      lines.push(`### Access Level: ${state.accessLevel}`)
      lines.push("")
    }

    // Flags captured
    if (state.flags?.length) {
      lines.push("### Flags Captured")
      for (const f of state.flags) {
        lines.push(`- ${f}`)
      }
      lines.push("")
    }

    // Notes
    if (state.notes?.length) {
      lines.push("### Notes")
      for (const n of state.notes) {
        lines.push(`- ${n}`)
      }
      lines.push("")
    }

    return lines.join("\n")
  }
}
