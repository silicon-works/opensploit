import z from "zod"
import { Tool } from "./tool"
import path from "path"
import fs from "fs/promises"
import yaml from "js-yaml"
import { Log } from "../util/log"
import * as SessionDirectory from "../session/directory"

const log = Log.create({ service: "tool.engagement-state" })

// =============================================================================
// Feature 03: Phase Management - Engagement State Tool
// =============================================================================
// Provides state sharing between agents during penetration testing engagements.
//
// Key behaviors:
// - Merges arrays (appends items)
// - Replaces scalar values
// - Persists to /tmp/opensploit-session-{rootSessionID}/state.yaml
// - Available to all agents for sharing discoveries
//
// Updated for Feature 04: Uses SessionDirectory for /tmp/ storage

// Storage paths - directly in session directory per Feature 04 spec
const STATE_FILE = "state.yaml"
const FINDINGS_DIR = "findings"

// -----------------------------------------------------------------------------
// State Schema (flexible - LLM determines fields)
// -----------------------------------------------------------------------------
// We use a permissive schema since the LLM decides what fields to include.
// Common fields are documented but not strictly enforced.

const PortInfoSchema = z.object({
  port: z.number(),
  protocol: z.enum(["tcp", "udp"]).default("tcp"),
  service: z.string().optional(),
  version: z.string().optional(),
  state: z.enum(["open", "closed", "filtered"]).optional(),
  banner: z.string().optional(),
}).passthrough()

const CredentialInfoSchema = z.object({
  username: z.string(),
  password: z.string().optional(),
  hash: z.string().optional(),
  key: z.string().optional(),
  service: z.string().optional(),
  validated: z.boolean().optional(),
  privileged: z.boolean().optional(),
  source: z.string().optional(),
}).passthrough()

const VulnerabilityInfoSchema = z.object({
  name: z.string(),
  severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
  service: z.string().optional(),
  port: z.number().optional(),
  cve: z.string().optional(),
  exploitable: z.boolean().optional(),
  exploited: z.boolean().optional(),
  accessGained: z.enum(["none", "user", "root"]).optional(),
}).passthrough()

const SessionInfoSchema = z.object({
  id: z.string(),
  type: z.enum(["ssh", "reverse", "webshell", "meterpreter"]).optional(),
  user: z.string().optional(),
  privileged: z.boolean().optional(),
  established: z.string().optional(),
  notes: z.string().optional(),
}).passthrough()

const FileInfoSchema = z.object({
  path: z.string(),
  type: z.enum(["config", "credential", "flag", "suid", "writable", "interesting"]).optional(),
  content: z.string().optional(),
  notes: z.string().optional(),
}).passthrough()

const FailedAttemptSchema = z.object({
  action: z.string(),
  tool: z.string().optional(),
  reason: z.string(),
  timestamp: z.string().optional(),
}).passthrough()

const TargetInfoSchema = z.object({
  ip: z.string(),
  hostname: z.string().optional(),
}).passthrough()

// Main state schema - permissive to allow LLM flexibility
const EngagementStateSchema = z.object({
  target: TargetInfoSchema.optional(),
  ports: z.array(PortInfoSchema).optional(),
  credentials: z.array(CredentialInfoSchema).optional(),
  vulnerabilities: z.array(VulnerabilityInfoSchema).optional(),
  sessions: z.array(SessionInfoSchema).optional(),
  files: z.array(FileInfoSchema).optional(),
  failedAttempts: z.array(FailedAttemptSchema).optional(),
  accessLevel: z.enum(["none", "user", "root"]).optional(),
  flags: z.array(z.string()).optional(),
}).passthrough()

type EngagementState = z.infer<typeof EngagementStateSchema>

// -----------------------------------------------------------------------------
// File System Helpers
// -----------------------------------------------------------------------------
// Uses /tmp/opensploit-session-{sessionID}/ for engagement data storage.
// Session directory is created on first write if it doesn't exist.

function getSessionDir(sessionID: string): string {
  return SessionDirectory.get(sessionID)
}

function getStatePath(sessionID: string): string {
  return SessionDirectory.statePath(sessionID)
}

async function ensureSessionDir(sessionID: string): Promise<string> {
  const dir = getSessionDir(sessionID)
  if (!SessionDirectory.exists(sessionID)) {
    SessionDirectory.create(sessionID)
  }
  return dir
}

async function ensureFindingsDir(sessionID: string): Promise<string> {
  await ensureSessionDir(sessionID)
  return SessionDirectory.findingsDir(sessionID)
}

// -----------------------------------------------------------------------------
// State Management
// -----------------------------------------------------------------------------

export async function loadEngagementState(sessionID: string): Promise<EngagementState> {
  try {
    const statePath = getStatePath(sessionID)
    const content = await fs.readFile(statePath, "utf-8")
    const parsed = yaml.load(content) as EngagementState
    return parsed ?? {}
  } catch (error: any) {
    if (error.code === "ENOENT") {
      // File doesn't exist yet - return empty state
      return {}
    }
    log.error("Failed to load engagement state", { error: error.message })
    return {}
  }
}

async function saveEngagementState(sessionID: string, state: EngagementState): Promise<void> {
  // Ensure session directory exists before writing
  await ensureSessionDir(sessionID)

  const statePath = getStatePath(sessionID)
  const content = yaml.dump(state, {
    indent: 2,
    lineWidth: 120,
    noRefs: true,
    sortKeys: false,
  })
  await fs.writeFile(statePath, content, "utf-8")
  log.info("Saved engagement state", { sessionID: sessionID.slice(-8), path: statePath })
}

/**
 * Merge updates into existing state.
 * - Arrays are appended (with deduplication for some fields)
 * - Scalars are replaced
 * - Objects are merged recursively
 *
 * Exported for testing.
 */
export function mergeState(existing: EngagementState, updates: Partial<EngagementState>): EngagementState {
  const result = { ...existing }

  for (const [key, value] of Object.entries(updates)) {
    if (value === undefined || value === null) continue

    const existingValue = (result as any)[key]

    if (Array.isArray(value)) {
      // Merge arrays - append new items
      const existingArray = Array.isArray(existingValue) ? existingValue : []

      // For certain arrays, deduplicate by key fields
      if (key === "ports") {
        // Dedupe by port+protocol
        const merged = [...existingArray]
        for (const item of value) {
          const exists = merged.some(
            (p: any) => p.port === item.port && p.protocol === item.protocol
          )
          if (!exists) merged.push(item)
          else {
            // Update existing entry
            const idx = merged.findIndex(
              (p: any) => p.port === item.port && p.protocol === item.protocol
            )
            if (idx !== -1) merged[idx] = { ...merged[idx], ...item }
          }
        }
        (result as any)[key] = merged
      } else if (key === "credentials") {
        // Dedupe by username+service
        const merged = [...existingArray]
        for (const item of value) {
          const exists = merged.some(
            (c: any) => c.username === item.username && c.service === item.service
          )
          if (!exists) merged.push(item)
          else {
            // Update existing entry
            const idx = merged.findIndex(
              (c: any) => c.username === item.username && c.service === item.service
            )
            if (idx !== -1) merged[idx] = { ...merged[idx], ...item }
          }
        }
        (result as any)[key] = merged
      } else if (key === "sessions") {
        // Dedupe by id
        const merged = [...existingArray]
        for (const item of value) {
          const exists = merged.some((s: any) => s.id === item.id)
          if (!exists) merged.push(item)
          else {
            const idx = merged.findIndex((s: any) => s.id === item.id)
            if (idx !== -1) merged[idx] = { ...merged[idx], ...item }
          }
        }
        (result as any)[key] = merged
      } else if (key === "flags") {
        // Dedupe flags (simple strings)
        const merged = [...new Set([...existingArray, ...value])]
        ;(result as any)[key] = merged
      } else {
        // For other arrays (vulnerabilities, files, failedAttempts), just append
        (result as any)[key] = [...existingArray, ...value]
      }
    } else if (typeof value === "object" && !Array.isArray(value)) {
      // Merge objects recursively
      if (typeof existingValue === "object" && !Array.isArray(existingValue)) {
        (result as any)[key] = { ...existingValue, ...value }
      } else {
        (result as any)[key] = value
      }
    } else {
      // Replace scalars
      (result as any)[key] = value
    }
  }

  return result
}

// -----------------------------------------------------------------------------
// Tool Definition
// -----------------------------------------------------------------------------

const DESCRIPTION = `Update the engagement state for the current penetration test session.

This tool maintains shared state between agents, tracking:
- **target**: Target IP and hostname
- **ports**: Discovered ports and services
- **credentials**: Found credentials (usernames, passwords, hashes, keys)
- **vulnerabilities**: Identified vulnerabilities
- **sessions**: Active shell sessions
- **files**: Interesting files found (configs, credentials, flags, SUID binaries)
- **failedAttempts**: What was tried and failed (to avoid repetition)
- **accessLevel**: Current access level (none, user, root)
- **flags**: Captured flags (CTF)

**Merge behavior:**
- Arrays are appended (ports, credentials deduplicated by key fields)
- Scalar values are replaced
- Objects are merged

**Important:** Check \`failedAttempts\` before trying an attack vector. If a similar action already failed, try a different approach.

**Example usage:**
\`\`\`
// Record discovered ports
update_engagement_state({
  ports: [
    { port: 22, protocol: "tcp", service: "ssh", version: "OpenSSH 8.2p1" }
  ]
})

// Record a failed attempt
update_engagement_state({
  failedAttempts: [
    { action: "SSH brute force as root", tool: "hydra", reason: "No valid password found" }
  ]
})

// Update access level after exploitation
update_engagement_state({
  accessLevel: "user",
  sessions: [
    { id: "shell-1", type: "reverse", user: "www-data" }
  ]
})
\`\`\``

const UpdateParametersSchema = z.object({
  target: TargetInfoSchema.optional().describe("Target information (IP, hostname)"),
  ports: z.array(PortInfoSchema).optional().describe("Discovered ports/services to add"),
  credentials: z.array(CredentialInfoSchema).optional().describe("Credentials to add"),
  vulnerabilities: z.array(VulnerabilityInfoSchema).optional().describe("Vulnerabilities to add"),
  sessions: z.array(SessionInfoSchema).optional().describe("Shell sessions to add"),
  files: z.array(FileInfoSchema).optional().describe("Interesting files to add"),
  failedAttempts: z.array(FailedAttemptSchema).optional().describe("Failed attempts to record"),
  accessLevel: z.enum(["none", "user", "root"]).optional().describe("Update access level"),
  flags: z.array(z.string()).optional().describe("Captured flags to add"),
}).passthrough()

export const UpdateEngagementStateTool = Tool.define("update_engagement_state", {
  description: DESCRIPTION,
  parameters: UpdateParametersSchema,
  async execute(params, ctx) {
    const sessionID = ctx.sessionID

    log.info("update_engagement_state called", { sessionID, keys: Object.keys(params) })

    // Load existing state
    const existingState = await loadEngagementState(sessionID)

    // Merge updates
    const newState = mergeState(existingState, params)

    // Save updated state
    await saveEngagementState(sessionID, newState)

    // Build summary of what was updated
    const updates: string[] = []
    if (params.target) updates.push(`target: ${params.target.ip}`)
    if (params.ports?.length) updates.push(`ports: +${params.ports.length}`)
    if (params.credentials?.length) updates.push(`credentials: +${params.credentials.length}`)
    if (params.vulnerabilities?.length) updates.push(`vulnerabilities: +${params.vulnerabilities.length}`)
    if (params.sessions?.length) updates.push(`sessions: +${params.sessions.length}`)
    if (params.files?.length) updates.push(`files: +${params.files.length}`)
    if (params.failedAttempts?.length) updates.push(`failedAttempts: +${params.failedAttempts.length}`)
    if (params.accessLevel) updates.push(`accessLevel: ${params.accessLevel}`)
    if (params.flags?.length) updates.push(`flags: +${params.flags.length}`)

    const summary = updates.length > 0 ? updates.join(", ") : "no changes"

    // Return current state summary
    const stateOverview = [
      `**Engagement State Updated**`,
      ``,
      `Changes: ${summary}`,
      ``,
      `**Current State:**`,
      `- Target: ${newState.target?.ip ?? "not set"}${newState.target?.hostname ? ` (${newState.target.hostname})` : ""}`,
      `- Ports: ${newState.ports?.length ?? 0} discovered`,
      `- Credentials: ${newState.credentials?.length ?? 0} found`,
      `- Vulnerabilities: ${newState.vulnerabilities?.length ?? 0} identified`,
      `- Sessions: ${newState.sessions?.length ?? 0} active`,
      `- Files: ${newState.files?.length ?? 0} of interest`,
      `- Failed Attempts: ${newState.failedAttempts?.length ?? 0} recorded`,
      `- Access Level: ${newState.accessLevel ?? "none"}`,
      `- Flags: ${newState.flags?.length ?? 0} captured`,
    ].join("\n")

    return {
      output: stateOverview,
      title: `update_engagement_state: ${summary}`,
      metadata: {
        updated: Object.keys(params),
        state: {
          ports: newState.ports?.length ?? 0,
          credentials: newState.credentials?.length ?? 0,
          vulnerabilities: newState.vulnerabilities?.length ?? 0,
          sessions: newState.sessions?.length ?? 0,
          accessLevel: newState.accessLevel ?? "none",
          flags: newState.flags?.length ?? 0,
        },
      },
    }
  },
})

// -----------------------------------------------------------------------------
// Read State Tool (for querying current state)
// -----------------------------------------------------------------------------

const READ_DESCRIPTION = `Read the current engagement state for the penetration test session.

Returns the full state including all discoveries, credentials, vulnerabilities, and failed attempts.
Use this to check what has been found and what has been tried before deciding on next steps.

**Important:** Check \`failedAttempts\` before trying an attack vector to avoid repeating failed approaches.`

export const ReadEngagementStateTool = Tool.define("read_engagement_state", {
  description: READ_DESCRIPTION,
  parameters: z.object({}),
  async execute(_params, ctx) {
    const sessionID = ctx.sessionID

    log.info("read_engagement_state called", { sessionID })

    const state = await loadEngagementState(sessionID)

    if (Object.keys(state).length === 0) {
      return {
        output: "No engagement state found. Use `update_engagement_state` to record discoveries.",
        title: "read_engagement_state: empty",
        metadata: {
          empty: true,
          target: undefined,
          ports: 0,
          credentials: 0,
          vulnerabilities: 0,
          accessLevel: "none" as const,
        },
      }
    }

    const output = yaml.dump(state, {
      indent: 2,
      lineWidth: 120,
      noRefs: true,
    })

    return {
      output: `**Current Engagement State:**\n\n\`\`\`yaml\n${output}\`\`\``,
      title: `read_engagement_state: ${state.target?.ip ?? "no target"}`,
      metadata: {
        empty: false,
        target: state.target?.ip,
        ports: state.ports?.length ?? 0,
        credentials: state.credentials?.length ?? 0,
        vulnerabilities: state.vulnerabilities?.length ?? 0,
        accessLevel: state.accessLevel ?? "none",
      },
    }
  },
})

// -----------------------------------------------------------------------------
// Helper for Context Injection (used by Task tool when spawning subagents)
// -----------------------------------------------------------------------------

/**
 * Get engagement state formatted for injection into subagent context.
 * Called by Task tool when spawning pentest subagents.
 */
export async function getEngagementStateForInjection(sessionID: string): Promise<string | null> {
  try {
    const state = await loadEngagementState(sessionID)

    if (Object.keys(state).length === 0) {
      return null
    }

    const stateYaml = yaml.dump(state, {
      indent: 2,
      lineWidth: 120,
      noRefs: true,
    })

    return [
      "## Current Engagement State",
      "",
      "The following discoveries have been made by other agents. Use this information and avoid repeating failed attempts.",
      "",
      "```yaml",
      stateYaml,
      "```",
    ].join("\n")
  } catch (error) {
    log.error("Failed to get engagement state for injection", { error })
    return null
  }
}

/**
 * Get the path to the findings directory for a session.
 * Subagents write detailed findings here (e.g., findings/recon.md).
 */
export async function getFindingsDir(sessionID: string): Promise<string> {
  return ensureFindingsDir(sessionID)
}
