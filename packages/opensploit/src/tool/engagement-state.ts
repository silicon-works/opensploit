/**
 * Engagement State Tool
 *
 * Allows sub-agents to update the shared engagement state with discoveries.
 * This enables sub-agents to persist their findings for other agents to use.
 *
 * Requirements:
 * - REQ-AGT-012: Sub-agents write discoveries to shared state file
 */

import { Tool } from "./tool"
import z from "zod"
import { EngagementState } from "../session/engagement-state"
import { getRootSession } from "../session/hierarchy"
import { Log } from "../util/log"

const log = Log.create({ service: "tool.engagement-state" })

export const EngagementStateTool = Tool.define("update_engagement_state", async () => {
  return {
    description: `Update the shared engagement state with new discoveries.

Use this tool to persist discoveries that should be shared with other sub-agents:
- Ports and services discovered during scanning
- Credentials found during enumeration
- Vulnerabilities identified during testing
- Active shell sessions after exploitation
- Files of interest found during post-exploitation
- Phase progression updates

The state is automatically shared with all sub-agents in the engagement.

Examples:
- Add a discovered port: { ports: [{ port: 22, protocol: "tcp", service: "ssh", state: "open" }] }
- Add credentials: { credentials: [{ username: "admin", password: "secret", source: "config file", validated: false }] }
- Add vulnerability: { vulnerabilities: [{ name: "SQL Injection", severity: "high", service: "web", port: 80, exploitAvailable: true }] }
- Mark vulnerability exploited: { vulnerabilities: [{ name: "SQL Injection", severity: "high", service: "web", exploitAvailable: true, exploited: true, accessGained: "user" }] }
- Add active session: { sessions: [{ id: "ssh-1", type: "ssh", user: "www-data", privileged: false, established: "2024-01-15T10:30:00Z" }] }
- Add file of interest: { files: [{ path: "/etc/shadow", type: "credential" }, { path: "/var/www/config.php", type: "config", notes: "Contains DB password" }] }
- Update phase: { phase: "enumeration" }
- Set access level: { accessLevel: "user" }
- Add captured flag: { flags: ["HTB{example_flag}"] }`,
    parameters: z.object({
      target: z
        .object({
          ip: z.string().optional(),
          hostname: z.string().optional(),
          os: z.string().optional(),
          osVersion: z.string().optional(),
        })
        .optional()
        .describe("Target information to update"),
      ports: z
        .array(
          z.object({
            port: z.number(),
            protocol: z.enum(["tcp", "udp"]),
            service: z.string(),
            version: z.string().optional(),
            banner: z.string().optional(),
            state: z.enum(["open", "filtered", "closed"]),
          })
        )
        .optional()
        .describe("New ports to add to the discovery list"),
      credentials: z
        .array(
          z.object({
            username: z.string(),
            password: z.string().optional(),
            hash: z.string().optional(),
            key: z.string().optional(),
            source: z.string(),
            validated: z.boolean(),
            privileged: z.boolean().optional(),
            validFor: z.array(z.string()).optional(),
          })
        )
        .optional()
        .describe("New credentials to add"),
      vulnerabilities: z
        .array(
          z.object({
            name: z.string(),
            severity: z.enum(["critical", "high", "medium", "low", "info"]),
            service: z.string(),
            port: z.number().optional(),
            cve: z.string().optional(),
            exploitAvailable: z.boolean(),
            exploited: z.boolean().optional(),
            accessGained: z.enum(["none", "user", "root"]).optional(),
            notes: z.string().optional(),
          })
        )
        .optional()
        .describe("New vulnerabilities to add"),
      sessions: z
        .array(
          z.object({
            id: z.string(),
            type: z.enum(["ssh", "reverse", "webshell", "meterpreter", "other"]),
            user: z.string(),
            privileged: z.boolean(),
            target: z.string().optional(),
            established: z.string(),
            notes: z.string().optional(),
          })
        )
        .optional()
        .describe("Active shell sessions to track"),
      files: z
        .array(
          z.object({
            path: z.string(),
            type: z.enum(["config", "credential", "flag", "suid", "writable", "interesting"]),
            content: z.string().optional(),
            notes: z.string().optional(),
          })
        )
        .optional()
        .describe("Files of interest found during engagement"),
      phase: z
        .enum(["reconnaissance", "enumeration", "exploitation", "post-exploitation", "reporting"])
        .optional()
        .describe("Update the current phase"),
      notes: z.array(z.string()).optional().describe("Notes to add to the engagement"),
      flags: z.array(z.string()).optional().describe("Captured flags (for CTF)"),
      accessLevel: z.enum(["none", "user", "root"]).optional().describe("Current access level achieved"),
    }),
    async execute(params, ctx) {
      // Find the root session for this sub-agent
      const rootSessionID = getRootSession(ctx.sessionID)

      log.info("updating engagement state", {
        sessionID: ctx.sessionID,
        rootSessionID,
        hasTarget: !!params.target,
        portsCount: params.ports?.length ?? 0,
        credsCount: params.credentials?.length ?? 0,
        vulnsCount: params.vulnerabilities?.length ?? 0,
        sessionsCount: params.sessions?.length ?? 0,
        filesCount: params.files?.length ?? 0,
        phase: params.phase,
      })

      // Build the update object
      const updates: EngagementState.State = {}

      if (params.target) {
        updates.target = params.target
      }
      if (params.ports && params.ports.length > 0) {
        updates.ports = params.ports
      }
      if (params.credentials && params.credentials.length > 0) {
        updates.credentials = params.credentials
      }
      if (params.vulnerabilities && params.vulnerabilities.length > 0) {
        updates.vulnerabilities = params.vulnerabilities
      }
      if (params.sessions && params.sessions.length > 0) {
        updates.sessions = params.sessions
      }
      if (params.files && params.files.length > 0) {
        updates.files = params.files
      }
      if (params.phase) {
        updates.phase = params.phase
      }
      if (params.notes && params.notes.length > 0) {
        updates.notes = params.notes
      }
      if (params.flags && params.flags.length > 0) {
        updates.flags = params.flags
      }
      if (params.accessLevel) {
        updates.accessLevel = params.accessLevel
      }

      // Update the state
      const newState = EngagementState.update(rootSessionID, updates)

      // Build summary
      const summary: string[] = []
      if (params.ports?.length) summary.push(`${params.ports.length} port(s)`)
      if (params.credentials?.length) summary.push(`${params.credentials.length} credential(s)`)
      if (params.vulnerabilities?.length) summary.push(`${params.vulnerabilities.length} vulnerability(ies)`)
      if (params.sessions?.length) summary.push(`${params.sessions.length} session(s)`)
      if (params.files?.length) summary.push(`${params.files.length} file(s)`)
      if (params.phase) summary.push(`phase: ${params.phase}`)
      if (params.notes?.length) summary.push(`${params.notes.length} note(s)`)
      if (params.flags?.length) summary.push(`${params.flags.length} flag(s)`)
      if (params.accessLevel) summary.push(`access: ${params.accessLevel}`)

      const summaryText = summary.length > 0 ? summary.join(", ") : "no changes"

      return {
        title: `Updated: ${summaryText}`,
        metadata: {},
        output: `Engagement state updated successfully.

**Added/Updated:**
${summaryText}

**Current State Summary:**
- Ports: ${newState.ports?.length ?? 0} discovered
- Credentials: ${newState.credentials?.length ?? 0} found
- Vulnerabilities: ${newState.vulnerabilities?.length ?? 0} identified
- Sessions: ${newState.sessions?.length ?? 0} active
- Files: ${newState.files?.length ?? 0} of interest
- Phase: ${newState.phase ?? "not set"}
- Access: ${newState.accessLevel ?? "none"}
- Flags: ${newState.flags?.length ?? 0} captured`,
      }
    },
  }
})
