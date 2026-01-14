import z from "zod"
import { Tool } from "./tool"
import path from "path"
import os from "os"
import fs from "fs/promises"
import { Log } from "../util/log"

const log = Log.create({ service: "tool.target-tracker" })

// =============================================================================
// Stub Implementation for Feature 07 (Target State Tracking)
// =============================================================================
// This is a simplified stub that stores engagement state in a JSON file.
// Full implementation will include:
// - Session-scoped state management
// - Structured findings storage
// - Integration with MCP tools for automatic state updates

const STATE_DIR = path.join(os.homedir(), ".opensploit", "sessions")

const PortInfoSchema = z.object({
  port: z.number(),
  protocol: z.enum(["tcp", "udp"]),
  service: z.string().optional(),
  version: z.string().optional(),
  state: z.enum(["open", "closed", "filtered"]).default("open"),
})

const CredentialInfoSchema = z.object({
  username: z.string(),
  password: z.string().optional(),
  hash: z.string().optional(),
  service: z.string(),
  source: z.string(),
})

const VulnInfoSchema = z.object({
  id: z.string(),
  name: z.string(),
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
  service: z.string().optional(),
  port: z.number().optional(),
  evidence: z.string().optional(),
})

const EngagementStateSchema = z.object({
  target: z.object({
    ip: z.string(),
    hostname: z.string().optional(),
    scope: z.array(z.string()).default([]),
  }),
  ports: z.array(PortInfoSchema).default([]),
  credentials: z.array(CredentialInfoSchema).default([]),
  vulnerabilities: z.array(VulnInfoSchema).default([]),
  accessLevel: z.enum(["none", "user", "root"]).default("none"),
  flags: z.array(z.string()).default([]),
  notes: z.array(z.string()).default([]),
  lastUpdated: z.string().optional(),
})

type EngagementState = z.infer<typeof EngagementStateSchema>

async function ensureStateDir(): Promise<void> {
  try {
    await fs.mkdir(STATE_DIR, { recursive: true })
  } catch {
    // Directory may already exist
  }
}

function getStatePath(sessionId: string): string {
  return path.join(STATE_DIR, sessionId, "state.json")
}

async function loadState(sessionId: string): Promise<EngagementState> {
  try {
    const statePath = getStatePath(sessionId)
    const content = await fs.readFile(statePath, "utf-8")
    return EngagementStateSchema.parse(JSON.parse(content))
  } catch {
    // Return default state if file doesn't exist
    return {
      target: { ip: "", scope: [] },
      ports: [],
      credentials: [],
      vulnerabilities: [],
      accessLevel: "none",
      flags: [],
      notes: [],
    }
  }
}

async function saveState(sessionId: string, state: EngagementState): Promise<void> {
  await ensureStateDir()
  const sessionDir = path.join(STATE_DIR, sessionId)
  await fs.mkdir(sessionDir, { recursive: true })

  state.lastUpdated = new Date().toISOString()
  await fs.writeFile(getStatePath(sessionId), JSON.stringify(state, null, 2), "utf-8")
}

const DESCRIPTION = `Track and manage engagement state for penetration testing sessions.

This tool maintains the current state of a security assessment including:
- Target information (IP, hostname, scope)
- Discovered ports and services
- Found credentials
- Identified vulnerabilities
- Current access level
- Captured flags

Use this tool to persist findings across tool invocations and share state between agents.

**Note:** This is a stub implementation. Full version (Feature 07) will include
structured storage, automatic MCP integration, and advanced querying.`

export const TargetTrackerTool = Tool.define("target_tracker", {
  description: DESCRIPTION,
  parameters: z.object({
    action: z.enum(["get", "set", "add_port", "add_credential", "add_vuln", "add_flag", "add_note", "set_access"])
      .describe("Action to perform on the engagement state"),
    session_id: z.string().describe("Session ID to scope the state"),
    data: z.any().optional().describe("Data for the action (varies by action type)"),
  }),
  async execute(params, ctx) {
    const { action, session_id, data } = params

    log.info("target_tracker action", { action, session_id })

    let state = await loadState(session_id)
    let output = ""

    switch (action) {
      case "get":
        output = JSON.stringify(state, null, 2)
        break

      case "set":
        if (data) {
          state = EngagementStateSchema.parse(data)
          await saveState(session_id, state)
          output = "State updated successfully"
        } else {
          output = "Error: 'data' required for 'set' action"
        }
        break

      case "add_port":
        if (data) {
          const port = PortInfoSchema.parse(data)
          // Avoid duplicates
          const exists = state.ports.some(p => p.port === port.port && p.protocol === port.protocol)
          if (!exists) {
            state.ports.push(port)
            await saveState(session_id, state)
            output = `Added port ${port.port}/${port.protocol}`
          } else {
            output = `Port ${port.port}/${port.protocol} already exists`
          }
        } else {
          output = "Error: 'data' required for 'add_port' action"
        }
        break

      case "add_credential":
        if (data) {
          const cred = CredentialInfoSchema.parse(data)
          state.credentials.push(cred)
          await saveState(session_id, state)
          output = `Added credential: ${cred.username} for ${cred.service}`
        } else {
          output = "Error: 'data' required for 'add_credential' action"
        }
        break

      case "add_vuln":
        if (data) {
          const vuln = VulnInfoSchema.parse(data)
          state.vulnerabilities.push(vuln)
          await saveState(session_id, state)
          output = `Added vulnerability: ${vuln.name} (${vuln.severity})`
        } else {
          output = "Error: 'data' required for 'add_vuln' action"
        }
        break

      case "add_flag":
        if (data && typeof data === "string") {
          if (!state.flags.includes(data)) {
            state.flags.push(data)
            await saveState(session_id, state)
            output = `Added flag: ${data}`
          } else {
            output = `Flag already captured: ${data}`
          }
        } else {
          output = "Error: 'data' (string) required for 'add_flag' action"
        }
        break

      case "add_note":
        if (data && typeof data === "string") {
          state.notes.push(data)
          await saveState(session_id, state)
          output = `Added note: ${data}`
        } else {
          output = "Error: 'data' (string) required for 'add_note' action"
        }
        break

      case "set_access":
        if (data && ["none", "user", "root"].includes(data)) {
          state.accessLevel = data as "none" | "user" | "root"
          await saveState(session_id, state)
          output = `Access level set to: ${data}`
        } else {
          output = "Error: 'data' must be 'none', 'user', or 'root'"
        }
        break

      default:
        output = `Unknown action: ${action}`
    }

    return {
      output,
      title: `target_tracker: ${action}`,
      metadata: { action, session_id },
    }
  },
})
