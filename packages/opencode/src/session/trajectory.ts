/**
 * Trajectory Module
 *
 * Records and exports TVAR reasoning chains for training data collection.
 * A trajectory is a complete sequence of TVAR (Thought-Verify-Action-Result) steps
 * from a penetration testing session, suitable for fine-tuning LLMs.
 *
 * Requirements (Feature 09):
 * - REQ-RSN-030: Record complete reasoning trajectories
 * - REQ-RSN-031: Store with session data
 * - REQ-RSN-032: Exportable in training-compatible format
 * - REQ-RSN-033: Include timing information
 *
 * Supports:
 * - Anonymization of IPs, hostnames, and credentials
 * - Anti-pattern detection for negative training data
 * - Multiple export formats (JSON, JSONL, ShareGPT)
 */

import { MessageV2 } from "./message-v2"
import { Session } from "."
import { Storage } from "@/storage/storage"
import { Log } from "@/util/log"
import type { Phase } from "./tvar-parser"

const log = Log.create({ service: "trajectory" })

export namespace Trajectory {
  /**
   * Anonymization options for training data
   */
  export interface AnonymizeOptions {
    enabled?: boolean
    ipMapping?: Map<string, string>
    hostnameMapping?: Map<string, string>
  }

  /**
   * Anti-pattern detected in trajectory for negative training
   */
  export interface AntiPattern {
    step: number
    issue: string
    badAction: string
    correctAction?: string
    category: "wrong_tool" | "phase_violation" | "custom_code" | "manual_exploitation"
  }

  /**
   * A single step in the trajectory
   */
  export interface Step {
    step: number
    timestamp: string
    phase?: Phase
    thought: string
    verify: string
    action?: string
    result?: string
    toolCall?: {
      tool: string
      method?: string
      success: boolean
    }
    durationMs?: number
  }

  /**
   * Complete trajectory for a session
   */
  export interface Data {
    sessionID: string
    target?: string
    model: string
    startTime: string
    endTime?: string
    trajectory: Step[]
    outcome?: {
      success: boolean
      accessAchieved?: "none" | "user" | "root"
      flagsCaptured?: string[]
      notes?: string
    }
    antiPatterns?: AntiPattern[]
    metadata?: Record<string, unknown>
  }

  // Regex patterns for anonymization
  const IPV4_PATTERN = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g
  const HOSTNAME_PATTERN = /\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g
  const CREDENTIAL_PATTERN = /(?:password|passwd|pwd|secret|key|token|credential)[\s:=]+["']?([^"'\s]+)["']?/gi

  // Common domains to preserve
  const COMMON_DOMAINS = ["github.com", "google.com", "localhost", "htb", "hackthebox.com"]

  /**
   * Anonymize text by replacing IPs, hostnames, and credentials
   */
  export function anonymizeText(text: string, options: AnonymizeOptions = {}): string {
    if (!options.enabled) return text

    let result = text
    const ipMap = options.ipMapping || new Map<string, string>()
    const hostMap = options.hostnameMapping || new Map<string, string>()

    // Replace IP addresses
    let ipCounter = 1
    result = result.replace(IPV4_PATTERN, (match) => {
      if (!ipMap.has(match)) {
        ipMap.set(match, `10.10.10.${ipCounter++}`)
      }
      return ipMap.get(match)!
    })

    // Replace hostnames (but not common domains)
    result = result.replace(HOSTNAME_PATTERN, (match) => {
      const lowerMatch = match.toLowerCase()
      if (COMMON_DOMAINS.some((d) => lowerMatch.includes(d))) return match
      if (!hostMap.has(match)) {
        hostMap.set(match, `target${hostMap.size + 1}.htb`)
      }
      return hostMap.get(match)!
    })

    // Redact credentials
    result = result.replace(CREDENTIAL_PATTERN, (match, value) => {
      return match.replace(value, "[REDACTED]")
    })

    return result
  }

  /**
   * Anonymize an entire trajectory
   */
  export function anonymize(trajectory: Data): Data {
    const options: AnonymizeOptions = {
      enabled: true,
      ipMapping: new Map(),
      hostnameMapping: new Map(),
    }

    const anonymizedSteps = trajectory.trajectory.map((step) => ({
      ...step,
      thought: anonymizeText(step.thought, options),
      verify: anonymizeText(step.verify, options),
      action: step.action ? anonymizeText(step.action, options) : undefined,
      result: step.result ? anonymizeText(step.result, options) : undefined,
    }))

    return {
      ...trajectory,
      target: trajectory.target ? anonymizeText(trajectory.target, options) : undefined,
      trajectory: anonymizedSteps,
    }
  }

  /**
   * Detect anti-patterns in trajectory for negative training data
   */
  export function detectAntiPatterns(trajectory: Data): AntiPattern[] {
    const antiPatterns: AntiPattern[] = []

    for (const step of trajectory.trajectory) {
      const combined = `${step.thought} ${step.verify} ${step.action || ""}`.toLowerCase()

      // Detect curl misuse for SQL injection
      if (combined.includes("curl") && (combined.includes("sql") || combined.includes("injection"))) {
        antiPatterns.push({
          step: step.step,
          issue: "Using curl for SQL injection testing instead of sqlmap",
          badAction: "curl with SQL payload",
          correctAction: "sqlmap.test_form",
          category: "wrong_tool",
        })
      }

      // Detect curl misuse for brute force
      if (combined.includes("curl") && combined.includes("brute") && combined.includes("force")) {
        antiPatterns.push({
          step: step.step,
          issue: "Using curl for brute force instead of hydra",
          badAction: "curl loop for credential testing",
          correctAction: "hydra.brute_force",
          category: "wrong_tool",
        })
      }

      // Detect custom code patterns
      if (combined.includes("python") && (combined.includes("exploit") || combined.includes("payload"))) {
        antiPatterns.push({
          step: step.step,
          issue: "Writing custom exploit code instead of using MCP tools",
          badAction: "Custom Python exploit",
          correctAction: "exploit-runner or searchsploit",
          category: "custom_code",
        })
      }

      // Detect phase violations
      if (step.phase === "reconnaissance" && (combined.includes("sqlmap") || combined.includes("exploit"))) {
        antiPatterns.push({
          step: step.step,
          issue: "Using exploitation tools during reconnaissance phase",
          badAction: step.toolCall?.tool || "exploitation tool",
          correctAction: "Complete reconnaissance first",
          category: "phase_violation",
        })
      }

      // Detect manual exploitation
      if (combined.includes("manual") && combined.includes("exploit")) {
        antiPatterns.push({
          step: step.step,
          issue: "Attempting manual exploitation instead of using MCP tools",
          badAction: "Manual exploitation",
          correctAction: "Use appropriate MCP tool (sqlmap, hydra, metasploit)",
          category: "manual_exploitation",
        })
      }
    }

    return antiPatterns
  }

  /**
   * Extract trajectory from a session by aggregating TVAR parts
   */
  export async function fromSession(sessionID: string): Promise<Data | null> {
    const messages = await Session.messages({ sessionID })
    if (messages.length === 0) return null

    const steps: Step[] = []
    let stepNum = 1
    let model = "unknown"
    let startTime: number | undefined
    let endTime: number | undefined

    for (const msg of messages) {
      if (msg.info.role === "assistant") {
        model = msg.info.modelID
        if (!startTime) startTime = msg.info.time.created
        if (msg.info.time.completed) endTime = msg.info.time.completed
      }

      for (const part of msg.parts) {
        if (part.type === "tvar") {
          const step: Step = {
            step: stepNum++,
            timestamp: new Date(part.time.start).toISOString(),
            phase: part.phase,
            thought: part.thought,
            verify: part.verify,
            action: part.action,
            result: part.result,
            durationMs: part.time.end ? part.time.end - part.time.start : undefined,
          }

          // Find associated tool call if any
          if (part.toolCallID) {
            const toolPart = msg.parts.find(
              (p): p is MessageV2.ToolPart => p.type === "tool" && p.callID === part.toolCallID,
            )
            if (toolPart) {
              step.toolCall = {
                tool: toolPart.tool,
                success: toolPart.state.status === "completed",
              }
            }
          }

          steps.push(step)
        }
      }
    }

    if (steps.length === 0) return null

    return {
      sessionID,
      model,
      startTime: startTime ? new Date(startTime).toISOString() : new Date().toISOString(),
      endTime: endTime ? new Date(endTime).toISOString() : undefined,
      trajectory: steps,
    }
  }

  /**
   * Export trajectory as JSONL (one JSON object per line)
   * Format suitable for fine-tuning: each line is a complete training example
   */
  export function toJSONL(trajectory: Data): string {
    const lines: string[] = []

    for (const step of trajectory.trajectory) {
      const example = {
        session_id: trajectory.sessionID,
        model: trajectory.model,
        step: step.step,
        phase: step.phase,
        context: {
          objective: step.thought.split("\n")[0],
        },
        output: {
          thought: step.thought,
          verify: step.verify,
          action: step.action,
          result: step.result,
        },
        tool_used: step.toolCall?.tool,
        tool_success: step.toolCall?.success,
        duration_ms: step.durationMs,
      }
      lines.push(JSON.stringify(example))
    }

    return lines.join("\n")
  }

  /**
   * Export trajectory in ShareGPT format for fine-tuning
   */
  export function toShareGPT(trajectory: Data): string {
    const conversations: Array<{
      id: string
      conversations: Array<{ from: string; value: string }>
    }> = []

    const convo = {
      id: trajectory.sessionID,
      conversations: [] as Array<{ from: string; value: string }>,
    }

    for (const step of trajectory.trajectory) {
      // System provides context for first step
      if (step.step === 1) {
        convo.conversations.push({
          from: "system",
          value: `You are a penetration testing agent. Phase: ${step.phase || "unknown"}`,
        })
      }

      // User turn (simulated task from objective)
      convo.conversations.push({
        from: "human",
        value: step.thought.split("\n")[0],
      })

      // Assistant turn (TVAR response)
      const tvarResponse = `<thought>
${step.thought}
</thought>

<verify>
${step.verify}
</verify>

${step.action ? `<action>\n${step.action}\n</action>\n\n` : ""}${step.result ? `<result>\n${step.result}\n</result>` : ""}`

      convo.conversations.push({
        from: "gpt",
        value: tvarResponse,
      })
    }

    conversations.push(convo)
    return JSON.stringify(conversations, null, 2)
  }

  /**
   * Save trajectory to storage for later export
   */
  export async function save(trajectory: Data): Promise<void> {
    await Storage.write(["trajectory", trajectory.sessionID], trajectory)
    log.info("saved", { sessionID: trajectory.sessionID, steps: trajectory.trajectory.length })
  }

  /**
   * Load trajectory from storage
   */
  export async function load(sessionID: string): Promise<Data | null> {
    try {
      return await Storage.read<Data>(["trajectory", sessionID])
    } catch {
      return null
    }
  }

  /**
   * List all saved trajectories
   */
  export async function list(): Promise<string[]> {
    const items = await Storage.list(["trajectory"])
    return items.map((item) => item[1])
  }

  /**
   * Format trajectory as human-readable text
   */
  export function formatAsText(trajectory: Data): string {
    const lines: string[] = []

    lines.push(`# Trajectory: ${trajectory.sessionID}`)
    lines.push(`Model: ${trajectory.model}`)
    lines.push(`Start: ${trajectory.startTime}`)
    if (trajectory.endTime) lines.push(`End: ${trajectory.endTime}`)
    lines.push("")
    lines.push("## Steps")
    lines.push("")

    for (const step of trajectory.trajectory) {
      const phase = step.phase ? ` (${step.phase})` : ""
      lines.push(`### Step ${step.step}${phase}`)
      lines.push("")
      lines.push(`**Thought**: ${step.thought}`)
      lines.push("")
      lines.push(`**Verify**: ${step.verify}`)
      if (step.action) {
        lines.push("")
        lines.push(`**Action**: ${step.action}`)
      }
      if (step.result) {
        lines.push("")
        lines.push(`**Result**: ${step.result}`)
      }
      if (step.toolCall) {
        lines.push("")
        lines.push(`**Tool**: ${step.toolCall.tool} (${step.toolCall.success ? "success" : "failed"})`)
      }
      lines.push("")
    }

    if (trajectory.outcome) {
      lines.push("## Outcome")
      lines.push("")
      lines.push(`Success: ${trajectory.outcome.success}`)
      if (trajectory.outcome.accessAchieved) {
        lines.push(`Access: ${trajectory.outcome.accessAchieved}`)
      }
      if (trajectory.outcome.flagsCaptured?.length) {
        lines.push(`Flags: ${trajectory.outcome.flagsCaptured.join(", ")}`)
      }
    }

    return lines.join("\n")
  }
}
