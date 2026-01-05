/**
 * Trajectory Module - Records and exports TVAR reasoning chains for training data
 *
 * A trajectory is a complete sequence of TVAR (Thought-Verify-Action-Result) steps
 * from a penetration testing session, suitable for fine-tuning LLMs.
 *
 * Supports:
 * - Anonymization of IPs, hostnames, and credentials (REQ-TRN-003)
 * - Outcome tracking for quality filtering (REQ-TRN-004)
 * - Anti-pattern detection for negative training (REQ-TRN-030)
 */

import { MessageV2 } from "./message-v2"
import { Session } from "."
import { Storage } from "@/storage/storage"
import { Identifier } from "@/id/id"

export namespace Trajectory {
  /**
   * Anonymization options
   */
  export interface AnonymizeOptions {
    enabled?: boolean
    ipMapping?: Map<string, string>
    hostnameMapping?: Map<string, string>
  }

  /**
   * Anti-pattern detection for negative training data
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
    phase?: "reconnaissance" | "enumeration" | "exploitation" | "post_exploitation" | "reporting"
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

  // IP address regex patterns
  const IPV4_PATTERN = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g
  const HOSTNAME_PATTERN = /\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g
  const CREDENTIAL_PATTERN = /(?:password|passwd|pwd|secret|key|token|credential)[\s:=]+["']?([^"'\s]+)["']?/gi

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

    // Replace hostnames (but not common domains like github.com)
    const commonDomains = ["github.com", "google.com", "localhost", "htb", "hackthebox.com"]
    result = result.replace(HOSTNAME_PATTERN, (match) => {
      const lowerMatch = match.toLowerCase()
      if (commonDomains.some((d) => lowerMatch.includes(d))) return match
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

      // Detect wrong tool usage
      if (combined.includes("curl") && (combined.includes("sql") || combined.includes("injection"))) {
        antiPatterns.push({
          step: step.step,
          issue: "Using curl for SQL injection testing instead of sqlmap",
          badAction: "curl with SQL payload",
          correctAction: "sqlmap.test_form",
          category: "wrong_tool",
        })
      }

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
   * Engagement-wide log entry for consolidated view
   */
  export interface EngagementLogEntry {
    timestamp: string
    agentName: string
    sessionID: string
    phase?: string
    type: "tvar" | "tool" | "text"
    summary: string
    details?: {
      tool?: string
      toolStatus?: string
      thought?: string
      action?: string
      result?: string
    }
    durationMs?: number
  }

  /**
   * Engagement log aggregating all sub-agent activity
   */
  export interface EngagementLog {
    rootSessionID: string
    startTime: string
    endTime?: string
    entries: EngagementLogEntry[]
    summary: {
      totalAgents: number
      agentNames: string[]
      toolCalls: number
      successfulTools: number
      failedTools: number
      phases: string[]
    }
  }

  /**
   * Get all child sessions recursively
   */
  async function getChildSessions(sessionID: string): Promise<Session.Info[]> {
    const children = await Session.children(sessionID)
    const all: Session.Info[] = [...children]
    for (const child of children) {
      const grandchildren = await getChildSessions(child.id)
      all.push(...grandchildren)
    }
    return all
  }

  /**
   * Extract agent name from session title
   */
  function extractAgentName(title: string): string {
    const match = title.match(/@(\w+)\s+subagent/)
    return match ? match[1] : "unknown"
  }

  /**
   * Create engagement log from root session and all sub-agents
   * This provides a consolidated view of all activity across the engagement
   */
  export async function fromEngagement(rootSessionID: string): Promise<EngagementLog> {
    const entries: EngagementLogEntry[] = []
    const agentSet = new Set<string>()
    const phaseSet = new Set<string>()
    let toolCalls = 0
    let successfulTools = 0
    let failedTools = 0
    let startTime: number | undefined
    let endTime: number | undefined

    // Get root session info
    const rootSession = await Session.get(rootSessionID)
    if (rootSession.time.created) startTime = rootSession.time.created

    // Process root session
    await processSession(rootSessionID, "master", entries, agentSet, phaseSet, {
      onToolCall: () => toolCalls++,
      onToolSuccess: () => successfulTools++,
      onToolFail: () => failedTools++,
    })

    // Get all child sessions and process them
    const children = await getChildSessions(rootSessionID)
    for (const child of children) {
      const agentName = extractAgentName(child.title)
      agentSet.add(agentName)
      if (child.time.updated && (!endTime || child.time.updated > endTime)) {
        endTime = child.time.updated
      }
      await processSession(child.id, agentName, entries, agentSet, phaseSet, {
        onToolCall: () => toolCalls++,
        onToolSuccess: () => successfulTools++,
        onToolFail: () => failedTools++,
      })
    }

    // Sort entries by timestamp
    entries.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())

    return {
      rootSessionID,
      startTime: startTime ? new Date(startTime).toISOString() : new Date().toISOString(),
      endTime: endTime ? new Date(endTime).toISOString() : undefined,
      entries,
      summary: {
        totalAgents: agentSet.size,
        agentNames: Array.from(agentSet),
        toolCalls,
        successfulTools,
        failedTools,
        phases: Array.from(phaseSet),
      },
    }
  }

  /**
   * Process a single session and add entries to the log
   */
  async function processSession(
    sessionID: string,
    agentName: string,
    entries: EngagementLogEntry[],
    agentSet: Set<string>,
    phaseSet: Set<string>,
    callbacks: {
      onToolCall: () => void
      onToolSuccess: () => void
      onToolFail: () => void
    },
  ): Promise<void> {
    agentSet.add(agentName)
    const messages = await Array.fromAsync(MessageV2.stream(sessionID))

    for (const msg of messages) {
      for (const part of msg.parts) {
        if (part.type === "tvar") {
          if (part.phase) phaseSet.add(part.phase)
          entries.push({
            timestamp: new Date(part.time.start).toISOString(),
            agentName,
            sessionID,
            phase: part.phase,
            type: "tvar",
            summary: part.thought.split("\n")[0].substring(0, 100),
            details: {
              thought: part.thought,
              action: part.action,
              result: part.result,
            },
            durationMs: part.time.end ? part.time.end - part.time.start : undefined,
          })
        } else if (part.type === "tool") {
          callbacks.onToolCall()
          const state = part.state
          let title: string | undefined
          let startMs: number | undefined
          let endMs: number | undefined

          if (state.status === "completed") {
            callbacks.onToolSuccess()
            title = state.title
            startMs = state.time?.start
            endMs = state.time?.end
          } else if (state.status === "error") {
            callbacks.onToolFail()
            title = state.error
            startMs = state.time?.start
            endMs = state.time?.end
          } else if (state.status === "running") {
            title = part.tool
            startMs = state.time?.start
          } else {
            title = part.tool
          }

          entries.push({
            timestamp: startMs ? new Date(startMs).toISOString() : new Date().toISOString(),
            agentName,
            sessionID,
            type: "tool",
            summary: `${part.tool}: ${title?.substring(0, 80) || ""}`,
            details: {
              tool: part.tool,
              toolStatus: state.status,
            },
            durationMs: startMs && endMs ? endMs - startMs : undefined,
          })
        }
      }
    }
  }

  /**
   * Format engagement log for display
   */
  export function formatEngagementLog(log: EngagementLog): string {
    const lines: string[] = []
    lines.push(`# Engagement Log`)
    lines.push(`Root Session: ${log.rootSessionID}`)
    lines.push(`Start: ${log.startTime}`)
    if (log.endTime) lines.push(`End: ${log.endTime}`)
    lines.push("")
    lines.push(`## Summary`)
    lines.push(`- Agents: ${log.summary.agentNames.join(", ")}`)
    lines.push(`- Tool Calls: ${log.summary.toolCalls} (${log.summary.successfulTools} success, ${log.summary.failedTools} failed)`)
    lines.push(`- Phases: ${log.summary.phases.join(" → ")}`)
    lines.push("")
    lines.push(`## Timeline`)
    lines.push("")

    let lastAgent = ""
    for (const entry of log.entries) {
      const time = entry.timestamp.split("T")[1]?.substring(0, 8) || ""
      const agent = entry.agentName !== lastAgent ? `[${entry.agentName}]` : "".padStart(entry.agentName.length + 2)
      lastAgent = entry.agentName
      const phase = entry.phase ? `(${entry.phase.substring(0, 5)})` : ""
      const icon = entry.type === "tool" ? "🔧" : entry.type === "tvar" ? "💭" : "📝"
      const duration = entry.durationMs ? `(${entry.durationMs}ms)` : ""
      lines.push(`${time} ${agent} ${icon} ${phase} ${entry.summary} ${duration}`)
    }

    return lines.join("\n")
  }

  /**
   * Extract trajectory from a session by aggregating TVAR parts
   */
  export async function fromSession(sessionID: string): Promise<Data | null> {
    const messages = await Array.fromAsync(MessageV2.stream(sessionID))
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
              (p) => p.type === "tool" && p.callID === part.toolCallID,
            ) as MessageV2.ToolPart | undefined
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

    // Export as conversation-style training data
    for (const step of trajectory.trajectory) {
      const example = {
        session_id: trajectory.sessionID,
        model: trajectory.model,
        step: step.step,
        phase: step.phase,
        // Input context
        context: {
          objective: step.thought.split("\n")[0], // First line as objective
        },
        // Expected output
        output: {
          thought: step.thought,
          verify: step.verify,
          action: step.action,
          result: step.result,
        },
        // Metadata
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

    // Group steps into conversation turns
    const convo = {
      id: trajectory.sessionID,
      conversations: [] as Array<{ from: string; value: string }>,
    }

    for (const step of trajectory.trajectory) {
      // System provides context
      if (step.step === 1) {
        convo.conversations.push({
          from: "system",
          value: `You are a penetration testing agent. Phase: ${step.phase || "unknown"}`,
        })
      }

      // User turn (simulated task)
      convo.conversations.push({
        from: "human",
        value: step.thought.split("\n")[0], // Objective as user request
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
}
