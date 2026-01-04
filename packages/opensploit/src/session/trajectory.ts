/**
 * Trajectory Module - Records and exports TVAR reasoning chains for training data
 *
 * A trajectory is a complete sequence of TVAR (Thought-Verify-Action-Result) steps
 * from a penetration testing session, suitable for fine-tuning LLMs.
 */

import { MessageV2 } from "./message-v2"
import { Session } from "."
import { Storage } from "@/storage/storage"
import { Identifier } from "@/id/id"

export namespace Trajectory {
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
    metadata?: Record<string, unknown>
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
