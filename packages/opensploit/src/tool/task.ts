import { Tool } from "./tool"
import DESCRIPTION from "./task.txt"
import z from "zod"
import { Session } from "../session"
import { Bus } from "../bus"
import { MessageV2 } from "../session/message-v2"
import { Identifier } from "../id/id"
import { Agent } from "../agent/agent"
import { SessionPrompt } from "../session/prompt"
import { iife } from "@/util/iife"
import { defer } from "@/util/defer"
import { Config } from "../config/config"
import { SessionDirectory } from "../session/directory"
import { EngagementState } from "../session/engagement-state"
import { BackgroundTask } from "../session/background-task"
import { registerRootSession } from "../session/hierarchy"
import { Log } from "../util/log"

const log = Log.create({ service: "tool.task" })

/**
 * Find the root (top-level) session ID by traversing parent chain
 */
async function findRootSession(sessionID: string): Promise<string> {
  let current = await Session.get(sessionID)
  while (current.parentID) {
    current = await Session.get(current.parentID)
  }
  return current.id
}

export const TaskTool = Tool.define("task", async () => {
  const agents = await Agent.list().then((x) => x.filter((a) => a.mode !== "primary"))
  const description = DESCRIPTION.replace(
    "{agents}",
    agents
      .map((a) => `- ${a.name}: ${a.description ?? "This subagent should only be called manually by the user."}`)
      .join("\n"),
  )
  return {
    description,
    parameters: z.object({
      description: z.string().describe("A short (3-5 words) description of the task"),
      prompt: z.string().describe("The task for the agent to perform"),
      subagent_type: z.string().describe("The type of specialized agent to use for this task"),
      session_id: z.string().describe("Existing Task session to continue").optional(),
      command: z.string().describe("The command that triggered this task").optional(),
      background: z.boolean().describe("Run task in background (non-blocking). Defaults to true for sub-agents.").optional(),
    }),
    async execute(params, ctx) {
      const agent = await Agent.get(params.subagent_type)
      if (!agent) throw new Error(`Unknown agent type: ${params.subagent_type} is not a valid agent type`)

      // Default to background mode for sub-agents (user stays in parent session)
      const runInBackground = params.background ?? true

      const session = await iife(async () => {
        if (params.session_id) {
          const found = await Session.get(params.session_id).catch(() => {})
          if (found) return found
        }

        return await Session.create({
          parentID: ctx.sessionID,
          title: params.description + ` (@${agent.name} subagent)`,
          background: runInBackground,
        })
      })
      const msg = await MessageV2.get({ sessionID: ctx.sessionID, messageID: ctx.messageID })
      if (msg.info.role !== "assistant") throw new Error("Not an assistant message")

      // Find root session and get session directory
      const rootSessionID = await findRootSession(ctx.sessionID)
      const sessionDir = SessionDirectory.get(rootSessionID)

      // Register this session in the hierarchy for permission bubbling
      registerRootSession(session.id, rootSessionID)
      log.info("registered session hierarchy", { sessionID: session.id, rootSessionID })

      // Ensure session directory exists (create if this is the first sub-agent)
      if (!SessionDirectory.exists(rootSessionID)) {
        SessionDirectory.create(rootSessionID)
        log.info("created session directory for root", { rootSessionID, sessionDir })
      }

      const messageID = Identifier.ascending("message")
      const model = agent.model ?? {
        modelID: msg.info.modelID,
        providerID: msg.info.providerID,
      }

      // Get engagement state context
      const stateContext = EngagementState.formatForPrompt(rootSessionID, sessionDir)

      // Build enhanced prompt with context injection
      const contextualizedPrompt = `${stateContext}

## Your Task
${params.prompt}`

      log.info("context injection", {
        rootSessionID,
        sessionDir,
        hasState: !!EngagementState.read(rootSessionID),
        promptLength: contextualizedPrompt.length,
      })

      const promptParts = await SessionPrompt.resolvePromptParts(contextualizedPrompt)
      const config = await Config.get()

      // Common prompt config
      const promptConfig = {
        messageID,
        sessionID: session.id,
        model: {
          modelID: model.modelID,
          providerID: model.providerID,
        },
        agent: agent.name,
        tools: {
          todowrite: false,
          todoread: false,
          task: false,
          ...Object.fromEntries((config.experimental?.primary_tools ?? []).map((t) => [t, false])),
          ...agent.tools,
        },
        parts: promptParts,
      }

      // Background execution mode
      if (runInBackground) {
        const taskID = session.id

        // Register the background task
        BackgroundTask.register({
          id: taskID,
          sessionID: session.id,
          rootSessionID,
          agentName: agent.name,
          description: params.description,
          status: "running",
          startTime: Date.now(),
          pendingApprovals: 0,
        })

        // Set up status update listener
        const unsub = Bus.subscribe(MessageV2.Event.PartUpdated, async (evt) => {
          if (evt.properties.part.sessionID !== session.id) return
          if (evt.properties.part.type !== "tool") return
          const part = evt.properties.part
          // Update background task status based on tool activity
          BackgroundTask.update(rootSessionID, taskID, { status: "running" })
        })

        // Execute prompt in background (fire and forget)
        SessionPrompt.prompt(promptConfig)
          .then((result) => {
            unsub()
            const text = result.parts.findLast((x) => x.type === "text")?.text ?? ""
            BackgroundTask.complete(rootSessionID, taskID, text)
          })
          .catch((error) => {
            unsub()
            BackgroundTask.fail(rootSessionID, taskID, error.message ?? String(error))
          })

        ctx.metadata({
          title: `${params.description} (background)`,
          metadata: {
            sessionId: session.id,
            background: true,
            taskId: taskID,
          },
        })

        const result: {
          title: string
          metadata: {
            sessionId: string
            background: boolean
            taskId: string | undefined
            summary: { id: string; tool: string; state: { status: string; title?: string } }[]
          }
          output: string
        } = {
          title: `${params.description} (background)`,
          metadata: {
            sessionId: session.id,
            background: true,
            taskId: taskID,
            summary: [],
          },
          output: `Background task started: ${params.description}\n\nTask ID: ${taskID}\nAgent: @${agent.name}\nSession: ${session.id}\n\nYou can continue working while this task runs in the background. Use the engagement-log command to see all activity.`,
        }
        return result
      }

      // Foreground execution (original behavior)
      ctx.metadata({
        title: params.description,
        metadata: {
          sessionId: session.id,
        },
      })

      const parts: Record<string, { id: string; tool: string; state: { status: string; title?: string } }> = {}
      const unsub = Bus.subscribe(MessageV2.Event.PartUpdated, async (evt) => {
        if (evt.properties.part.sessionID !== session.id) return
        if (evt.properties.part.messageID === messageID) return
        if (evt.properties.part.type !== "tool") return
        const part = evt.properties.part
        parts[part.id] = {
          id: part.id,
          tool: part.tool,
          state: {
            status: part.state.status,
            title: part.state.status === "completed" ? part.state.title : undefined,
          },
        }
        ctx.metadata({
          title: params.description,
          metadata: {
            summary: Object.values(parts).sort((a, b) => a.id.localeCompare(b.id)),
            sessionId: session.id,
          },
        })
      })

      function cancel() {
        SessionPrompt.cancel(session.id)
      }
      ctx.abort.addEventListener("abort", cancel)
      using _ = defer(() => ctx.abort.removeEventListener("abort", cancel))

      const result = await SessionPrompt.prompt(promptConfig)
      unsub()
      const messages = await Session.messages({ sessionID: session.id })
      const summary = messages
        .filter((x) => x.info.role === "assistant")
        .flatMap((msg) => msg.parts.filter((x: any) => x.type === "tool") as MessageV2.ToolPart[])
        .map((part) => ({
          id: part.id,
          tool: part.tool,
          state: {
            status: part.state.status,
            title: part.state.status === "completed" ? part.state.title : undefined,
          },
        }))
      const text = result.parts.findLast((x) => x.type === "text")?.text ?? ""

      const output = text + "\n\n" + ["<task_metadata>", `session_id: ${session.id}`, "</task_metadata>"].join("\n")

      const foregroundResult: {
        title: string
        metadata: {
          sessionId: string
          background: boolean
          taskId: string | undefined
          summary: { id: string; tool: string; state: { status: string; title?: string } }[]
        }
        output: string
      } = {
        title: params.description,
        metadata: {
          summary,
          sessionId: session.id,
          background: false,
          taskId: undefined,
        },
        output,
      }
      return foregroundResult
    },
  }
})
