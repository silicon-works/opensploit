import { Tool } from "./tool"
import DESCRIPTION from "./task.txt"
import z from "zod"
import path from "path"
import { Session } from "../session"
import { SessionID, MessageID } from "../session/schema"
import { MessageV2 } from "../session/message-v2"
import { Identifier } from "../id/id"
import { Agent } from "../agent/agent"
import { SessionPrompt } from "../session/prompt"
import { iife } from "@/util/iife"
import { defer } from "@/util/defer"
import { Config } from "../config/config"
import { PermissionNext } from "@/permission/next"
import { getEngagementStateForInjection } from "./engagement-state"
import { registerRootSession, hasParent } from "../session/hierarchy"
import * as SessionDirectory from "../session/directory"
import { Log } from "../util/log"

const log = Log.create({ service: "tool.task" })

// -----------------------------------------------------------------------------
// Helper: Get Root Session ID
// -----------------------------------------------------------------------------
// Walks up the parent chain to find the root session for state sharing.

async function getRootSessionID(sessionID: string): Promise<string> {
  let currentID = sessionID
  while (true) {
    const session = await Session.get(currentID as SessionID)
    if (!session.parentID) {
      return currentID
    }
    currentID = session.parentID
  }
}

// -----------------------------------------------------------------------------
// Helper: Check if this is a pentest subagent
// -----------------------------------------------------------------------------
// Pentest subagents are identified by their agent type starting with "pentest/"
// This includes pentest/recon, pentest/enum, pentest/exploit, etc.
// The master "pentest" agent is handled separately (it's a primary agent).

function isPentestSubagent(agentName: string): boolean {
  return agentName.startsWith("pentest/")
}

const parameters = z.object({
  description: z.string().describe("A short (3-5 words) description of the task"),
  prompt: z.string().describe("The task for the agent to perform"),
  subagent_type: z.string().describe("The type of specialized agent to use for this task"),
  task_id: z
    .string()
    .describe(
      "This should only be set if you mean to resume a previous task (you can pass a prior task_id and the task will continue the same subagent session as before instead of creating a fresh one)",
    )
    .optional(),
  command: z.string().describe("The command that triggered this task").optional(),
})

export const TaskTool = Tool.define("task", async (ctx) => {
  const agents = await Agent.list().then((x) => x.filter((a) => a.mode !== "primary"))

  // Filter agents by permissions if agent provided
  const caller = ctx?.agent
  const accessibleAgents = caller
    ? agents.filter((a) => PermissionNext.evaluate("task", a.name, caller.permission).action !== "deny")
    : agents

  const description = DESCRIPTION.replace(
    "{agents}",
    accessibleAgents
      .map((a) => `- ${a.name}: ${a.description ?? "This subagent should only be called manually by the user."}`)
      .join("\n"),
  )
  return {
    description,
    parameters,
    async execute(params: z.infer<typeof parameters>, ctx) {
      const config = await Config.get()

      // Skip permission check when:
      // 1. User explicitly invoked via @ or command subtask (bypassAgentCheck)
      // 2. Spawning pentest subagents (pentest/* agents are part of authorized methodology)
      if (!ctx.extra?.bypassAgentCheck && !isPentestSubagent(params.subagent_type)) {
        await ctx.ask({
          permission: "task",
          patterns: [params.subagent_type],
          always: ["*"],
          metadata: {
            description: params.description,
            subagent_type: params.subagent_type,
          },
        })
      }

      const agent = await Agent.get(params.subagent_type)
      if (!agent) throw new Error(`Unknown agent type: ${params.subagent_type} is not a valid agent type`)

      // Find root session for hierarchy tracking and state sharing
      const rootSessionID = await getRootSessionID(ctx.sessionID)

      // Pentest sub-agents get TodoWrite + depth-limited task spawning
      const isPentest = isPentestSubagent(params.subagent_type)
      // First-level pentest sub-agents (spawned by master) can spawn further pentest/* agents.
      // Second-level (spawned by sub-agents) cannot — they are leaf agents.
      const canChildSpawn = isPentest && !hasParent(ctx.sessionID)
      const sessionDirRule = {
        permission: "external_directory",
        pattern: path.join(SessionDirectory.get(rootSessionID), "*"),
        action: "ask" as const,
      }

      const session = await iife(async () => {
        if (params.task_id) {
          const found = await Session.get(SessionID.make(params.task_id)).catch(() => {})
          if (found) return found
        }

        return await Session.create({
          parentID: ctx.sessionID,
          title: params.description + ` (@${agent.name} subagent)`,
          objective: params.prompt,
          permission: [
            // TodoWrite/TodoRead: enabled for pentest sub-agents, denied for others
            ...(isPentest ? [] : [
              { permission: "todowrite", pattern: "*", action: "deny" as const },
              { permission: "todoread", pattern: "*", action: "deny" as const },
            ]),
            // Task spawning: allow pentest/* for first-level sub-agents, deny for deeper
            ...(canChildSpawn ? [
              { permission: "task" as const, pattern: "*" as const, action: "deny" as const },
              { permission: "task" as const, pattern: "pentest/*" as const, action: "allow" as const },
            ] : [
              { permission: "task" as const, pattern: "*" as const, action: "deny" as const },
            ]),
            sessionDirRule,
            ...(config.experimental?.primary_tools?.map((t) => ({
              pattern: "*",
              action: "allow" as const,
              permission: t,
            })) ?? []),
          ],
        })
      })

      if (
        !session.permission?.some(
          (rule) => rule.permission === sessionDirRule.permission && rule.pattern === sessionDirRule.pattern,
        )
      ) {
        await Session.setPermission({
          sessionID: session.id,
          permission: [...(session.permission ?? []), sessionDirRule],
        })
      }

      // Register hierarchy for permission bubbling (Feature 04)
      registerRootSession(session.id, rootSessionID)
      log.info("registered hierarchy", {
        sessionID: session.id.slice(-8),
        rootSessionID: rootSessionID.slice(-8),
        agent: agent.name,
      })

      const msg = await MessageV2.get({ sessionID: ctx.sessionID, messageID: ctx.messageID })
      if (msg.info.role !== "assistant") throw new Error("Not an assistant message")

      const model = agent.model ?? {
        modelID: msg.info.modelID,
        providerID: msg.info.providerID,
      }

      ctx.metadata({
        title: params.description,
        metadata: {
          sessionId: session.id,
          model,
        },
      })

      const messageID = MessageID.ascending()

      function cancel() {
        SessionPrompt.cancel(session.id)
      }
      ctx.abort.addEventListener("abort", cancel)
      using _ = defer(() => ctx.abort.removeEventListener("abort", cancel))

      // -------------------------------------------------------------------------
      // Context Injection for Pentest Session Tree (Feature 04)
      // -------------------------------------------------------------------------
      // When spawning pentest/* subagents, inject:
      // - Session working directory path
      // - Current engagement state (target, ports, creds, vulns, failed attempts)
      //
      // Also inject for other agents (general, explore) if engagement state exists,
      // allowing them to benefit from shared context when spawned in a pentest tree.

      let enrichedPrompt = params.prompt

      // Check if we should inject context:
      // 1. Always for pentest/* subagents
      // 2. For other agents only if engagement state already exists
      const engagementState = await getEngagementStateForInjection(rootSessionID)
      const shouldInjectContext = isPentest || engagementState !== null

      if (shouldInjectContext) {
        // Ensure session directory exists (normally created at parent session start, fallback here)
        if (!SessionDirectory.exists(rootSessionID)) {
          SessionDirectory.create(rootSessionID)
          log.info("created session directory (fallback)", { rootSessionID: rootSessionID.slice(-8) })
        }
        const sessionDir = SessionDirectory.get(rootSessionID)

        // Build enriched prompt with context
        const spawnInfo = canChildSpawn
          ? "You CAN spawn pentest/* sub-agents for focused sub-tasks."
          : "You are a leaf agent — you CANNOT spawn sub-agents. Work within your context."

        enrichedPrompt = `## Session Directory
${sessionDir}

## Delegation
${spawnInfo}

${engagementState ?? "No engagement state yet. Use \`update_engagement_state\` to record discoveries."}

---

## Your Task
${params.prompt}`

        log.info("context injection", {
          rootSessionID: rootSessionID.slice(-8),
          sessionDir,
          hasState: !!engagementState,
          agent: agent.name,
        })
      }

      const promptParts = await SessionPrompt.resolvePromptParts(enrichedPrompt)

      const result = await SessionPrompt.prompt({
        messageID,
        sessionID: session.id,
        model: {
          modelID: model.modelID,
          providerID: model.providerID,
        },
        agent: agent.name,
        tools: {
          ...(isPentest ? {} : { todowrite: false, todoread: false }),
          ...(canChildSpawn ? {} : { task: false }),
          ...Object.fromEntries((config.experimental?.primary_tools ?? []).map((t) => [t, false])),
        },
        parts: promptParts,
      })

      const text = result.parts.findLast((x) => x.type === "text")?.text ?? ""

      const output = [
        `task_id: ${session.id} (for resuming to continue this task if needed)`,
        "",
        "<task_result>",
        text,
        "</task_result>",
      ].join("\n")

      return {
        title: params.description,
        metadata: {
          sessionId: session.id,
          model,
        },
        output,
      }
    },
  }
})
