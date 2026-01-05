import { BusEvent } from "@/bus/bus-event"
import { Bus } from "@/bus"
import z from "zod"
import { Log } from "../util/log"
import { Identifier } from "../id/id"
import { Plugin } from "../plugin"
import { Instance } from "../project/instance"
import { Wildcard } from "../util/wildcard"
import { getRootSession, hasParent } from "../session/hierarchy"

export namespace Permission {
  const log = Log.create({ service: "permission" })

  function toKeys(pattern: Info["pattern"], type: string): string[] {
    return pattern === undefined ? [type] : Array.isArray(pattern) ? pattern : [pattern]
  }

  function covered(keys: string[], approved: Record<string, boolean>): boolean {
    const pats = Object.keys(approved)
    return keys.every((k) => pats.some((p) => Wildcard.match(k, p)))
  }

  export const Info = z
    .object({
      id: z.string(),
      type: z.string(),
      pattern: z.union([z.string(), z.array(z.string())]).optional(),
      sessionID: z.string(),
      messageID: z.string(),
      callID: z.string().optional(),
      title: z.string(),
      metadata: z.record(z.string(), z.any()),
      time: z.object({
        created: z.number(),
      }),
      // For sub-agent permissions (display context only)
      sourceSessionID: z.string().optional(), // Original sub-agent session (if different from sessionID)
      agentName: z.string().optional(), // Name of the sub-agent
    })
    .meta({
      ref: "Permission",
    })
  export type Info = z.infer<typeof Info>

  export const Event = {
    Updated: BusEvent.define("permission.updated", Info),
    Replied: BusEvent.define(
      "permission.replied",
      z.object({
        sessionID: z.string(),
        permissionID: z.string(),
        response: z.string(),
      }),
    ),
  }

  const state = Instance.state(
    () => {
      const pending: {
        [sessionID: string]: {
          [permissionID: string]: {
            info: Info
            resolve: () => void
            reject: (e: any) => void
          }
        }
      } = {}

      const approved: {
        [sessionID: string]: {
          [permissionID: string]: boolean
        }
      } = {}

      return {
        pending,
        approved,
      }
    },
    async (state) => {
      for (const pending of Object.values(state.pending)) {
        for (const item of Object.values(pending)) {
          item.reject(new RejectedError(item.info.sessionID, item.info.id, item.info.callID, item.info.metadata))
        }
      }
    },
  )

  export function pending() {
    return state().pending
  }

  export async function ask(input: {
    type: Info["type"]
    title: Info["title"]
    pattern?: Info["pattern"]
    callID?: Info["callID"]
    sessionID: Info["sessionID"]
    messageID: Info["messageID"]
    metadata: Info["metadata"]
    agentName?: string // Optional agent name for sub-agents
  }) {
    const { pending, approved } = state()

    // Sub-agents use root session for permissions - simple delegation
    const effectiveSessionID = getRootSession(input.sessionID)
    const isSubAgent = effectiveSessionID !== input.sessionID

    log.info("asking", {
      sessionID: input.sessionID,
      effectiveSessionID,
      isSubAgent,
      pattern: input.pattern,
    })

    // Check approvals against the effective session (root for sub-agents)
    const approvedForSession = approved[effectiveSessionID] || {}
    const keys = toKeys(input.pattern, input.type)
    if (covered(keys, approvedForSession)) return

    const info: Info = {
      id: Identifier.ascending("permission"),
      type: input.type,
      pattern: input.pattern,
      sessionID: effectiveSessionID, // Use root session for sub-agents
      messageID: input.messageID,
      callID: input.callID,
      title: input.title,
      metadata: input.metadata,
      time: {
        created: Date.now(),
      },
      // Track original session for context (display only)
      sourceSessionID: isSubAgent ? input.sessionID : undefined,
      agentName: input.agentName,
    }

    switch (
      await Plugin.trigger("permission.ask", info, {
        status: "ask",
      }).then((x) => x.status)
    ) {
      case "deny":
        throw new RejectedError(info.sessionID, info.id, info.callID, info.metadata)
      case "allow":
        return
    }

    // Store under effective session only - no dual storage
    pending[effectiveSessionID] = pending[effectiveSessionID] || {}

    return new Promise<void>((resolve, reject) => {
      pending[effectiveSessionID][info.id] = { info, resolve, reject }
      Bus.publish(Event.Updated, info)
    })
  }

  export const Response = z.enum(["once", "always", "reject"])
  export type Response = z.infer<typeof Response>

  export function respond(input: { sessionID: Info["sessionID"]; permissionID: Info["id"]; response: Response }) {
    log.info("respond", input)
    const { pending, approved } = state()
    const match = pending[input.sessionID]?.[input.permissionID]
    if (!match) {
      log.warn("permission not found", { ...input, available: Object.keys(pending) })
      return
    }

    // Clean up
    delete pending[input.sessionID][input.permissionID]

    // Publish reply
    Bus.publish(Event.Replied, {
      sessionID: input.sessionID,
      permissionID: input.permissionID,
      response: input.response,
    })

    if (input.response === "reject") {
      match.reject(new RejectedError(input.sessionID, input.permissionID, match.info.callID, match.info.metadata))
      return
    }
    match.resolve()

    // "Always" approves this pattern for future requests in this session
    if (input.response === "always") {
      approved[input.sessionID] = approved[input.sessionID] || {}
      for (const k of toKeys(match.info.pattern, match.info.type)) {
        approved[input.sessionID][k] = true
      }

      // Auto-approve any pending items that now match
      const items = pending[input.sessionID]
      if (items) {
        for (const item of Object.values(items)) {
          if (covered(toKeys(item.info.pattern, item.info.type), approved[input.sessionID])) {
            respond({ sessionID: input.sessionID, permissionID: item.info.id, response: "always" })
          }
        }
      }
    }
  }

  export class RejectedError extends Error {
    constructor(
      public readonly sessionID: string,
      public readonly permissionID: string,
      public readonly toolCallID?: string,
      public readonly metadata?: Record<string, any>,
      public readonly reason?: string,
    ) {
      super(
        reason !== undefined
          ? reason
          : `The user rejected permission to use this specific tool call. You may try again with different parameters.`,
      )
    }
  }
}
