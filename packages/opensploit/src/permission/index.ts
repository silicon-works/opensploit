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
      // For bubbled permissions from sub-agents
      sourceSessionID: z.string().optional(), // Original sub-agent session
      rootSessionID: z.string().optional(), // Root session for bubbling
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

    // Check if this is from a child session and get the root session
    const isChildSession = hasParent(input.sessionID)
    const rootSessionID = getRootSession(input.sessionID)

    log.info("asking", {
      sessionID: input.sessionID,
      messageID: input.messageID,
      toolCallID: input.callID,
      pattern: input.pattern,
      isChildSession,
      rootSessionID,
    })

    // Check approvals for both the original session and root session
    const approvedForSession = approved[input.sessionID] || {}
    const approvedForRoot = approved[rootSessionID] || {}
    const keys = toKeys(input.pattern, input.type)
    if (covered(keys, approvedForSession) || covered(keys, approvedForRoot)) return

    const info: Info = {
      id: Identifier.ascending("permission"),
      type: input.type,
      pattern: input.pattern,
      sessionID: input.sessionID,
      messageID: input.messageID,
      callID: input.callID,
      title: input.title,
      metadata: input.metadata,
      time: {
        created: Date.now(),
      },
      // Add bubbling metadata
      sourceSessionID: isChildSession ? input.sessionID : undefined,
      rootSessionID: isChildSession ? rootSessionID : undefined,
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

    // Store under the original session (for tool result routing)
    pending[input.sessionID] = pending[input.sessionID] || {}

    // If this is a child session, also store under root session for unified approval queue
    if (isChildSession) {
      pending[rootSessionID] = pending[rootSessionID] || {}
    }

    return new Promise<void>((resolve, reject) => {
      const entry = {
        info,
        resolve,
        reject,
      }

      // Store under original session
      pending[input.sessionID][info.id] = entry

      // If child session, also store under root session with same ID
      // This allows the root TUI to show and respond to the permission
      if (isChildSession) {
        pending[rootSessionID][info.id] = entry
        // Publish event with root sessionID so it appears in root TUI
        const rootInfo = { ...info, sessionID: rootSessionID }
        Bus.publish(Event.Updated, rootInfo)
        log.info("bubbled to root", { permissionID: info.id, rootSessionID })
      }

      // Always publish for the original session
      Bus.publish(Event.Updated, info)
    })
  }

  export const Response = z.enum(["once", "always", "reject"])
  export type Response = z.infer<typeof Response>

  export function respond(input: { sessionID: Info["sessionID"]; permissionID: Info["id"]; response: Response }) {
    log.info("response", input)
    const { pending, approved } = state()
    const match = pending[input.sessionID]?.[input.permissionID]
    if (!match) {
      log.warn("permission not found", {
        sessionID: input.sessionID,
        permissionID: input.permissionID,
        availableSessions: Object.keys(pending),
        availablePermissions: pending[input.sessionID] ? Object.keys(pending[input.sessionID]) : []
      })
      return
    }

    // Get the original session and root session from the permission info
    const originalSessionID = match.info.sourceSessionID || match.info.sessionID
    const rootSessionID = match.info.rootSessionID

    // Clean up from the session we received the response from
    delete pending[input.sessionID][input.permissionID]

    // If this was a bubbled permission, also clean up from the other session
    if (rootSessionID && input.sessionID !== originalSessionID) {
      // Response came from root, clean up from original
      delete pending[originalSessionID]?.[input.permissionID]
    } else if (rootSessionID && input.sessionID === originalSessionID) {
      // Response came from original (less common), clean up from root
      delete pending[rootSessionID]?.[input.permissionID]
    }

    // Publish reply event for both sessions
    Bus.publish(Event.Replied, {
      sessionID: input.sessionID,
      permissionID: input.permissionID,
      response: input.response,
    })
    if (rootSessionID && input.sessionID !== originalSessionID) {
      Bus.publish(Event.Replied, {
        sessionID: originalSessionID,
        permissionID: input.permissionID,
        response: input.response,
      })
    }

    if (input.response === "reject") {
      match.reject(new RejectedError(originalSessionID, input.permissionID, match.info.callID, match.info.metadata))
      return
    }
    match.resolve()

    if (input.response === "always") {
      // Apply approval to both sessions if bubbled
      const sessionsToApprove = rootSessionID ? [originalSessionID, rootSessionID] : [input.sessionID]

      for (const sessionToApprove of sessionsToApprove) {
        approved[sessionToApprove] = approved[sessionToApprove] || {}
        const approveKeys = toKeys(match.info.pattern, match.info.type)
        for (const k of approveKeys) {
          approved[sessionToApprove][k] = true
        }
      }

      // Check pending items in both sessions
      for (const sessionToCheck of sessionsToApprove) {
        const items = pending[sessionToCheck]
        if (!items) continue
        for (const item of Object.values(items)) {
          const itemKeys = toKeys(item.info.pattern, item.info.type)
          if (covered(itemKeys, approved[sessionToCheck])) {
            respond({
              sessionID: item.info.sessionID,
              permissionID: item.info.id,
              response: input.response,
            })
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
