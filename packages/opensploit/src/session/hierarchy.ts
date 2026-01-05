/**
 * Session Hierarchy Tracker
 *
 * Tracks parent-child relationships between sessions for permission bubbling.
 * This module is designed to be imported by both Session and Permission
 * without causing circular dependencies.
 */

import { Log } from "@/util/log"

const log = Log.create({ service: "session.hierarchy" })

/**
 * Maps child session IDs to their root session ID
 * This is populated when sessions are created and used for permission bubbling
 */
const rootSessionMap = new Map<string, string>()

/**
 * Register a session's root session
 */
export function registerRootSession(sessionID: string, rootSessionID: string): void {
  rootSessionMap.set(sessionID, rootSessionID)
  log.info("registered", { sessionID, rootSessionID })
}

/**
 * Get the root session for a given session ID
 * Returns the sessionID itself if it's a root session (no parent)
 */
export function getRootSession(sessionID: string): string {
  return rootSessionMap.get(sessionID) ?? sessionID
}

/**
 * Check if a session has a registered parent
 */
export function hasParent(sessionID: string): boolean {
  const root = rootSessionMap.get(sessionID)
  return root !== undefined && root !== sessionID
}

/**
 * Clear registration for a session (called on session delete)
 */
export function unregister(sessionID: string): void {
  rootSessionMap.delete(sessionID)
}

/**
 * Get all child sessions for a root session
 */
export function getChildren(rootSessionID: string): string[] {
  const children: string[] = []
  for (const [childID, rootID] of rootSessionMap.entries()) {
    if (rootID === rootSessionID && childID !== rootSessionID) {
      children.push(childID)
    }
  }
  return children
}
