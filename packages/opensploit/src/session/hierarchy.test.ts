/**
 * Test for Session Hierarchy tracking
 */

import { describe, expect, test, beforeEach } from "bun:test"
import { registerRootSession, getRootSession, hasParent, unregister, getChildren } from "./hierarchy"

describe("SessionHierarchy", () => {
  const rootID = "root-session-001"
  const childID1 = "child-session-001"
  const childID2 = "child-session-002"
  const grandchildID = "grandchild-session-001"

  beforeEach(() => {
    // Clean up registrations between tests
    unregister(childID1)
    unregister(childID2)
    unregister(grandchildID)
    unregister(rootID)
  })

  test("getRootSession should return sessionID itself if not registered", () => {
    const result = getRootSession("unknown-session")
    expect(result).toBe("unknown-session")
  })

  test("registerRootSession should track parent-child relationship", () => {
    registerRootSession(childID1, rootID)
    expect(getRootSession(childID1)).toBe(rootID)
  })

  test("hasParent should return false for unregistered sessions", () => {
    expect(hasParent("unknown-session")).toBe(false)
  })

  test("hasParent should return true for registered child sessions", () => {
    registerRootSession(childID1, rootID)
    expect(hasParent(childID1)).toBe(true)
  })

  test("hasParent should return false when sessionID equals rootID", () => {
    // This shouldn't happen in practice, but test the edge case
    registerRootSession(rootID, rootID)
    expect(hasParent(rootID)).toBe(false)
  })

  test("unregister should remove the session from hierarchy", () => {
    registerRootSession(childID1, rootID)
    expect(hasParent(childID1)).toBe(true)

    unregister(childID1)
    expect(hasParent(childID1)).toBe(false)
    expect(getRootSession(childID1)).toBe(childID1)
  })

  test("getChildren should return all children of a root session", () => {
    registerRootSession(childID1, rootID)
    registerRootSession(childID2, rootID)

    const children = getChildren(rootID)
    expect(children).toContain(childID1)
    expect(children).toContain(childID2)
    expect(children.length).toBe(2)
  })

  test("getChildren should return empty array if no children", () => {
    const children = getChildren("no-children-root")
    expect(children).toEqual([])
  })

  test("multiple levels of nesting all point to same root", () => {
    // All sub-agents track back to the same root session
    registerRootSession(childID1, rootID)
    registerRootSession(childID2, rootID)
    registerRootSession(grandchildID, rootID) // Even grandchildren point directly to root

    expect(getRootSession(childID1)).toBe(rootID)
    expect(getRootSession(childID2)).toBe(rootID)
    expect(getRootSession(grandchildID)).toBe(rootID)
  })
})
