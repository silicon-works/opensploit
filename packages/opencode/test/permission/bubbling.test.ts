import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import { Ultrasploit } from "../../src/permission/ultrasploit"
import { PermissionNext } from "../../src/permission/next"
import {
  registerRootSession,
  getRootSession,
  unregister,
  unregisterTree,
} from "../../src/session/hierarchy"
import { Instance } from "../../src/project/instance"
import { tmpdir } from "../fixture/fixture"

describe("permission.bubbling", () => {
  const rootSessionID = "session_root_test_001"
  const childSessionID = "session_child_test_001"
  const grandchildSessionID = "session_grandchild_test_001"

  // ---------------------------------------------------------------------------
  // Hierarchy Tests (no Instance context needed)
  // ---------------------------------------------------------------------------

  describe("hierarchy module", () => {
    beforeEach(() => {
      registerRootSession(childSessionID, rootSessionID)
      registerRootSession(grandchildSessionID, rootSessionID)
    })

    afterEach(() => {
      unregisterTree(rootSessionID)
    })

    test("getRootSession returns root for child session", () => {
      expect(getRootSession(childSessionID)).toBe(rootSessionID)
    })

    test("getRootSession returns root for grandchild session", () => {
      expect(getRootSession(grandchildSessionID)).toBe(rootSessionID)
    })

    test("getRootSession returns self for unregistered session", () => {
      const unknownSession = "session_unknown_001"
      expect(getRootSession(unknownSession)).toBe(unknownSession)
    })

    test("getRootSession returns self for root session", () => {
      expect(getRootSession(rootSessionID)).toBe(rootSessionID)
    })

    test("unregisterTree clears all children", () => {
      unregisterTree(rootSessionID)
      expect(getRootSession(childSessionID)).toBe(childSessionID)
      expect(getRootSession(grandchildSessionID)).toBe(grandchildSessionID)
    })
  })

  // ---------------------------------------------------------------------------
  // Ultrasploit Mode Tests (requires Instance context)
  // ---------------------------------------------------------------------------

  describe("ultrasploit mode", () => {
    test("isUltrasploit returns false by default", async () => {
      await using tmp = await tmpdir({ git: true })
      await Instance.provide({
        directory: tmp.path,
        fn: async () => {
          expect(Ultrasploit.isEnabled(rootSessionID)).toBe(false)
        },
      })
    })

    test("enableUltrasploit enables for root session", async () => {
      await using tmp = await tmpdir({ git: true })
      await Instance.provide({
        directory: tmp.path,
        fn: async () => {
          Ultrasploit.enable(rootSessionID)
          expect(Ultrasploit.isEnabled(rootSessionID)).toBe(true)
          Ultrasploit.disable(rootSessionID)
        },
      })
    })

    test("disableUltrasploit disables for root session", async () => {
      await using tmp = await tmpdir({ git: true })
      await Instance.provide({
        directory: tmp.path,
        fn: async () => {
          Ultrasploit.enable(rootSessionID)
          expect(Ultrasploit.isEnabled(rootSessionID)).toBe(true)

          Ultrasploit.disable(rootSessionID)
          expect(Ultrasploit.isEnabled(rootSessionID)).toBe(false)
        },
      })
    })

    test("ultrasploit enabled on child applies to root", async () => {
      await using tmp = await tmpdir({ git: true })
      await Instance.provide({
        directory: tmp.path,
        fn: async () => {
          // Set up hierarchy
          registerRootSession(childSessionID, rootSessionID)

          // Enable ultrasploit via child session
          Ultrasploit.enable(childSessionID)

          // Should be enabled for root (since child maps to root)
          expect(Ultrasploit.isEnabled(rootSessionID)).toBe(true)
          // Should also return true when checking via child
          expect(Ultrasploit.isEnabled(childSessionID)).toBe(true)

          // Cleanup
          Ultrasploit.disable(rootSessionID)
          unregister(childSessionID)
        },
      })
    })

    test("ultrasploit enabled on grandchild applies to entire tree", async () => {
      await using tmp = await tmpdir({ git: true })
      await Instance.provide({
        directory: tmp.path,
        fn: async () => {
          // Set up hierarchy
          registerRootSession(childSessionID, rootSessionID)
          registerRootSession(grandchildSessionID, rootSessionID)

          // Enable ultrasploit via grandchild session
          Ultrasploit.enable(grandchildSessionID)

          // Should be enabled for all sessions in tree
          expect(Ultrasploit.isEnabled(rootSessionID)).toBe(true)
          expect(Ultrasploit.isEnabled(childSessionID)).toBe(true)
          expect(Ultrasploit.isEnabled(grandchildSessionID)).toBe(true)

          // Cleanup
          Ultrasploit.disable(rootSessionID)
          unregisterTree(rootSessionID)
        },
      })
    })

    test("ultrasploit disabled on child disables for entire tree", async () => {
      await using tmp = await tmpdir({ git: true })
      await Instance.provide({
        directory: tmp.path,
        fn: async () => {
          // Set up hierarchy
          registerRootSession(childSessionID, rootSessionID)

          // Enable via root
          Ultrasploit.enable(rootSessionID)
          expect(Ultrasploit.isEnabled(rootSessionID)).toBe(true)

          // Disable via child (should affect root)
          Ultrasploit.disable(childSessionID)
          expect(Ultrasploit.isEnabled(rootSessionID)).toBe(false)
          expect(Ultrasploit.isEnabled(childSessionID)).toBe(false)

          // Cleanup
          unregister(childSessionID)
        },
      })
    })

    test("ultrasploit is isolated between different session trees", async () => {
      await using tmp = await tmpdir({ git: true })
      await Instance.provide({
        directory: tmp.path,
        fn: async () => {
          const otherRootID = "session_other_root_001"

          // Enable ultrasploit for our test tree
          Ultrasploit.enable(rootSessionID)

          // Other root should NOT have ultrasploit enabled
          expect(Ultrasploit.isEnabled(otherRootID)).toBe(false)
          expect(Ultrasploit.isEnabled(rootSessionID)).toBe(true)

          // Cleanup
          Ultrasploit.disable(rootSessionID)
        },
      })
    })
  })

  // ---------------------------------------------------------------------------
  // Permission Module Integration Tests
  // ---------------------------------------------------------------------------

  describe("permission module integration", () => {
    test("pending permissions list is accessible", async () => {
      await using tmp = await tmpdir({ git: true })
      await Instance.provide({
        directory: tmp.path,
        fn: async () => {
          const pending = await PermissionNext.list()
          expect(pending).toBeDefined()
          expect(Array.isArray(pending)).toBe(true)
        },
      })
    })

    test("permission list returns array", async () => {
      await using tmp = await tmpdir({ git: true })
      await Instance.provide({
        directory: tmp.path,
        fn: async () => {
          const list = await PermissionNext.list()
          expect(Array.isArray(list)).toBe(true)
        },
      })
    })
  })

  // ---------------------------------------------------------------------------
  // Integration: Ultrasploit with Hierarchy Changes
  // ---------------------------------------------------------------------------

  describe("ultrasploit with hierarchy changes", () => {
    test("ultrasploit persists after child unregistered", async () => {
      await using tmp = await tmpdir({ git: true })
      await Instance.provide({
        directory: tmp.path,
        fn: async () => {
          // Set up hierarchy
          registerRootSession(childSessionID, rootSessionID)

          Ultrasploit.enable(rootSessionID)

          // Unregister child
          unregister(childSessionID)

          // Root should still have ultrasploit enabled
          expect(Ultrasploit.isEnabled(rootSessionID)).toBe(true)

          // Cleanup
          Ultrasploit.disable(rootSessionID)
        },
      })
    })

    test("ultrasploit state persists when tree unregistered (explicit disable needed)", async () => {
      await using tmp = await tmpdir({ git: true })
      await Instance.provide({
        directory: tmp.path,
        fn: async () => {
          // Set up hierarchy
          registerRootSession(childSessionID, rootSessionID)

          Ultrasploit.enable(rootSessionID)
          expect(Ultrasploit.isEnabled(rootSessionID)).toBe(true)

          // Unregister entire tree
          unregisterTree(rootSessionID)

          // Note: ultrasploit state is stored by root session ID, not in hierarchy
          // So it persists even after tree unregistration
          // This is intentional - cleanup should be explicit
          expect(Ultrasploit.isEnabled(rootSessionID)).toBe(true)

          // Explicit disable
          Ultrasploit.disable(rootSessionID)
          expect(Ultrasploit.isEnabled(rootSessionID)).toBe(false)
        },
      })
    })
  })
})
