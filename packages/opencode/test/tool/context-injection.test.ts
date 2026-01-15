import { describe, expect, test, afterEach } from "bun:test"
import yaml from "js-yaml"
import * as SessionDirectory from "../../src/session/directory"
import {
  loadEngagementState,
  getEngagementStateForInjection,
} from "../../src/tool/engagement-state"
import {
  registerRootSession,
  getRootSession,
  unregisterTree,
} from "../../src/session/hierarchy"
import { writeFileSync } from "fs"

describe("tool.context-injection", () => {
  const rootSessionID = "test-context-injection-root-001"
  const childSessionID = "test-context-injection-child-001"

  // Clean up after each test
  afterEach(() => {
    SessionDirectory.cleanup(rootSessionID)
    unregisterTree(rootSessionID)
  })

  // ---------------------------------------------------------------------------
  // Helper function tests
  // ---------------------------------------------------------------------------

  describe("isPentestSubagent logic", () => {
    // This tests the logic used in task.ts for isPentestSubagent
    function isPentestSubagent(agentName: string): boolean {
      return agentName.startsWith("pentest/")
    }

    test("returns true for pentest/recon", () => {
      expect(isPentestSubagent("pentest/recon")).toBe(true)
    })

    test("returns true for pentest/enum", () => {
      expect(isPentestSubagent("pentest/enum")).toBe(true)
    })

    test("returns true for pentest/exploit", () => {
      expect(isPentestSubagent("pentest/exploit")).toBe(true)
    })

    test("returns false for general", () => {
      expect(isPentestSubagent("general")).toBe(false)
    })

    test("returns false for explore", () => {
      expect(isPentestSubagent("explore")).toBe(false)
    })

    test("returns false for pentest (without slash)", () => {
      expect(isPentestSubagent("pentest")).toBe(false)
    })
  })

  // ---------------------------------------------------------------------------
  // Context injection scope tests
  // ---------------------------------------------------------------------------

  describe("context injection scope", () => {
    test("engagement state is null when no state file exists", async () => {
      const state = await getEngagementStateForInjection(rootSessionID)
      expect(state).toBeNull()
    })

    test("engagement state is formatted when state file exists", async () => {
      // Create session directory and write state
      SessionDirectory.create(rootSessionID)
      const statePath = SessionDirectory.statePath(rootSessionID)

      const stateContent = yaml.dump({
        target: { ip: "10.10.10.1", hostname: "target.htb" },
        ports: [{ port: 22, protocol: "tcp", service: "ssh" }],
        accessLevel: "none",
      })
      writeFileSync(statePath, stateContent)

      const injection = await getEngagementStateForInjection(rootSessionID)
      expect(injection).not.toBeNull()
      expect(injection).toContain("## Current Engagement State")
      expect(injection).toContain("10.10.10.1")
      expect(injection).toContain("target.htb")
    })

    test("sub-agents share root session directory", async () => {
      // Register hierarchy
      registerRootSession(childSessionID, rootSessionID)

      // Create session directory for root
      SessionDirectory.create(rootSessionID)

      // Child should get the same directory as root
      const rootDir = SessionDirectory.get(rootSessionID)
      const childRootID = getRootSession(childSessionID)
      const childDir = SessionDirectory.get(childRootID)

      expect(childDir).toBe(rootDir)
    })

    test("state written by child is accessible by root", async () => {
      // Register hierarchy
      registerRootSession(childSessionID, rootSessionID)

      // Create session directory for root
      SessionDirectory.create(rootSessionID)

      // Write state using root's path (simulating what a child would do)
      const childRootID = getRootSession(childSessionID)
      const statePath = SessionDirectory.statePath(childRootID)

      const stateContent = yaml.dump({
        target: { ip: "192.168.1.1" },
      })
      writeFileSync(statePath, stateContent)

      // Root should be able to read the state
      const rootState = await loadEngagementState(rootSessionID)
      expect(rootState.target?.ip).toBe("192.168.1.1")
    })
  })

  // ---------------------------------------------------------------------------
  // Context injection decision logic tests
  // ---------------------------------------------------------------------------

  describe("context injection decision", () => {
    // Simulates the logic in task.ts for deciding whether to inject context
    function shouldInjectContext(isPentest: boolean, engagementState: string | null): boolean {
      return isPentest || engagementState !== null
    }

    test("injects context for pentest/* agent even without state", () => {
      expect(shouldInjectContext(true, null)).toBe(true)
    })

    test("injects context for pentest/* agent with state", () => {
      expect(shouldInjectContext(true, "some state")).toBe(true)
    })

    test("does NOT inject context for non-pentest agent without state", () => {
      expect(shouldInjectContext(false, null)).toBe(false)
    })

    test("injects context for non-pentest agent when state exists", () => {
      expect(shouldInjectContext(false, "some state")).toBe(true)
    })
  })

  // ---------------------------------------------------------------------------
  // Session directory structure tests
  // ---------------------------------------------------------------------------

  describe("session directory structure for context", () => {
    test("session directory path follows expected format", () => {
      const dir = SessionDirectory.get(rootSessionID)
      expect(dir).toContain("opensploit-session-")
      expect(dir).toContain(rootSessionID)
    })

    test("created directory has expected subdirectories", async () => {
      SessionDirectory.create(rootSessionID)
      const dir = SessionDirectory.get(rootSessionID)

      expect(SessionDirectory.exists(rootSessionID)).toBe(true)

      // Check standard structure exists
      const { existsSync } = await import("fs")
      const { join } = await import("path")

      expect(existsSync(join(dir, "findings"))).toBe(true)
      expect(existsSync(join(dir, "artifacts"))).toBe(true)
      expect(existsSync(join(dir, "artifacts", "screenshots"))).toBe(true)
      expect(existsSync(join(dir, "artifacts", "loot"))).toBe(true)
    })

    test("state.yaml path is in session directory", () => {
      const statePath = SessionDirectory.statePath(rootSessionID)
      const dir = SessionDirectory.get(rootSessionID)

      expect(statePath).toBe(`${dir}/state.yaml`)
    })
  })

  // ---------------------------------------------------------------------------
  // Ultrasploit keyword stripping tests
  // ---------------------------------------------------------------------------

  describe("ultrasploit keyword stripping", () => {
    // Simulates the logic in prompt.ts for stripping "ultrasploit" from user messages
    function stripUltrasploit(text: string): string {
      return text.replace(/\bultrasploit\b/gi, "").replace(/\s{2,}/g, " ").trim()
    }

    test("strips ultrasploit from beginning of message", () => {
      expect(stripUltrasploit("ultrasploit scan the target")).toBe("scan the target")
    })

    test("strips ultrasploit from end of message", () => {
      expect(stripUltrasploit("scan the target ultrasploit")).toBe("scan the target")
    })

    test("strips ultrasploit from middle of message", () => {
      expect(stripUltrasploit("please ultrasploit scan the target")).toBe("please scan the target")
    })

    test("strips multiple occurrences", () => {
      expect(stripUltrasploit("ultrasploit ultrasploit scan")).toBe("scan")
    })

    test("case insensitive stripping", () => {
      expect(stripUltrasploit("ULTRASPLOIT scan")).toBe("scan")
      expect(stripUltrasploit("UltraSploit scan")).toBe("scan")
    })

    test("does not strip partial matches", () => {
      expect(stripUltrasploit("myultrasploittool")).toBe("myultrasploittool")
    })

    test("handles message with only ultrasploit", () => {
      expect(stripUltrasploit("ultrasploit")).toBe("")
    })

    test("preserves message without ultrasploit", () => {
      expect(stripUltrasploit("scan the target")).toBe("scan the target")
    })

    test("collapses multiple spaces after stripping", () => {
      expect(stripUltrasploit("scan  ultrasploit  target")).toBe("scan target")
    })
  })
})
