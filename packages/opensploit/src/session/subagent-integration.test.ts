/**
 * Integration tests for sub-agent architecture features
 *
 * Tests:
 * - Session directory lifecycle (create/cleanup)
 * - Permission bubbling to root session
 * - Background task management
 * - Engagement log aggregation
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test"
import { SessionDirectory } from "./directory"
import { EngagementState } from "./engagement-state"
import { BackgroundTask } from "./background-task"
import { Trajectory } from "./trajectory"
import { registerRootSession, getRootSession, getChildren, unregister } from "./hierarchy"
import { existsSync, mkdirSync, writeFileSync } from "fs"
import { join } from "path"
import { tmpdir } from "os"

describe("Session Directory Lifecycle", () => {
  const testSessionID = `test-session-${Date.now()}`

  afterEach(() => {
    SessionDirectory.cleanup(testSessionID)
  })

  test("creates session directory with standard structure", () => {
    const dir = SessionDirectory.create(testSessionID)

    expect(existsSync(dir)).toBe(true)
    expect(existsSync(join(dir, "findings"))).toBe(true)
    expect(existsSync(join(dir, "artifacts"))).toBe(true)
    expect(existsSync(join(dir, "artifacts", "screenshots"))).toBe(true)
    expect(existsSync(join(dir, "artifacts", "loot"))).toBe(true)
  })

  test("returns consistent path for same session", () => {
    const dir1 = SessionDirectory.get(testSessionID)
    const dir2 = SessionDirectory.get(testSessionID)

    expect(dir1).toBe(dir2)
  })

  test("exists returns correct status", () => {
    expect(SessionDirectory.exists(testSessionID)).toBe(false)

    SessionDirectory.create(testSessionID)

    expect(SessionDirectory.exists(testSessionID)).toBe(true)
  })

  test("cleanup removes directory completely", () => {
    SessionDirectory.create(testSessionID)
    expect(SessionDirectory.exists(testSessionID)).toBe(true)

    SessionDirectory.cleanup(testSessionID)
    expect(SessionDirectory.exists(testSessionID)).toBe(false)
  })

  test("can write and read findings", () => {
    SessionDirectory.create(testSessionID)

    const content = "# Reconnaissance Findings\n\n- Open ports: 22, 80"
    SessionDirectory.writeFinding(testSessionID, "recon", content)

    const read = SessionDirectory.readFinding(testSessionID, "recon")
    expect(read).toBe(content)
  })

  test("returns null for non-existent findings", () => {
    SessionDirectory.create(testSessionID)

    const read = SessionDirectory.readFinding(testSessionID, "nonexistent")
    expect(read).toBeNull()
  })
})

describe("Session Hierarchy and Permission Bubbling", () => {
  const testChildren: string[] = []

  afterEach(() => {
    // Clean up registered children
    for (const child of testChildren) {
      unregister(child)
    }
    testChildren.length = 0
  })

  test("registers and retrieves root session", () => {
    const child = `child-1-${Date.now()}`
    const root = `root-1-${Date.now()}`
    testChildren.push(child)

    registerRootSession(child, root)

    expect(getRootSession(child)).toBe(root)
  })

  test("returns own ID if not registered", () => {
    expect(getRootSession("orphan-session")).toBe("orphan-session")
  })

  test("tracks multiple children to same root", () => {
    const root = `root-multi-${Date.now()}`
    const child1 = `child-1-${Date.now()}`
    const child2 = `child-2-${Date.now()}`
    testChildren.push(child1, child2)

    registerRootSession(child1, root)
    registerRootSession(child2, root)

    expect(getRootSession(child1)).toBe(root)
    expect(getRootSession(child2)).toBe(root)

    const children = getChildren(root)
    expect(children).toContain(child1)
    expect(children).toContain(child2)
  })

  test("handles nested hierarchy", () => {
    const root = `root-nested-${Date.now()}`
    const child = `child-${Date.now()}`
    const grandchild = `grandchild-${Date.now()}`
    testChildren.push(child, grandchild)

    registerRootSession(child, root)
    registerRootSession(grandchild, root) // All map to root

    expect(getRootSession(grandchild)).toBe(root)
  })
})

// Background Task Management tests require full instance context
// These are covered by manual integration testing with real sessions
describe("Background Task Management", () => {
  test("BackgroundTask module exports required functions", () => {
    // Verify the module has the expected shape
    expect(typeof BackgroundTask.register).toBe("function")
    expect(typeof BackgroundTask.update).toBe("function")
    expect(typeof BackgroundTask.complete).toBe("function")
    expect(typeof BackgroundTask.fail).toBe("function")
    expect(typeof BackgroundTask.getTask).toBe("function")
    expect(typeof BackgroundTask.getTasks).toBe("function")
  })
})

describe("Engagement State Sharing", () => {
  // Test with unique session IDs per test to avoid state pollution
  test("EngagementState module exports required functions", () => {
    expect(typeof EngagementState.read).toBe("function")
    expect(typeof EngagementState.update).toBe("function")
    expect(typeof EngagementState.addPort).toBe("function")
    expect(typeof EngagementState.addCredential).toBe("function")
    expect(typeof EngagementState.addVulnerability).toBe("function")
    expect(typeof EngagementState.formatForPrompt).toBe("function")
  })

  test("formats state for prompt injection with session directory", () => {
    const testSessionID = `engage-format-${Date.now()}`
    SessionDirectory.create(testSessionID)

    // Add some test ports
    EngagementState.addPort(testSessionID, {
      port: 22,
      protocol: "tcp",
      service: "ssh",
      state: "open",
    })
    EngagementState.addPort(testSessionID, {
      port: 80,
      protocol: "tcp",
      service: "http",
      state: "open",
    })

    const formatted = EngagementState.formatForPrompt(testSessionID, SessionDirectory.get(testSessionID))

    // Should contain session directory info
    expect(formatted).toContain("Session Working Directory")
    expect(formatted).toContain(testSessionID)
    // Should contain port info
    expect(formatted).toContain("22")
    expect(formatted).toContain("80")

    // Cleanup
    SessionDirectory.cleanup(testSessionID)
  })
})

describe("TVAR Parser Integration", () => {
  test("parseTVAR extracts structured data", async () => {
    const { parseTVAR, extractPhase } = await import("./tvar-parser")

    const text = `
<thought>
I need to scan the target for open ports to understand the attack surface.
This is the reconnaissance phase.
</thought>

<verify>
Using nmap is appropriate for port scanning. This tool is phase-appropriate
and follows the tool selection hierarchy.
</verify>

<action>
nmap.tcp_scan -target 10.10.10.1 -ports 1-1000
</action>

<result>
Found ports 22 (SSH), 80 (HTTP), 443 (HTTPS) open.
</result>
`

    const blocks = parseTVAR(text)
    expect(blocks.length).toBe(1)

    const block = blocks[0]
    expect(block.thought).toContain("scan the target")
    expect(block.verify).toContain("nmap is appropriate")
    expect(block.action).toContain("tcp_scan")
    expect(block.result).toContain("22 (SSH)")

    const phase = extractPhase(block)
    expect(phase).toBe("reconnaissance")
  })

  test("hasTVAR detects TVAR presence", async () => {
    const { hasTVAR } = await import("./tvar-parser")

    const withTVAR = "<thought>test</thought><verify>test</verify>"
    const withoutTVAR = "Regular text without TVAR"
    const partial = "<thought>only thought</thought>"

    expect(hasTVAR(withTVAR)).toBe(true)
    expect(hasTVAR(withoutTVAR)).toBe(false)
    expect(hasTVAR(partial)).toBe(false) // Needs both thought and verify
  })
})

describe("Trajectory Anonymization", () => {
  test("anonymizes IP addresses", () => {
    const text = "Target IP is 192.168.1.100 and gateway is 192.168.1.1"

    const result = Trajectory.anonymizeText(text, { enabled: true })

    expect(result).not.toContain("192.168.1.100")
    expect(result).not.toContain("192.168.1.1")
    expect(result).toContain("10.10.10.")
  })

  test("redacts credentials", () => {
    const text = 'Found password: secretpass123 and key: myapikey'

    const result = Trajectory.anonymizeText(text, { enabled: true })

    expect(result).not.toContain("secretpass123")
    expect(result).not.toContain("myapikey")
    expect(result).toContain("[REDACTED]")
  })

  test("preserves common domains", () => {
    const text = "Cloned from github.com/test/repo to target1.example.com"

    const result = Trajectory.anonymizeText(text, { enabled: true })

    expect(result).toContain("github.com")
    expect(result).not.toContain("example.com")
  })
})
