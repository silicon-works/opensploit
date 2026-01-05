/**
 * Test for Engagement State management
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import { EngagementState } from "./engagement-state"
import { SessionDirectory } from "./directory"
import fs from "fs"
import path from "path"

describe("EngagementState", () => {
  const testSessionID = "test-session-123"
  let testDir: string

  beforeEach(() => {
    // Create a test session directory
    testDir = SessionDirectory.create(testSessionID)
  })

  afterEach(() => {
    // Clean up test directory
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true })
    }
  })

  test("should return null on read when state file doesn't exist", () => {
    const state = EngagementState.read(testSessionID)
    expect(state).toBeNull()
  })

  test("should update target information", () => {
    const state = EngagementState.update(testSessionID, {
      target: {
        ip: "10.10.10.1",
        hostname: "target.htb",
        os: "Linux",
      },
    })

    expect(state.target?.ip).toBe("10.10.10.1")
    expect(state.target?.hostname).toBe("target.htb")
    expect(state.target?.os).toBe("Linux")
  })

  test("should merge ports without duplicates", () => {
    // Add first port
    EngagementState.update(testSessionID, {
      ports: [{ port: 22, protocol: "tcp", service: "ssh", state: "open" }],
    })

    // Add second port and duplicate first port
    const state = EngagementState.update(testSessionID, {
      ports: [
        { port: 22, protocol: "tcp", service: "ssh", state: "open" }, // duplicate
        { port: 80, protocol: "tcp", service: "http", state: "open" },
      ],
    })

    expect(state.ports?.length).toBe(2)
    expect(state.ports?.find((p) => p.port === 22)).toBeDefined()
    expect(state.ports?.find((p) => p.port === 80)).toBeDefined()
  })

  test("should merge credentials without duplicates", () => {
    // Add first credential
    EngagementState.update(testSessionID, {
      credentials: [{ username: "admin", password: "secret", source: "config", validated: false }],
    })

    // Add second credential and duplicate first
    const state = EngagementState.update(testSessionID, {
      credentials: [
        { username: "admin", password: "secret", source: "config", validated: false }, // duplicate
        { username: "root", hash: "abc123", source: "shadow", validated: false },
      ],
    })

    expect(state.credentials?.length).toBe(2)
    expect(state.credentials?.find((c) => c.username === "admin")).toBeDefined()
    expect(state.credentials?.find((c) => c.username === "root")).toBeDefined()
  })

  test("should merge vulnerabilities without duplicates", () => {
    EngagementState.update(testSessionID, {
      vulnerabilities: [{ name: "SQLi", severity: "high", service: "web", port: 80, exploitAvailable: true }],
    })

    const state = EngagementState.update(testSessionID, {
      vulnerabilities: [
        { name: "SQLi", severity: "high", service: "web", port: 80, exploitAvailable: true }, // duplicate
        { name: "XSS", severity: "medium", service: "web", port: 80, exploitAvailable: false },
      ],
    })

    expect(state.vulnerabilities?.length).toBe(2)
    expect(state.vulnerabilities?.find((v) => v.name === "SQLi")).toBeDefined()
    expect(state.vulnerabilities?.find((v) => v.name === "XSS")).toBeDefined()
  })

  test("should concatenate notes (not deduplicate)", () => {
    EngagementState.update(testSessionID, {
      notes: ["First note"],
    })

    const state = EngagementState.update(testSessionID, {
      notes: ["Second note"],
    })

    expect(state.notes?.length).toBe(2)
    expect(state.notes).toContain("First note")
    expect(state.notes).toContain("Second note")
  })

  test("should merge flags without duplicates", () => {
    EngagementState.update(testSessionID, {
      flags: ["HTB{flag1}"],
    })

    const state = EngagementState.update(testSessionID, {
      flags: ["HTB{flag1}", "HTB{flag2}"], // flag1 is duplicate
    })

    expect(state.flags?.length).toBe(2)
    expect(state.flags).toContain("HTB{flag1}")
    expect(state.flags).toContain("HTB{flag2}")
  })

  test("should update phase", () => {
    const state = EngagementState.update(testSessionID, {
      phase: "enumeration",
    })

    expect(state.phase).toBe("enumeration")

    const state2 = EngagementState.update(testSessionID, {
      phase: "exploitation",
    })

    expect(state2.phase).toBe("exploitation")
  })

  test("should update access level", () => {
    const state = EngagementState.update(testSessionID, {
      accessLevel: "user",
    })

    expect(state.accessLevel).toBe("user")

    const state2 = EngagementState.update(testSessionID, {
      accessLevel: "root",
    })

    expect(state2.accessLevel).toBe("root")
  })

  test("should persist state to disk as YAML", () => {
    EngagementState.update(testSessionID, {
      target: { ip: "10.10.10.1" },
      ports: [{ port: 22, protocol: "tcp", service: "ssh", state: "open" }],
      phase: "reconnaissance",
    })

    // Verify file exists
    const stateFile = path.join(testDir, "state.yaml")
    expect(fs.existsSync(stateFile)).toBe(true)

    // Verify content
    const fileContent = fs.readFileSync(stateFile, "utf-8")
    expect(fileContent).toContain("10.10.10.1")
    expect(fileContent).toContain("reconnaissance")
  })

  test("should reload state from disk", () => {
    EngagementState.update(testSessionID, {
      target: { ip: "10.10.10.1" },
      ports: [{ port: 22, protocol: "tcp", service: "ssh", state: "open" }],
      phase: "reconnaissance",
    })

    // Read the state back
    const state = EngagementState.read(testSessionID)
    expect(state).toBeDefined()
    expect(state?.target?.ip).toBe("10.10.10.1")
    expect(state?.ports?.[0]?.port).toBe(22)
    expect(state?.phase).toBe("reconnaissance")
  })

  test("formatForPrompt should include session directory when no state exists", () => {
    const freshSessionID = "fresh-session-no-state"
    const formatted = EngagementState.formatForPrompt(freshSessionID, "/tmp/no-state")
    expect(formatted).toContain("## Session Working Directory")
    expect(formatted).toContain("/tmp/no-state")
    expect(formatted).toContain("No prior state found")
  })

  test("formatForPrompt should include full state when it exists", () => {
    EngagementState.update(testSessionID, {
      target: { ip: "10.10.10.1", hostname: "target.htb" },
      ports: [{ port: 22, protocol: "tcp", service: "ssh", state: "open" }],
      phase: "enumeration",
    })

    const formatted = EngagementState.formatForPrompt(testSessionID, testDir)
    expect(formatted).toContain("## Session Working Directory")
    expect(formatted).toContain("## Current Engagement State")
    expect(formatted).toContain("10.10.10.1")
    expect(formatted).toContain("target.htb")
    expect(formatted).toContain("enumeration")
    expect(formatted).toContain("22")
  })

  test("should handle convenience methods", () => {
    EngagementState.addPort(testSessionID, {
      port: 443,
      protocol: "tcp",
      service: "https",
      state: "open",
    })

    EngagementState.addCredential(testSessionID, {
      username: "test",
      password: "pass",
      source: "config",
      validated: true,
    })

    EngagementState.addVulnerability(testSessionID, {
      name: "Test Vuln",
      severity: "high",
      service: "web",
      exploitAvailable: true,
    })

    EngagementState.setPhase(testSessionID, "exploitation")
    EngagementState.addFlag(testSessionID, "HTB{test}")

    const state = EngagementState.read(testSessionID)
    expect(state?.ports?.find((p) => p.port === 443)).toBeDefined()
    expect(state?.credentials?.find((c) => c.username === "test")).toBeDefined()
    expect(state?.vulnerabilities?.find((v) => v.name === "Test Vuln")).toBeDefined()
    expect(state?.phase).toBe("exploitation")
    expect(state?.flags).toContain("HTB{test}")
  })
})
