import { describe, expect, test } from "bun:test"
import { Trajectory } from "../../src/session/trajectory"

describe("Trajectory.anonymizeText", () => {
  test("should not modify text when disabled", () => {
    const text = "Connect to 192.168.1.100 with password secret123"
    const result = Trajectory.anonymizeText(text, { enabled: false })
    expect(result).toBe(text)
  })

  test("should replace IP addresses", () => {
    const text = "Scanning 192.168.1.100 and 10.0.0.50"
    const result = Trajectory.anonymizeText(text, { enabled: true })
    expect(result).not.toContain("192.168.1.100")
    expect(result).not.toContain("10.0.0.50")
    expect(result).toContain("10.10.10.")
  })

  test("should use consistent IP mapping", () => {
    const ipMap = new Map<string, string>()
    const text1 = "Host 192.168.1.100 is up"
    const text2 = "Scanning 192.168.1.100 again"
    const options = { enabled: true, ipMapping: ipMap }

    const result1 = Trajectory.anonymizeText(text1, options)
    const result2 = Trajectory.anonymizeText(text2, options)

    // Extract the anonymized IP from first result and verify it's used in second
    const match = result1.match(/10\.10\.10\.\d+/)
    expect(match).not.toBeNull()
    expect(result2).toContain(match![0])
  })

  test("should replace hostnames but preserve common domains", () => {
    const text = "Connecting to target.internal.corp and github.com"
    const result = Trajectory.anonymizeText(text, { enabled: true })
    expect(result).not.toContain("target.internal.corp")
    expect(result).toContain("github.com") // preserved
    expect(result).toMatch(/target\d+\.htb/) // replaced with anonymized
  })

  test("should redact credentials", () => {
    const text = "password: super_secret_123 and key=abc123"
    const result = Trajectory.anonymizeText(text, { enabled: true })
    expect(result).not.toContain("super_secret_123")
    expect(result).not.toContain("abc123")
    expect(result).toContain("[REDACTED]")
  })
})

describe("Trajectory.detectAntiPatterns", () => {
  test("should detect curl misuse for SQL injection", () => {
    const trajectory: Trajectory.Data = {
      sessionID: "test",
      model: "test-model",
      startTime: new Date().toISOString(),
      trajectory: [
        {
          step: 1,
          timestamp: new Date().toISOString(),
          thought: "Testing SQL injection with curl",
          verify: "Using curl to send SQL payloads",
        },
      ],
    }
    const antiPatterns = Trajectory.detectAntiPatterns(trajectory)
    expect(antiPatterns.length).toBeGreaterThan(0)
    expect(antiPatterns[0].category).toBe("wrong_tool")
    expect(antiPatterns[0].correctAction).toBe("sqlmap.test_form")
  })

  test("should detect curl misuse for brute force", () => {
    const trajectory: Trajectory.Data = {
      sessionID: "test",
      model: "test-model",
      startTime: new Date().toISOString(),
      trajectory: [
        {
          step: 1,
          timestamp: new Date().toISOString(),
          thought: "Need to brute force the login",
          verify: "Using curl in a loop for brute force testing",
        },
      ],
    }
    const antiPatterns = Trajectory.detectAntiPatterns(trajectory)
    expect(antiPatterns.length).toBeGreaterThan(0)
    expect(antiPatterns[0].category).toBe("wrong_tool")
    expect(antiPatterns[0].correctAction).toBe("hydra.brute_force")
  })

  test("should detect custom exploit code", () => {
    const trajectory: Trajectory.Data = {
      sessionID: "test",
      model: "test-model",
      startTime: new Date().toISOString(),
      trajectory: [
        {
          step: 1,
          timestamp: new Date().toISOString(),
          thought: "Writing a Python exploit for the vulnerability",
          verify: "Custom payload script",
        },
      ],
    }
    const antiPatterns = Trajectory.detectAntiPatterns(trajectory)
    expect(antiPatterns.length).toBeGreaterThan(0)
    expect(antiPatterns[0].category).toBe("custom_code")
  })

  test("should detect phase violations", () => {
    const trajectory: Trajectory.Data = {
      sessionID: "test",
      model: "test-model",
      startTime: new Date().toISOString(),
      trajectory: [
        {
          step: 1,
          timestamp: new Date().toISOString(),
          phase: "reconnaissance",
          thought: "Running sqlmap during reconnaissance",
          verify: "Testing sqlmap on the target",
        },
      ],
    }
    const antiPatterns = Trajectory.detectAntiPatterns(trajectory)
    expect(antiPatterns.length).toBeGreaterThan(0)
    expect(antiPatterns[0].category).toBe("phase_violation")
  })

  test("should not flag valid tool usage", () => {
    const trajectory: Trajectory.Data = {
      sessionID: "test",
      model: "test-model",
      startTime: new Date().toISOString(),
      trajectory: [
        {
          step: 1,
          timestamp: new Date().toISOString(),
          phase: "reconnaissance",
          thought: "Scanning for open ports",
          verify: "Using nmap for port discovery",
        },
      ],
    }
    const antiPatterns = Trajectory.detectAntiPatterns(trajectory)
    expect(antiPatterns.length).toBe(0)
  })
})

describe("Trajectory.toJSONL", () => {
  test("should format trajectory as JSONL", () => {
    const trajectory: Trajectory.Data = {
      sessionID: "test-session",
      model: "claude-3",
      startTime: "2024-01-01T00:00:00Z",
      trajectory: [
        {
          step: 1,
          timestamp: "2024-01-01T00:00:01Z",
          phase: "reconnaissance",
          thought: "First step thought",
          verify: "First step verify",
          action: "First action",
        },
        {
          step: 2,
          timestamp: "2024-01-01T00:00:02Z",
          thought: "Second step",
          verify: "Second verify",
        },
      ],
    }

    const jsonl = Trajectory.toJSONL(trajectory)
    const lines = jsonl.split("\n")
    expect(lines.length).toBe(2)

    const line1 = JSON.parse(lines[0])
    expect(line1.session_id).toBe("test-session")
    expect(line1.step).toBe(1)
    expect(line1.phase).toBe("reconnaissance")
    expect(line1.output.thought).toBe("First step thought")

    const line2 = JSON.parse(lines[1])
    expect(line2.step).toBe(2)
    expect(line2.phase).toBeUndefined()
  })
})

describe("Trajectory.toShareGPT", () => {
  test("should format trajectory as ShareGPT", () => {
    const trajectory: Trajectory.Data = {
      sessionID: "test-session",
      model: "claude-3",
      startTime: "2024-01-01T00:00:00Z",
      trajectory: [
        {
          step: 1,
          timestamp: "2024-01-01T00:00:01Z",
          phase: "reconnaissance",
          thought: "Scanning target",
          verify: "Using appropriate tools",
        },
      ],
    }

    const shareGPT = Trajectory.toShareGPT(trajectory)
    const parsed = JSON.parse(shareGPT)

    expect(Array.isArray(parsed)).toBe(true)
    expect(parsed.length).toBe(1)
    expect(parsed[0].id).toBe("test-session")
    expect(parsed[0].conversations.length).toBe(3) // system, human, gpt

    const systemMsg = parsed[0].conversations[0]
    expect(systemMsg.from).toBe("system")
    expect(systemMsg.value).toContain("reconnaissance")

    const gptMsg = parsed[0].conversations[2]
    expect(gptMsg.from).toBe("gpt")
    expect(gptMsg.value).toContain("<thought>")
    expect(gptMsg.value).toContain("<verify>")
  })
})

describe("Trajectory.formatAsText", () => {
  test("should format trajectory as readable text", () => {
    const trajectory: Trajectory.Data = {
      sessionID: "test-session",
      model: "claude-3",
      startTime: "2024-01-01T00:00:00Z",
      endTime: "2024-01-01T01:00:00Z",
      trajectory: [
        {
          step: 1,
          timestamp: "2024-01-01T00:00:01Z",
          phase: "reconnaissance",
          thought: "Scanning target",
          verify: "Tool selection correct",
          action: "Running nmap",
          result: "Found 3 ports",
          toolCall: {
            tool: "nmap",
            success: true,
          },
        },
      ],
      outcome: {
        success: true,
        accessAchieved: "root",
        flagsCaptured: ["flag1", "flag2"],
      },
    }

    const text = Trajectory.formatAsText(trajectory)

    expect(text).toContain("# Trajectory: test-session")
    expect(text).toContain("Model: claude-3")
    expect(text).toContain("### Step 1 (reconnaissance)")
    expect(text).toContain("**Thought**: Scanning target")
    expect(text).toContain("**Tool**: nmap (success)")
    expect(text).toContain("## Outcome")
    expect(text).toContain("Success: true")
    expect(text).toContain("Access: root")
    expect(text).toContain("flag1, flag2")
  })
})

describe("Trajectory.anonymize", () => {
  test("should anonymize entire trajectory", () => {
    const trajectory: Trajectory.Data = {
      sessionID: "test-session",
      model: "claude-3",
      target: "192.168.1.100",
      startTime: "2024-01-01T00:00:00Z",
      trajectory: [
        {
          step: 1,
          timestamp: "2024-01-01T00:00:01Z",
          thought: "Scanning 192.168.1.100 for vulnerabilities",
          verify: "Target IP is correct",
          action: "nmap 192.168.1.100",
          result: "Login credentials password=admin123 found in config",
        },
      ],
    }

    const anonymized = Trajectory.anonymize(trajectory)

    // Target should be anonymized
    expect(anonymized.target).not.toContain("192.168.1.100")
    expect(anonymized.target).toContain("10.10.10.")

    // Trajectory steps should be anonymized
    expect(anonymized.trajectory[0].thought).not.toContain("192.168.1.100")
    expect(anonymized.trajectory[0].result).toContain("[REDACTED]")
    expect(anonymized.trajectory[0].result).not.toContain("admin123")
  })
})

// =============================================================================
// Feature 06: Engagement Log Aggregation Tests
// =============================================================================

describe("Trajectory.formatEngagementLog", () => {
  test("should format engagement log with header and summary", () => {
    const log: Trajectory.EngagementLog = {
      rootSessionID: "session-abc123",
      startTime: "2026-01-16T10:00:00.000Z",
      endTime: "2026-01-16T10:30:00.000Z",
      entries: [],
      summary: {
        totalAgents: 3,
        agentNames: ["master", "recon", "enum"],
        toolCalls: 10,
        successfulTools: 8,
        failedTools: 2,
        phases: ["reconnaissance", "enumeration"],
      },
    }

    const formatted = Trajectory.formatEngagementLog(log)

    expect(formatted).toContain("# Engagement Log")
    expect(formatted).toContain("Root Session: session-abc123")
    expect(formatted).toContain("Start: 2026-01-16T10:00:00.000Z")
    expect(formatted).toContain("End: 2026-01-16T10:30:00.000Z")
    expect(formatted).toContain("## Summary")
    expect(formatted).toContain("Agents: master, recon, enum")
    expect(formatted).toContain("Tool Calls: 10 (8 success, 2 failed)")
    expect(formatted).toContain("Phases: reconnaissance → enumeration")
  })

  test("should format timeline entries with TVAR", () => {
    const log: Trajectory.EngagementLog = {
      rootSessionID: "session-abc123",
      startTime: "2026-01-16T10:00:00.000Z",
      entries: [
        {
          timestamp: "2026-01-16T10:00:05.000Z",
          agentName: "master",
          sessionID: "session-abc123",
          phase: "reconnaissance",
          type: "tvar",
          summary: "Starting pentest on target",
          durationMs: 100,
        },
        {
          timestamp: "2026-01-16T10:00:10.000Z",
          agentName: "recon",
          sessionID: "session-child1",
          phase: "reconnaissance",
          type: "tvar",
          summary: "Beginning port scan",
        },
      ],
      summary: {
        totalAgents: 2,
        agentNames: ["master", "recon"],
        toolCalls: 0,
        successfulTools: 0,
        failedTools: 0,
        phases: ["reconnaissance"],
      },
    }

    const formatted = Trajectory.formatEngagementLog(log)

    expect(formatted).toContain("## Timeline")
    expect(formatted).toContain("10:00:05")
    expect(formatted).toContain("[master]")
    expect(formatted).toContain("💭") // TVAR icon
    expect(formatted).toContain("(recon)") // phase abbreviation
    expect(formatted).toContain("Starting pentest on target")
    expect(formatted).toContain("(100ms)") // duration
    expect(formatted).toContain("[recon]")
    expect(formatted).toContain("Beginning port scan")
  })

  test("should format timeline entries with tools", () => {
    const log: Trajectory.EngagementLog = {
      rootSessionID: "session-abc123",
      startTime: "2026-01-16T10:00:00.000Z",
      entries: [
        {
          timestamp: "2026-01-16T10:00:05.000Z",
          agentName: "recon",
          sessionID: "session-child1",
          type: "tool",
          summary: "nmap: port_scan completed",
          details: {
            tool: "nmap",
            toolStatus: "completed",
          },
          durationMs: 15000,
        },
      ],
      summary: {
        totalAgents: 1,
        agentNames: ["recon"],
        toolCalls: 1,
        successfulTools: 1,
        failedTools: 0,
        phases: [],
      },
    }

    const formatted = Trajectory.formatEngagementLog(log)

    expect(formatted).toContain("🔧") // tool icon
    expect(formatted).toContain("nmap: port_scan completed")
    expect(formatted).toContain("(15000ms)")
  })

  test("should not repeat agent name for consecutive entries", () => {
    const log: Trajectory.EngagementLog = {
      rootSessionID: "session-abc123",
      startTime: "2026-01-16T10:00:00.000Z",
      entries: [
        {
          timestamp: "2026-01-16T10:00:05.000Z",
          agentName: "recon",
          sessionID: "session-child1",
          type: "tvar",
          summary: "First entry",
        },
        {
          timestamp: "2026-01-16T10:00:06.000Z",
          agentName: "recon",
          sessionID: "session-child1",
          type: "tvar",
          summary: "Second entry",
        },
        {
          timestamp: "2026-01-16T10:00:07.000Z",
          agentName: "master",
          sessionID: "session-abc123",
          type: "tvar",
          summary: "Third entry from different agent",
        },
      ],
      summary: {
        totalAgents: 2,
        agentNames: ["recon", "master"],
        toolCalls: 0,
        successfulTools: 0,
        failedTools: 0,
        phases: [],
      },
    }

    const formatted = Trajectory.formatEngagementLog(log)
    const lines = formatted.split("\n")

    // Find the timeline lines (after "## Timeline" and empty line)
    const timelineStart = lines.findIndex((l) => l === "## Timeline") + 2
    const timelineLines = lines.slice(timelineStart).filter((l) => l.trim())

    // First recon entry should have [recon]
    expect(timelineLines[0]).toContain("[recon]")

    // Second recon entry should NOT have [recon] (same agent)
    expect(timelineLines[1]).not.toContain("[recon]")

    // Third entry should have [master] (different agent)
    expect(timelineLines[2]).toContain("[master]")
  })

  test("should handle empty engagement log", () => {
    const log: Trajectory.EngagementLog = {
      rootSessionID: "session-empty",
      startTime: "2026-01-16T10:00:00.000Z",
      entries: [],
      summary: {
        totalAgents: 1,
        agentNames: ["master"],
        toolCalls: 0,
        successfulTools: 0,
        failedTools: 0,
        phases: [],
      },
    }

    const formatted = Trajectory.formatEngagementLog(log)

    expect(formatted).toContain("# Engagement Log")
    expect(formatted).toContain("Tool Calls: 0 (0 success, 0 failed)")
    expect(formatted).toContain("## Timeline")
    // No phase line since phases array is empty
    expect(formatted).not.toContain("Phases:")
  })

  test("should handle entries without duration", () => {
    const log: Trajectory.EngagementLog = {
      rootSessionID: "session-abc123",
      startTime: "2026-01-16T10:00:00.000Z",
      entries: [
        {
          timestamp: "2026-01-16T10:00:05.000Z",
          agentName: "master",
          sessionID: "session-abc123",
          type: "tvar",
          summary: "Entry without duration",
          // No durationMs
        },
      ],
      summary: {
        totalAgents: 1,
        agentNames: ["master"],
        toolCalls: 0,
        successfulTools: 0,
        failedTools: 0,
        phases: [],
      },
    }

    const formatted = Trajectory.formatEngagementLog(log)

    expect(formatted).toContain("Entry without duration")
    // Should not have duration suffix
    expect(formatted).not.toMatch(/Entry without duration \(\d+ms\)/)
  })
})

describe("Trajectory.EngagementLog types", () => {
  test("EngagementLogEntry should have required fields", () => {
    const entry: Trajectory.EngagementLogEntry = {
      timestamp: "2026-01-16T10:00:00.000Z",
      agentName: "recon",
      sessionID: "session-123",
      type: "tvar",
      summary: "Test summary",
    }

    expect(entry.timestamp).toBeDefined()
    expect(entry.agentName).toBeDefined()
    expect(entry.sessionID).toBeDefined()
    expect(entry.type).toBeDefined()
    expect(entry.summary).toBeDefined()
  })

  test("EngagementLogEntry should support optional fields", () => {
    const entry: Trajectory.EngagementLogEntry = {
      timestamp: "2026-01-16T10:00:00.000Z",
      agentName: "recon",
      sessionID: "session-123",
      type: "tool",
      summary: "nmap: port scan",
      phase: "reconnaissance",
      durationMs: 5000,
      details: {
        tool: "nmap",
        toolStatus: "completed",
        thought: "Scanning for ports",
      },
    }

    expect(entry.phase).toBe("reconnaissance")
    expect(entry.durationMs).toBe(5000)
    expect(entry.details?.tool).toBe("nmap")
    expect(entry.details?.toolStatus).toBe("completed")
    expect(entry.details?.thought).toBe("Scanning for ports")
  })

  test("EngagementLog should have required summary fields", () => {
    const log: Trajectory.EngagementLog = {
      rootSessionID: "session-root",
      startTime: "2026-01-16T10:00:00.000Z",
      entries: [],
      summary: {
        totalAgents: 2,
        agentNames: ["master", "recon"],
        toolCalls: 5,
        successfulTools: 4,
        failedTools: 1,
        phases: ["reconnaissance"],
      },
    }

    expect(log.rootSessionID).toBe("session-root")
    expect(log.summary.totalAgents).toBe(2)
    expect(log.summary.agentNames).toEqual(["master", "recon"])
    expect(log.summary.toolCalls).toBe(5)
    expect(log.summary.successfulTools).toBe(4)
    expect(log.summary.failedTools).toBe(1)
    expect(log.summary.phases).toEqual(["reconnaissance"])
  })
})
