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
