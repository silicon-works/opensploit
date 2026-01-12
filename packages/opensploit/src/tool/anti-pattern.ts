import { Log } from "../util/log"

const log = Log.create({ service: "tool.anti-pattern" })

/**
 * Anti-pattern detection for penetration testing
 * Detects common mistakes and provides guidance
 */
export namespace AntiPattern {
  export interface Detection {
    pattern: string
    severity: "warning" | "error"
    message: string
    suggestion: string
  }

  /**
   * Security tools that MUST be run via MCP, not bash
   * Running these via bash violates the MCP architecture - agents should use mcp_tool instead
   */
  const SECURITY_TOOLS_VIA_BASH = [
    // Network scanning
    { pattern: /\bnmap\b/, tool: "nmap", mcpMethod: "nmap.port_scan" },
    { pattern: /\bmasscan\b/, tool: "masscan", mcpMethod: "masscan.scan" },

    // Web fuzzing
    { pattern: /\bffuf\b/, tool: "ffuf", mcpMethod: "ffuf.fuzz" },
    { pattern: /\bgobuster\b/, tool: "gobuster", mcpMethod: "ffuf.fuzz (use ffuf instead)" },
    { pattern: /\bdirbuster\b/, tool: "dirbuster", mcpMethod: "ffuf.fuzz (use ffuf instead)" },
    { pattern: /\bdirb\b/, tool: "dirb", mcpMethod: "ffuf.fuzz (use ffuf instead)" },

    // Vulnerability scanning
    { pattern: /\bnikto\b/, tool: "nikto", mcpMethod: "nikto.scan" },
    { pattern: /\bnuclei\b/, tool: "nuclei", mcpMethod: "nuclei.scan" },

    // SQL injection
    { pattern: /\bsqlmap\b/, tool: "sqlmap", mcpMethod: "sqlmap.test_injection" },

    // Password attacks
    { pattern: /\bhydra\b/, tool: "hydra", mcpMethod: "hydra.brute_force" },
    { pattern: /\bjohn\b/, tool: "john", mcpMethod: "john.crack" },
    { pattern: /\bhashcat\b/, tool: "hashcat", mcpMethod: "john.crack (use john for basic cracking)" },

    // Exploitation
    { pattern: /\bmsfconsole\b/, tool: "metasploit", mcpMethod: "metasploit.run_module" },
    { pattern: /\bmsfvenom\b/, tool: "msfvenom", mcpMethod: "payload.generate" },

    // Remote access
    { pattern: /\bssh\s+\S+@/, tool: "ssh", mcpMethod: "ssh.exec" },
    { pattern: /\bnc\s+-/, tool: "netcat", mcpMethod: "netcat.listen or netcat.connect" },
    { pattern: /\bnetcat\b/, tool: "netcat", mcpMethod: "netcat.listen or netcat.connect" },

    // HTTP requests (for exploitation)
    { pattern: /\bcurl\s+.*-d\s/, tool: "curl (POST)", mcpMethod: "curl.request" },
    { pattern: /\bwget\b/, tool: "wget", mcpMethod: "curl.download" },
  ]

  /**
   * Patterns that indicate potential issues
   */
  const WARNING_PATTERNS = [
    {
      pattern: /--privileged/,
      message: "Running Docker with --privileged flag directly",
      suggestion: "Use mcp_tool which handles privileged containers with user approval",
    },
    {
      pattern: /sudo\s+(nmap|hydra|nikto|sqlmap)/,
      message: "Running security tools with sudo",
      suggestion: "Use mcp_tool - containers handle permissions properly",
    },
    {
      pattern: /\|\s*(grep|awk|sed)\s+password/i,
      message: "Piping output to search for passwords",
      suggestion: "Use the dedicated find_credentials method on database tools",
    },
    {
      pattern: /echo\s+.*>>?\s*\/etc\/(passwd|shadow|hosts)/,
      message: "Directly modifying system files",
      suggestion: "Use the hosts tool for /etc/hosts, avoid modifying other system files",
    },
    {
      pattern: /sudo\s+tee\s+(-a\s+)?\/etc\/hosts/,
      message: "Modifying /etc/hosts via sudo tee",
      suggestion: "Use the hosts tool instead: hosts({ action: 'add', entries: [{ ip: '...', hostname: '...' }] })",
    },
    {
      pattern: /rm\s+-rf?\s+\//,
      message: "Dangerous recursive deletion command detected",
      suggestion: "Never run recursive delete on root paths",
    },
    {
      pattern: />\s*\/dev\/null\s*2>&1/,
      message: "Suppressing all output",
      suggestion: "Keep output visible for logging and analysis",
    },
  ]

  /**
   * Check a bash command for anti-patterns
   */
  export function checkBashCommand(command: string): Detection[] {
    const detections: Detection[] = []

    // Check for security tools via bash - BLOCK these, agents must use MCP tools
    for (const { pattern, tool, mcpMethod } of SECURITY_TOOLS_VIA_BASH) {
      if (pattern.test(command)) {
        detections.push({
          pattern: tool,
          severity: "error", // Block - security tools must use MCP architecture
          message: `Using ${tool} via bash instead of MCP`,
          suggestion: `Use mcp_tool to invoke ${mcpMethod} instead. MCP tools run in isolated containers with proper logging and session tracking.`,
        })
      }
    }

    // Check for warning patterns
    for (const { pattern, message, suggestion } of WARNING_PATTERNS) {
      if (pattern.test(command)) {
        detections.push({
          pattern: pattern.source,
          severity: "warning",
          message,
          suggestion,
        })
      }
    }

    if (detections.length > 0) {
      log.warn("anti-patterns detected", { command: command.slice(0, 100), detections: detections.length })
    }

    return detections
  }

  /**
   * Format detections for display
   */
  export function formatDetections(detections: Detection[]): string {
    if (detections.length === 0) return ""

    const errors = detections.filter((d) => d.severity === "error")
    const warnings = detections.filter((d) => d.severity === "warning")

    let output = ""

    if (errors.length > 0) {
      output += "⛔ ANTI-PATTERN ERRORS:\n"
      for (const error of errors) {
        output += `  • ${error.message}\n    → ${error.suggestion}\n`
      }
      output += "\n"
    }

    if (warnings.length > 0) {
      output += "⚠️  ANTI-PATTERN WARNINGS:\n"
      for (const warning of warnings) {
        output += `  • ${warning.message}\n    → ${warning.suggestion}\n`
      }
      output += "\n"
    }

    return output
  }

  /**
   * Check if detections include blocking errors
   */
  export function hasBlockingErrors(detections: Detection[]): boolean {
    return detections.some((d) => d.severity === "error")
  }

  /**
   * Anti-patterns for tool selection
   */
  const TOOL_SELECTION_PATTERNS = [
    {
      wrongTool: "sqlmap",
      correctTool: "nosqlmap",
      condition: (args: Record<string, unknown>) =>
        typeof args.target === "string" && /mongodb|nosql|mongo/i.test(args.target),
      message: "Using sqlmap for NoSQL database",
    },
    {
      wrongTool: "hydra",
      correctTool: "john",
      condition: (args: Record<string, unknown>) =>
        typeof args.hash === "string" || typeof args.hashfile === "string",
      message: "Using hydra for hash cracking (hydra is for network brute-force)",
    },
  ]

  /**
   * Check tool selection for potential mistakes
   */
  export function checkToolSelection(
    toolName: string,
    args: Record<string, unknown>
  ): Detection | null {
    for (const pattern of TOOL_SELECTION_PATTERNS) {
      if (toolName === pattern.wrongTool && pattern.condition(args)) {
        return {
          pattern: pattern.wrongTool,
          severity: "warning",
          message: pattern.message,
          suggestion: `Consider using ${pattern.correctTool} instead`,
        }
      }
    }
    return null
  }
}
