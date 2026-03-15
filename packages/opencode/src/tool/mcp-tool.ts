import z from "zod"
import { Tool } from "./tool"
import { ContainerManager } from "../container"
import { Log } from "../util/log"
import { store as storeOutput } from "./output-store"
import { TargetValidation } from "./target-validation"
import { PhaseGating } from "./phase-gating"
import { getRootSession } from "../session/hierarchy"
import * as SessionDirectory from "../session/directory"
import path from "path"
import os from "os"
import fs from "fs/promises"
import yaml from "js-yaml"
import {
  recordExperience,
  getToolContext,
  setCurrentPhase,
  type ToolResult as ExperienceToolResult,
  type ToolParams as ExperienceToolParams,
} from "../memory"

const log = Log.create({ service: "tool.mcp" })

// Common parameter names that contain targets
const TARGET_PARAM_NAMES = ["target", "host", "hostname", "url", "ip", "address", "target_host", "rhost", "rhosts"]

function summarizeTargetArgs(args: Record<string, unknown>): string {
  const keys = TARGET_PARAM_NAMES.concat(["port", "ports", "wordlist", "method"])
  const parts: string[] = []
  for (const key of keys) {
    if (args[key] !== undefined) {
      const val = String(args[key])
      parts.push(`${key}=${val.length > 50 ? val.slice(0, 50) + "..." : val}`)
    }
  }
  return parts.join(", ") || "(no target params)"
}

// Registry cache (shared with tool-registry-search.ts)
const REGISTRY_URL = "https://opensploit.ai/registry.yaml"
const REGISTRY_DIR = path.join(os.homedir(), ".opensploit")
const REGISTRY_PATH = path.join(REGISTRY_DIR, "registry.yaml")

interface RegistryTool {
  name: string
  image?: string
  // Local MCP server configuration (for tools like Burp)
  local?: {
    host: string
    port: number
    setup_url?: string
    setup_instructions?: string
  }
  methods?: Record<string, {
    description: string
    params?: Record<string, unknown>
    required_ports?: number[]
    timeout_seconds?: number
  }>
  timeout_seconds?: number
  requirements?: {
    network?: boolean
    privileged?: boolean
    local_only?: boolean // Cannot run in Docker
  }
  // Service container configuration (for VPN, proxies, etc.)
  service?: boolean // Mark as a service container that persists
  service_name?: string // Name for network sharing (e.g., "vpn")
  use_service?: string // Use network from this service (e.g., "vpn")
  see_also?: Array<{ tool: string; reason: string }>
  resources?: { memory_mb?: number; cpu?: number }
}

interface Registry {
  tools: Record<string, RegistryTool>
}

let cachedRegistry: Registry | null = null
let cacheTimestamp = 0
const CACHE_MAX_AGE_MS = 5 * 60 * 1000

/**
 * Call a local MCP server via HTTP
 */
async function callLocalMcpServer(
  host: string,
  port: number,
  method: string,
  args: Record<string, unknown>
): Promise<unknown> {
  const url = `http://${host}:${port}`

  // MCP over HTTP uses JSON-RPC style requests
  const request = {
    jsonrpc: "2.0",
    id: Date.now(),
    method: "tools/call",
    params: {
      name: method,
      arguments: args,
    },
  }

  log.info("calling local MCP server", { url, method })

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(request),
  })

  if (!response.ok) {
    throw new Error(`Local MCP server returned ${response.status}: ${response.statusText}`)
  }

  const result = await response.json()

  if (result.error) {
    throw new Error(result.error.message || "Local MCP server error")
  }

  return result.result
}

/**
 * Check if a local MCP server is available
 */
async function isLocalMcpServerAvailable(host: string, port: number): Promise<boolean> {
  try {
    const response = await fetch(`http://${host}:${port}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
      signal: AbortSignal.timeout(2000),
    })
    return response.ok || response.status === 400 // 400 might be method not found, but server is running
  } catch {
    return false
  }
}

async function getRegistry(): Promise<Registry> {
  const now = Date.now()

  if (cachedRegistry && now - cacheTimestamp < CACHE_MAX_AGE_MS) {
    return cachedRegistry
  }

  // Try to fetch fresh
  try {
    const response = await fetch(REGISTRY_URL)
    if (response.ok) {
      const text = await response.text()
      cachedRegistry = yaml.load(text) as Registry
      cacheTimestamp = now

      // Cache to disk
      await fs.mkdir(REGISTRY_DIR, { recursive: true }).catch(() => {})
      await fs.writeFile(REGISTRY_PATH, text).catch(() => {})

      return cachedRegistry
    }
  } catch {
    // Fall through to cache
  }

  // Try disk cache
  try {
    const text = await fs.readFile(REGISTRY_PATH, "utf-8")
    cachedRegistry = yaml.load(text) as Registry
    cacheTimestamp = now
    return cachedRegistry
  } catch {
    // Return empty
    return { tools: {} }
  }
}

const DESCRIPTION = `Invoke an MCP tool from the OpenSploit tool registry.

This tool spawns a Docker container running the specified security tool and executes the given method.

Usage:
- First use tool_registry_search to find available tools and their methods
- Then use this tool to invoke specific methods with parameters

Example:
  tool: "nmap"
  method: "port_scan"
  args: {"target": "10.10.10.1", "ports": "1-1000"}

Clock offset:
  Some Kerberos/AD operations fail if the container clock differs from the target by >5 minutes.
  Use clock_offset to shift the container's perceived time:
  tool: "impacket"
  method: "get_tgt"
  args: {"domain": "corp.local", "username": "admin", "password": "pass"}
  clock_offset: "+7h"

The container will be automatically started if not running, and will be stopped after idle timeout.`

interface ToolResult {
  output: string
  title: string
  metadata: {
    tool: string
    method: string
    success: boolean
    error?: string
    skipped?: boolean
  }
}

export const McpToolInvoke = Tool.define("mcp_tool", {
  description: DESCRIPTION,
  parameters: z.object({
    tool: z.string().describe("The tool name from the registry (e.g., 'nmap', 'sqlmap', 'ffuf')"),
    method: z.string().describe("The method to call on the tool (e.g., 'port_scan', 'test_injection')"),
    args: z.record(z.string(), z.unknown()).optional().describe("Arguments to pass to the method"),
    timeout: z.number().optional().describe("Timeout in seconds. Overrides the registry default. Use when you know the operation will take longer (e.g., full port scan, large wordlist)."),
    clock_offset: z.string().optional().describe(
      "Time offset for the container (e.g., '+7h', '-30m', '+2h30m'). " +
      "Uses libfaketime to shift the container's clock. " +
      "Required for Kerberos operations when target has clock skew (KRB_AP_ERR_SKEW). " +
      "Measure with: nmap -sV -p 88 <target> or check LDAP/SMB timestamps."
    ),
  }),
  async execute(params, ctx): Promise<ToolResult> {
    const { tool: toolName, method, args = {}, timeout: agentTimeout, clock_offset } = params
    const sessionId = ctx.sessionID
    const rootSessionId = getRootSession(sessionId)

    // Ensure session directory exists (for wordlists, artifacts, etc.)
    if (!SessionDirectory.exists(rootSessionId)) {
      SessionDirectory.create(rootSessionId)
    }
    const sessionDir = SessionDirectory.get(rootSessionId)

    log.info("invoking mcp tool", { toolName, method, args, sessionId, rootSessionId })

    // Get registry to find the image
    const registry = await getRegistry()
    const toolDef = registry.tools[toolName]

    if (!toolDef) {
      return {
        output: `Tool "${toolName}" not found in registry.\n\nUse tool_registry_search to find available tools.`,
        title: `Error: Tool not found`,
        metadata: { tool: toolName, method, success: false, error: "Tool not found" },
      }
    }

    // Check if tool has either Docker image or local server config
    if (!toolDef.image && !toolDef.local) {
      return {
        output: `Tool "${toolName}" does not have a Docker image or local server configured.\n\nThis tool may not be available yet.`,
        title: `Error: No configuration`,
        metadata: { tool: toolName, method, success: false, error: "No Docker image or local server" },
      }
    }

    // Check if method exists
    if (toolDef.methods && !toolDef.methods[method]) {
      const availableMethods = Object.keys(toolDef.methods).join(", ")
      return {
        output: `Method "${method}" not found on tool "${toolName}".\n\nAvailable methods: ${availableMethods}`,
        title: `Error: Method not found`,
        metadata: { tool: toolName, method, success: false, error: "Method not found" },
      }
    }

    // Timeout chain: agent-specified > tool-level registry default > 300s system default
    // (method-level kept for backwards compat but tool.yaml no longer ships per-method values)
    const methodDefForTimeout = toolDef.methods?.[method]
    const methodTimeout = methodDefForTimeout?.timeout_seconds
    const toolTimeout = toolDef.timeout_seconds
    const timeoutMs = agentTimeout ? agentTimeout * 1000
      : methodTimeout ? methodTimeout * 1000
      : toolTimeout ? toolTimeout * 1000
      : 300_000

    try {
      // Validate targets in args
      let targetWarning = ""
      for (const paramName of TARGET_PARAM_NAMES) {
        const value = args[paramName]
        if (typeof value === "string" && value) {
          const validation = TargetValidation.validateTarget(value)

          // Warn about high-risk targets (government, military, educational) but do NOT block
          if (validation.highRisk && !targetWarning) {
            targetWarning = `${validation.highRiskWarning}\n\n`
            log.warn("high-risk target detected", {
              toolName,
              method,
              target: value,
              category: validation.highRiskWarning,
            })
          }
          // Warn about external targets
          else if (validation.info.isExternal && !targetWarning) {
            targetWarning = `⚠️  EXTERNAL TARGET: ${value}\nType: ${validation.info.type.toUpperCase()}\nEnsure you have authorization to scan this target.\n\n`
            log.warn("external target detected", { toolName, method, target: value, type: validation.info.type })
          }
        }
      }

      // Check phase gating
      const phaseCheck = PhaseGating.checkToolInvocation(sessionId, toolName)
      let phaseWarning = ""
      if (phaseCheck.warning) {
        phaseWarning = phaseCheck.warning + "\n\n"
      }

      // Update ToolContext with current phase (Doc 22 §Agent Loop Integration)
      const toolPhase = PhaseGating.getToolPhase(toolName)
      if (toolPhase) {
        setCurrentPhase(sessionId, toolPhase)
      }

      // Ask permission to run the MCP tool via PermissionNext (respects agent rules)
      try {
        await ctx.ask({
          permission: "mcp_tool",
          patterns: [`mcp:${toolName}:${method}`],
          always: [`mcp:${toolName}:*`],
          metadata: {
            tool: toolName,
            method,
            args,
          },
        })
      } catch {
        return {
          output: `Permission denied to run ${toolName}.${method}`,
          title: `Blocked: Permission denied`,
          metadata: { tool: toolName, method, success: false, error: "Permission denied" },
        }
      }

      // Pre-flight: skip tools with repeated infrastructure failures (RC1)
      try {
        const { loadEngagementState } = await import("./engagement-state")
        const state = await loadEngagementState(rootSessionId).catch(() => ({} as any))
        const toolFailures = (state as any).toolFailures || []
        const { Config } = await import("../config/config")
        const cfg = await Config.get().catch(() => ({} as any))
        const threshold = (cfg as any).experimental?.tool_failure_threshold ?? 3
        const match = toolFailures.find(
          (f: any) => f.tool === toolName && (!f.method || f.method === method) && (f.count || 0) >= threshold
        )
        if (match) {
          return {
            output: `**SKIPPED**: \`${toolName}.${method}\` has failed ${match.count} times.\n\n` +
                    `Last error: ${match.error}\n\n` +
                    `Use \`tool_registry_search\` to find an alternative tool. ` +
                    `To retry, clear failures: \`update_engagement_state({ resetToolFailures: true })\`.`,
            title: `Skipped: ${toolName}.${method} (known broken)`,
            metadata: { tool: toolName, method, success: false, error: "Tool known broken", skipped: true },
          }
        }

        // Port pre-flight: check if required ports are accessible (RC2)
        const methodEntry = toolDef.methods?.[method]
        const requiredPorts: number[] = methodEntry?.required_ports ?? []

        if (requiredPorts.length > 0 && Array.isArray(state.ports) && state.ports.length > 0) {
          const portChecks = requiredPorts.map(rp => {
            const entry = state.ports.find((p: any) => p.port === rp)
            return { port: rp, scanned: !!entry, state: entry?.state as string | undefined }
          })

          const allBlocked = portChecks.every(p => p.scanned && (p.state === "filtered" || p.state === "closed"))
          const anyUnscanned = portChecks.some(p => !p.scanned)

          // Only block if we have positive evidence that EVERY required port is blocked
          if (allBlocked && !anyUnscanned) {
            const blockedList = portChecks.map(p => `${p.port} (${p.state})`).join(", ")
            return {
              output: `**ALL REQUIRED PORTS BLOCKED**: \`${toolName}.${method}\` needs port(s) ${requiredPorts.join(", ")} ` +
                      `but all are ${blockedList} on the target.\n\n` +
                      `Use \`tool_registry_search\` to find tools that work with the ports that ARE open.`,
              title: `Blocked: ${toolName}.${method} (ports ${requiredPorts.join(",")})`,
              metadata: { tool: toolName, method, success: false, error: `All required ports blocked` },
            }
          }
        }
      } catch { /* Non-critical pre-flight */ }

      // Determine if we should use local server or Docker
      let result: unknown
      let usedLocal = false

      if (toolDef.local) {
        // Try local MCP server first (e.g., Burp Suite)
        const { host, port, setup_url, setup_instructions } = toolDef.local
        const available = await isLocalMcpServerAvailable(host, port)

        if (available) {
          log.info("using local MCP server", { toolName, host, port })
          result = await callLocalMcpServer(host, port, method, args as Record<string, unknown>)
          usedLocal = true
        } else if (toolDef.requirements?.local_only) {
          // This tool can only run locally (no Docker fallback)
          return {
            output: `⚠️  LOCAL MCP SERVER NOT AVAILABLE\n\nTool "${toolName}" requires a local MCP server at ${host}:${port}.\n\nSetup instructions:\n${setup_instructions || `See ${setup_url || "tool documentation"} for setup instructions.`}\n\nEnsure the MCP server is running and accessible.`,
            title: `Error: Local server not available`,
            metadata: { tool: toolName, method, success: false, error: "Local server not available" },
          }
        }
        // Fall through to Docker if local not available and Docker fallback exists
      }

      if (!usedLocal) {
        // Use Docker container
        if (!toolDef.image) {
          return {
            output: `Tool "${toolName}" requires a local MCP server which is not running.\n\nNo Docker fallback available.`,
            title: `Error: No server available`,
            metadata: { tool: toolName, method, success: false, error: "No server available" },
          }
        }

        const dockerAvailable = await ContainerManager.isDockerAvailable()
        if (!dockerAvailable) {
          return {
            output: `Docker is not available.\n\nPlease ensure Docker is installed and running:\n  - Install Docker: https://docs.docker.com/get-docker/\n  - Start Docker daemon\n  - Verify with: docker info`,
            title: `Error: Docker not available`,
            metadata: { tool: toolName, method, success: false, error: "Docker not available" },
          }
        }

        // Determine service network to use
        // 1. Tool explicitly specifies use_service
        // 2. VPN service is active and tool needs network
        let useServiceNetwork: string | undefined
        if (toolDef.use_service) {
          useServiceNetwork = toolDef.use_service
        } else if (!toolDef.service && ContainerManager.isServiceActive("vpn")) {
          // Automatically use VPN network for network-enabled tools
          useServiceNetwork = "vpn"
          log.info("routing through VPN service", { toolName })
        }

        // Call the tool via container manager
        result = await ContainerManager.callTool(
          toolName,
          toolDef.image,
          method,
          args as Record<string, unknown>,
          {
            privileged: toolDef.requirements?.privileged ?? false,
            sessionDir,
            isService: toolDef.service,
            serviceName: toolDef.service_name,
            useServiceNetwork,
            timeout: timeoutMs,
            clockOffset: clock_offset,
            resources: toolDef.resources,
          }
        )
      }

      // Format the raw result
      let rawOutput = ""

      if (typeof result === "object" && result !== null) {
        const r = result as Record<string, unknown>

        // Handle MCP tool result format
        if ("content" in r && Array.isArray(r.content)) {
          for (const item of r.content as Array<{ type: string; text?: string }>) {
            if (item.type === "text" && item.text) {
              rawOutput += item.text + "\n"
            }
          }
        } else {
          rawOutput = JSON.stringify(result, null, 2)
        }
      } else {
        rawOutput = String(result)
      }

      // Detect MCP soft failures: BaseMCPServer sets isError=true when result.success=false
      // This is the middle ground — agent SEES the failure (metadata.success: false) but it's
      // NOT auto-recorded to toolFailures/circuit breaker (LLM decides what to record)
      const isToolError = typeof result === "object" && result !== null &&
        (result as Record<string, unknown>).isError === true

      // Use output store to handle large outputs
      // This prevents context overflow by storing large outputs externally
      // and returning a summary with a reference ID
      // Use ROOT session ID so outputs are accessible to all agents in the tree
      const storeResult = await storeOutput({
        sessionId: rootSessionId,
        tool: toolName,
        method,
        data: typeof result === "object" ? result : null,
        rawOutput,
      })

      let output: string
      const warnings = phaseWarning + targetWarning
      if (storeResult.stored) {
        // Large output was stored externally, return summary with reference
        output = warnings + storeResult.output
        log.info("large output stored externally", {
          toolName,
          method,
          outputId: storeResult.outputId,
        })
      } else {
        // Small output, return directly with header
        output = `${warnings}# ${toolName}.${method} Result\n\n${storeResult.output}`
      }

      // Detect Kerberos clock skew and hint about clock_offset
      if (!clock_offset && /KRB_AP_ERR_SKEW|clock skew too great/i.test(rawOutput)) {
        output += "\n\n**HINT:** Kerberos clock skew detected. Use the `clock_offset` parameter " +
          "to shift the container's clock. Measure target time with `nmap -sV -p 88 <target>` " +
          "or compare LDAP/SMB timestamps, then pass e.g. `clock_offset: \"+7h\"`."
      }

      // Record experience for learning (Doc 22 §Part 2)
      // This captures successful tool executions for pattern learning
      try {
        const experienceParams: ExperienceToolParams = {
          tool: toolName,
          method,
          args: args as Record<string, unknown>,
        }
        const experienceOutput: ExperienceToolResult = isToolError
          ? { error: rawOutput.slice(0, 500), output: rawOutput }
          : {
              output: rawOutput,
              ...(typeof result === "object" && result !== null ? (result as Record<string, unknown>) : {}),
            }
        const toolContext = getToolContext(sessionId)
        await recordExperience(sessionId, experienceParams, experienceOutput, toolContext)
      } catch (expError) {
        // Don't fail tool execution if experience recording fails
        log.warn("failed to record experience", { toolName, method, error: String(expError) })
      }

      return {
        output,
        title: `${toolName}.${method}${storeResult.stored ? " (output stored)" : ""}`,
        metadata: { tool: toolName, method, success: !isToolError },
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error)
      log.error("mcp tool invocation failed", { toolName, method, error: errorMessage })

      // Record failed experience for learning (Doc 22 §Part 2)
      // Failures are important for learning recovery patterns
      try {
        const experienceParams: ExperienceToolParams = {
          tool: toolName,
          method,
          args: args as Record<string, unknown>,
        }
        const experienceOutput: ExperienceToolResult = {
          error: errorMessage,
        }
        const toolContext = getToolContext(sessionId)
        await recordExperience(sessionId, experienceParams, experienceOutput, toolContext)
      } catch (expError) {
        // Don't fail tool execution if experience recording fails
        log.warn("failed to record failed experience", { toolName, method, error: String(expError) })
      }

      // Auto-record MCP failure to engagement state (RC1)
      try {
        const { loadEngagementState, mergeState: mergeEngState, saveEngagementState } = await import("./engagement-state")
        const state = await loadEngagementState(rootSessionId).catch(() => ({} as any))
        if (Object.keys(state).length > 0) {
          await saveEngagementState(rootSessionId, mergeEngState(state, {
            toolFailures: [{
              tool: toolName,
              method,
              error: errorMessage.slice(0, 200),
              count: 1,
              firstSeen: new Date().toISOString(),
              lastSeen: new Date().toISOString(),
              argsSummary: summarizeTargetArgs(args as Record<string, unknown>),
            }],
          }))
        }
      } catch { /* Don't fail tool execution if state recording fails */ }

      // Timeout-specific error messages (RC3)
      const isTimeout = /timeout|timed?\s*out|ETIMEDOUT/i.test(errorMessage)
      if (isTimeout) {
        const sec = Math.round(timeoutMs / 1000)
        return {
          output: `**TIMEOUT**: \`${toolName}.${method}\` exceeded ${sec}s timeout.\n\n` +
                  `Suggestions:\n` +
                  `- Use more targeted parameters (fewer ports, smaller wordlist)\n` +
                  `- Break the task into smaller chunks\n` +
                  `- Use \`tool_registry_search\` for a faster alternative`,
          title: `Timeout: ${toolName}.${method} (${sec}s)`,
          metadata: { tool: toolName, method, success: false, error: `Timeout after ${sec}s` },
        }
      }

      // Image pull failure with see_also alternatives (RC8)
      const isPullFailure = /pull|manifest|denied|unauthorized|not found/i.test(errorMessage) &&
                            /image|docker|container/i.test(errorMessage)
      if (isPullFailure) {
        const seeAlso = toolDef.see_also
        let altMsg = ""
        if (Array.isArray(seeAlso) && seeAlso.length > 0) {
          altMsg = "\n\nAlternatives from registry:\n" +
            seeAlso.map((a) => `- **${a.tool}**: ${a.reason}`).join("\n")
        }
        return {
          output: `**DOCKER IMAGE UNAVAILABLE**: \`${toolDef.image}\` could not be pulled.\n\n` +
                  `Error: ${errorMessage}\n\n` +
                  `Use \`tool_registry_search\` to find alternative tools.${altMsg}`,
          title: `Image unavailable: ${toolName}`,
          metadata: { tool: toolName, method, success: false, error: "Image pull failed" },
        }
      }

      return {
        output: `Failed to invoke ${toolName}.${method}:\n\n${errorMessage}`,
        title: `Error: ${toolName}.${method}`,
        metadata: { tool: toolName, method, success: false, error: errorMessage },
      }
    }
  },
})
