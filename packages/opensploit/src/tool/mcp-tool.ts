import z from "zod"
import { Tool } from "./tool"
import { ContainerManager } from "../container"
import { Log } from "../util/log"
import { OutputStore } from "./output-store"
import { TargetValidation } from "./target-validation"
import { PhaseGating } from "./phase-gating"
import { Permission } from "../permission"
import path from "path"
import os from "os"
import fs from "fs/promises"
import yaml from "js-yaml"

const log = Log.create({ service: "tool.mcp" })

// Common parameter names that contain targets
const TARGET_PARAM_NAMES = ["target", "host", "hostname", "url", "ip", "address", "target_host", "rhost", "rhosts"]

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
    when_to_use?: string
    next_step?: string
    params?: Record<string, unknown>
  }>
  requirements?: {
    network?: boolean
    privileged?: boolean
    local_only?: boolean  // Cannot run in Docker
  }
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

The container will be automatically started if not running, and will be stopped after idle timeout.`

interface ToolResult {
  output: string
  title: string
  metadata: {
    tool: string
    method: string
    success: boolean
    error?: string
  }
}

export const McpToolInvoke = Tool.define("mcp_tool", {
  description: DESCRIPTION,
  parameters: z.object({
    tool: z.string().describe("The tool name from the registry (e.g., 'nmap', 'sqlmap', 'ffuf')"),
    method: z.string().describe("The method to call on the tool (e.g., 'port_scan', 'test_injection')"),
    args: z.record(z.string(), z.unknown()).optional().describe("Arguments to pass to the method"),
  }),
  async execute(params, ctx): Promise<ToolResult> {
    const { tool: toolName, method, args = {} } = params
    const sessionId = ctx.sessionID

    log.info("invoking mcp tool", { toolName, method, args, sessionId })

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
      let output = `Method "${method}" not found on tool "${toolName}".\n\n`
      output += `## Available Methods for ${toolName}\n\n`

      for (const [methodName, methodDef] of Object.entries(toolDef.methods)) {
        output += `### ${methodName}\n`
        output += `${methodDef.description}\n`
        if (methodDef.when_to_use) {
          output += `*When to use:* ${methodDef.when_to_use}\n`
        }
        output += "\n"
      }

      output += `\nUse one of the methods listed above with mcp_tool.`

      return {
        output,
        title: `Error: Method not found`,
        metadata: { tool: toolName, method, success: false, error: "Method not found" },
      }
    }

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
            log.warn("high-risk target detected", { toolName, method, target: value, category: validation.highRiskWarning })
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

      // Ask permission to run the MCP tool
      try {
        await Permission.ask({
          type: "mcp_tool",
          title: `Run ${toolName}.${method}?`,
          pattern: `mcp:${toolName}:${method}`,
          sessionID: ctx.sessionID,
          messageID: ctx.messageID,
          callID: ctx.callID,
          metadata: {
            tool: toolName,
            method,
            args,
          },
        })
      } catch (error) {
        if (error instanceof Permission.RejectedError) {
          return {
            output: `Permission denied to run ${toolName}.${method}`,
            title: `Blocked: Permission denied`,
            metadata: { tool: toolName, method, success: false, error: "Permission denied" },
          }
        }
        throw error
      }

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

        // Call the tool via container manager
        result = await ContainerManager.callTool(
          toolName,
          toolDef.image,
          method,
          args as Record<string, unknown>,
          { privileged: toolDef.requirements?.privileged ?? false }
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

      // Use OutputStore to handle large outputs
      // This prevents context overflow by storing large outputs externally
      // and returning a summary with a reference ID
      const storeResult = await OutputStore.store({
        sessionId,
        toolName,
        method,
        content: rawOutput,
        contentType: typeof result === "object" ? "json" : "text",
      })

      let output: string
      const warnings = phaseWarning + targetWarning
      if (storeResult.stored) {
        // Large output was stored externally, return summary with reference
        output = warnings + storeResult.output
        log.info("large output stored externally", {
          toolName,
          method,
          outputId: storeResult.reference?.id,
          sizeBytes: storeResult.reference?.sizeBytes,
        })
      } else {
        // Small output, return directly with header
        output = `${warnings}# ${toolName}.${method} Result\n\n${storeResult.output}`
      }

      return {
        output,
        title: `${toolName}.${method}${storeResult.stored ? " (output stored)" : ""}`,
        metadata: { tool: toolName, method, success: true },
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error)
      log.error("mcp tool invocation failed", { toolName, method, error: errorMessage })

      return {
        output: `Failed to invoke ${toolName}.${method}:\n\n${errorMessage}`,
        title: `Error: ${toolName}.${method}`,
        metadata: { tool: toolName, method, success: false, error: errorMessage },
      }
    }
  },
})
