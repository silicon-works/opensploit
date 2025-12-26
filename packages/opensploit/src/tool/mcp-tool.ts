import z from "zod"
import { Tool } from "./tool"
import { ContainerManager } from "../container"
import { Log } from "../util/log"
import { OutputStore } from "./output-store"
import path from "path"
import os from "os"
import fs from "fs/promises"
import yaml from "js-yaml"

const log = Log.create({ service: "tool.mcp" })

// Registry cache (shared with tool-registry-search.ts)
const REGISTRY_URL = "https://opensploit.ai/registry.yaml"
const REGISTRY_DIR = path.join(os.homedir(), ".opensploit")
const REGISTRY_PATH = path.join(REGISTRY_DIR, "registry.yaml")

interface RegistryTool {
  name: string
  image?: string
  methods?: Record<string, { description: string; params?: Record<string, unknown> }>
}

interface Registry {
  tools: Record<string, RegistryTool>
}

let cachedRegistry: Registry | null = null
let cacheTimestamp = 0
const CACHE_MAX_AGE_MS = 5 * 60 * 1000

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

    if (!toolDef.image) {
      return {
        output: `Tool "${toolName}" does not have a Docker image configured.\n\nThis tool may not be available yet.`,
        title: `Error: No image`,
        metadata: { tool: toolName, method, success: false, error: "No Docker image" },
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

    try {
      // Check Docker availability first
      const dockerAvailable = await ContainerManager.isDockerAvailable()
      if (!dockerAvailable) {
        return {
          output: `Docker is not available.\n\nPlease ensure Docker is installed and running:\n  - Install Docker: https://docs.docker.com/get-docker/\n  - Start Docker daemon\n  - Verify with: docker info`,
          title: `Error: Docker not available`,
          metadata: { tool: toolName, method, success: false, error: "Docker not available" },
        }
      }

      // Call the tool via container manager
      const result = await ContainerManager.callTool(toolName, toolDef.image, method, args as Record<string, unknown>)

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
      if (storeResult.stored) {
        // Large output was stored externally, return summary with reference
        output = storeResult.output
        log.info("large output stored externally", {
          toolName,
          method,
          outputId: storeResult.reference?.id,
          sizeBytes: storeResult.reference?.sizeBytes,
        })
      } else {
        // Small output, return directly with header
        output = `# ${toolName}.${method} Result\n\n${storeResult.output}`
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
