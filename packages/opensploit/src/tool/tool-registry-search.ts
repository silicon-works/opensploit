import z from "zod"
import { Tool } from "./tool"
import DESCRIPTION from "./tool-registry-search.txt"
import path from "path"
import os from "os"
import fs from "fs/promises"
import yaml from "js-yaml"
import { Log } from "../util/log"

const log = Log.create({ service: "tool.registry-search" })

// Registry URLs and paths
const REGISTRY_URL = "https://opensploit.ai/registry.yaml"
const REGISTRY_DIR = path.join(os.homedir(), ".opensploit")
const REGISTRY_PATH = path.join(REGISTRY_DIR, "registry.yaml")
const CACHE_MAX_AGE_MS = 5 * 60 * 1000 // 5 minutes

// Raw registry schema (matches mcp-tools registry.yaml format)
const RawMethodSchema = z.object({
  description: z.string(),
  when_to_use: z.string().optional(),
  params: z.record(z.string(), z.any()).optional(),
  returns: z.record(z.string(), z.any()).optional(),
})

const RawToolEntry = z.object({
  name: z.string(),
  version: z.string().optional(),
  description: z.string(),
  image: z.string().optional(),
  image_size_mb: z.number().optional(),
  capabilities: z.array(z.string()).optional().default([]),
  phases: z.array(z.string()).optional().default([]),
  methods: z.record(z.string(), RawMethodSchema).optional(),
  requirements: z
    .object({
      network: z.boolean().optional(),
      privileged: z.boolean().optional(),
    })
    .optional(),
  resources: z
    .object({
      memory_mb: z.number().optional(),
      cpu: z.number().optional(),
    })
    .optional(),
})

const RawRegistry = z.object({
  version: z.string(),
  updated_at: z.string().optional(),
  tools: z.record(z.string(), RawToolEntry),
})

// Normalized tool entry (with methods as array)
interface ToolMethod {
  name: string
  description: string
  when_to_use?: string
  params?: Record<string, any>
  returns?: Record<string, any>
}

interface ToolEntry {
  name: string
  version?: string
  description: string
  image?: string
  capabilities: string[]
  phases: string[]
  methods: ToolMethod[]
  requirements?: {
    network?: boolean
    privileged?: boolean
  }
  resources?: {
    memory_mb?: number
    cpu?: number
  }
}

interface Registry {
  version: string
  updated_at?: string
  tools: Record<string, ToolEntry>
}

// Transform raw registry to normalized format
function transformRegistry(raw: z.infer<typeof RawRegistry>): Registry {
  const tools: Record<string, ToolEntry> = {}

  for (const [key, rawTool] of Object.entries(raw.tools)) {
    const methods: ToolMethod[] = []

    if (rawTool.methods) {
      for (const [methodName, methodDef] of Object.entries(rawTool.methods)) {
        methods.push({
          name: methodName,
          description: methodDef.description,
          when_to_use: methodDef.when_to_use,
          params: methodDef.params,
          returns: methodDef.returns,
        })
      }
    }

    tools[key] = {
      name: rawTool.name,
      version: rawTool.version,
      description: rawTool.description,
      image: rawTool.image,
      capabilities: rawTool.capabilities,
      phases: rawTool.phases,
      methods,
      requirements: rawTool.requirements,
      resources: rawTool.resources,
    }
  }

  return {
    version: raw.version,
    updated_at: raw.updated_at,
    tools,
  }
}

// In-memory cache
let cachedRegistry: Registry | null = null
let cacheTimestamp = 0

// Ensure registry directory exists
async function ensureRegistryDir(): Promise<void> {
  try {
    await fs.mkdir(REGISTRY_DIR, { recursive: true })
  } catch {
    // Directory may already exist
  }
}

// Fetch registry from URL
async function fetchRegistry(): Promise<Registry | null> {
  try {
    log.info("fetching registry from", { url: REGISTRY_URL })
    const response = await fetch(REGISTRY_URL, {
      headers: { "User-Agent": "opensploit-cli" },
    })

    if (!response.ok) {
      log.warn("failed to fetch registry", { status: response.status })
      return null
    }

    const text = await response.text()
    const parsed = yaml.load(text) as unknown
    const validated = RawRegistry.parse(parsed)

    // Cache to disk
    await ensureRegistryDir()
    await fs.writeFile(REGISTRY_PATH, text, "utf-8")
    log.info("registry cached to disk", { path: REGISTRY_PATH })

    return transformRegistry(validated)
  } catch (error) {
    log.warn("error fetching registry", { error: String(error) })
    return null
  }
}

// Load registry from disk cache
async function loadCachedRegistry(): Promise<Registry | null> {
  try {
    const text = await fs.readFile(REGISTRY_PATH, "utf-8")
    const parsed = yaml.load(text) as unknown
    const validated = RawRegistry.parse(parsed)
    log.info("loaded registry from cache", { path: REGISTRY_PATH })
    return transformRegistry(validated)
  } catch {
    log.info("no cached registry found")
    return null
  }
}

// Get registry (fetch with cache fallback)
async function getRegistry(): Promise<Registry> {
  const now = Date.now()

  // Return memory cache if fresh
  if (cachedRegistry && now - cacheTimestamp < CACHE_MAX_AGE_MS) {
    return cachedRegistry
  }

  // Try to fetch fresh registry
  const fresh = await fetchRegistry()
  if (fresh) {
    cachedRegistry = fresh
    cacheTimestamp = now
    return fresh
  }

  // Fall back to disk cache
  const cached = await loadCachedRegistry()
  if (cached) {
    cachedRegistry = cached
    cacheTimestamp = now
    return cached
  }

  // Return empty registry as last resort
  log.warn("no registry available, returning empty")
  return {
    version: "0.0.0",
    tools: {},
  }
}

// Simple semantic matching for tool search
function matchScore(tool: ToolEntry, query: string, phase?: string, capability?: string): number {
  let score = 0
  const queryLower = query.toLowerCase()
  const words = queryLower.split(/\s+/)

  // Match against tool name
  if (tool.name.toLowerCase().includes(queryLower)) {
    score += 10
  }

  // Match against description
  const descLower = tool.description.toLowerCase()
  for (const word of words) {
    if (descLower.includes(word)) {
      score += 2
    }
  }

  // Match against capabilities
  for (const cap of tool.capabilities) {
    const capLower = cap.toLowerCase().replace(/_/g, " ")
    if (capLower.includes(queryLower) || queryLower.includes(capLower)) {
      score += 5
    }
    for (const word of words) {
      if (capLower.includes(word)) {
        score += 2
      }
    }
  }

  // Match against phases
  if (phase) {
    const phaseLower = phase.toLowerCase()
    if (tool.phases.some((p) => p.toLowerCase() === phaseLower)) {
      score += 8
    }
  }

  // Match against specific capability
  if (capability) {
    const capLower = capability.toLowerCase()
    if (tool.capabilities.some((c) => c.toLowerCase() === capLower)) {
      score += 10
    }
  }

  // Match against method descriptions
  for (const method of tool.methods) {
    const methodDesc = method.description.toLowerCase()
    const whenToUse = method.when_to_use?.toLowerCase() || ""
    for (const word of words) {
      if (methodDesc.includes(word) || whenToUse.includes(word)) {
        score += 1
      }
    }
  }

  return score
}

// Format tool for output
function formatToolOutput(tool: ToolEntry): string {
  let output = `## ${tool.name} (v${tool.version || "latest"})\n\n`
  output += `**Description:** ${tool.description}\n\n`
  output += `**Phases:** ${tool.phases.join(", ") || "any"}\n`
  output += `**Capabilities:** ${tool.capabilities.join(", ") || "general"}\n`

  if (tool.image) {
    output += `**Image:** ${tool.image}\n`
  }

  if (tool.methods.length > 0) {
    output += `\n### Methods\n\n`
    for (const method of tool.methods) {
      output += `#### ${method.name}\n`
      output += `${method.description}\n`
      if (method.when_to_use) {
        output += `*When to use:* ${method.when_to_use}\n`
      }
      if (method.params) {
        output += `\n**Parameters:**\n`
        for (const [paramName, paramInfo] of Object.entries(method.params as Record<string, any>)) {
          const required = paramInfo.required ? " (required)" : ""
          const defaultVal = paramInfo.default !== undefined ? ` [default: ${paramInfo.default}]` : ""
          output += `- \`${paramName}\`${required}: ${paramInfo.description || paramInfo.type}${defaultVal}\n`
        }
      }
      output += "\n"
    }
  }

  return output
}

export const ToolRegistrySearchTool = Tool.define("tool_registry_search", {
  description: DESCRIPTION,
  parameters: z.object({
    query: z.string().describe("Natural language query to search for tools (e.g., 'port scanning', 'SQL injection')"),
    phase: z
      .enum(["reconnaissance", "enumeration", "exploitation", "post-exploitation"])
      .optional()
      .describe("Filter by pentest phase"),
    capability: z.string().optional().describe("Filter by specific capability (e.g., 'port_scanning', 'sql_injection')"),
    limit: z.number().optional().default(5).describe("Maximum number of results to return"),
  }),
  async execute(params, _ctx) {
    const { query, phase, capability, limit = 5 } = params

    log.info("searching tool registry", { query, phase, capability })

    // Fetch registry (with caching)
    const registry = await getRegistry()

    // Score and rank tools
    const toolsWithScores: Array<{ tool: ToolEntry; score: number }> = []

    for (const [, tool] of Object.entries(registry.tools)) {
      const score = matchScore(tool, query, phase, capability)
      if (score > 0) {
        toolsWithScores.push({ tool, score })
      }
    }

    // Sort by score descending
    toolsWithScores.sort((a, b) => b.score - a.score)

    // Take top results
    const topTools = toolsWithScores.slice(0, limit)

    if (topTools.length === 0) {
      return {
        output: `No tools found matching query: "${query}"${phase ? ` in phase: ${phase}` : ""}${capability ? ` with capability: ${capability}` : ""}\n\nTry a different query or check available phases: reconnaissance, enumeration, exploitation, post-exploitation`,
        title: `Tool search: ${query}`,
        metadata: { results: 0, registry_version: registry.version },
      }
    }

    // Format output
    let output = `# Tool Registry Search Results\n\n`
    output += `**Query:** ${query}\n`
    if (phase) output += `**Phase Filter:** ${phase}\n`
    if (capability) output += `**Capability Filter:** ${capability}\n`
    output += `**Results:** ${topTools.length} tools found\n\n---\n\n`

    for (const { tool } of topTools) {
      output += formatToolOutput(tool)
      output += "---\n\n"
    }

    output += `\n*To use a tool, invoke it via its MCP server with the appropriate method and parameters.*`

    return {
      output,
      title: `Tool search: ${query} (${topTools.length} results)`,
      metadata: {
        results: topTools.length,
        registry_version: registry.version,
      },
    }
  },
})
