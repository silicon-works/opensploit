import z from "zod"
import { Tool } from "./tool"
import DESCRIPTION from "./tool-registry-search.txt"
import path from "path"
import os from "os"
import fs from "fs/promises"
import yaml from "js-yaml"
import { Log } from "../util/log"

const log = Log.create({ service: "tool.registry-search" })

// =============================================================================
// Configuration
// =============================================================================

const REGISTRY_CONFIG = {
  REMOTE_URL: "https://opensploit.ai/registry.yaml",
  CACHE_DIR: path.join(os.homedir(), ".opensploit"),
  CACHE_PATH: path.join(os.homedir(), ".opensploit", "registry.yaml"),
  CACHE_TTL_MS: 24 * 60 * 60 * 1000, // 24 hours
}

const VALID_PHASES = ["reconnaissance", "enumeration", "exploitation", "post-exploitation"] as const
type Phase = (typeof VALID_PHASES)[number]

// =============================================================================
// Registry Zod Schemas (for validation)
// =============================================================================

const ParamDefSchema = z.object({
  type: z.union([z.string(), z.array(z.string())]),
  required: z.boolean().optional(),
  default: z.any().optional(),
  description: z.string().optional(),
  enum: z.array(z.union([z.string(), z.number()])).optional(),
  values: z.array(z.string()).optional(),
})

const ReturnDefSchema = z.object({
  type: z.string(),
  description: z.string().optional(),
  items: z.string().optional(),
})

const MethodDefSchema = z.object({
  description: z.string(),
  when_to_use: z.string().optional(),
  next_step: z.string().optional(),
  params: z.record(z.string(), ParamDefSchema).optional(),
  returns: z.record(z.string(), ReturnDefSchema).optional(),
})

const NeverUseForEntrySchema = z.union([
  z.string(),
  z.object({
    task: z.string(),
    use_instead: z.union([z.string(), z.array(z.string())]),
    reason: z.string().optional(),
  }),
])

const RegistryToolSchema = z.object({
  name: z.string(),
  version: z.string().optional(),
  description: z.string(),
  image: z.string().optional(),
  image_size_mb: z.number().optional(),
  external: z.boolean().optional(),
  source: z.string().optional(),
  capabilities: z.array(z.string()).optional().default([]),
  phases: z.array(z.string()).optional().default([]),
  routing: z
    .object({
      use_for: z.array(z.string()).optional(),
      triggers: z.array(z.string()).optional(),
      never_use_for: z.array(NeverUseForEntrySchema).optional(),
      prefer_over: z.array(z.string()).optional(),
    })
    .optional(),
  requirements: z
    .object({
      network: z.boolean().optional(),
      privileged: z.boolean().optional(),
      privileged_reason: z.string().optional(),
    })
    .optional(),
  resources: z
    .object({
      memory_mb: z.number().optional(),
      cpu: z.number().optional(),
    })
    .optional(),
  methods: z.record(z.string(), MethodDefSchema).optional(),
})

const RegistrySchema = z.object({
  version: z.string(),
  updated_at: z.string().optional(),
  tools: z.record(z.string(), RegistryToolSchema),
})

// =============================================================================
// Registry Types (inferred from Zod schemas)
// =============================================================================

type ParamDef = z.infer<typeof ParamDefSchema>
type ReturnDef = z.infer<typeof ReturnDefSchema>
type MethodDef = z.infer<typeof MethodDefSchema>
type NeverUseForEntry = z.infer<typeof NeverUseForEntrySchema>
type RegistryTool = z.infer<typeof RegistryToolSchema>
type Registry = z.infer<typeof RegistrySchema>

// =============================================================================
// Result Types
// =============================================================================

interface ToolMethodResult {
  name: string
  description: string
  when_to_use?: string
  next_step?: string
  params: Record<string, ParamDef>
  returns?: Record<string, ReturnDef>
}

interface ToolResult {
  tool: string
  name: string
  description: string
  image?: string
  routing: {
    use_for: string[]
    triggers?: string[]
    never_use_for?: NeverUseForEntry[]
    prefer_over?: string[]
  }
  suggested_alternatives?: string[]
  capabilities: string[]
  phases: string[]
  requirements?: {
    network?: boolean
    privileged?: boolean
    privileged_reason?: string
  }
  methods: ToolMethodResult[]
  warning?: string
}

interface ToolSearchResult {
  query: string
  phase?: string
  capability?: string
  results: ToolResult[]
  anti_pattern_warnings: string[]
  registry_version: string
  cache_status?: "fresh" | "stale" | "new"
}

// =============================================================================
// Registry Fetching
// =============================================================================

interface CacheInfo {
  registry: Registry
  timestamp: number
}

let memoryCache: CacheInfo | null = null

async function ensureCacheDir(): Promise<void> {
  try {
    await fs.mkdir(REGISTRY_CONFIG.CACHE_DIR, { recursive: true })
  } catch {
    // Directory may already exist
  }
}

async function getCacheTimestamp(): Promise<number | null> {
  try {
    const stats = await fs.stat(REGISTRY_CONFIG.CACHE_PATH)
    return stats.mtime.getTime()
  } catch {
    return null
  }
}

function isCacheStale(timestamp: number): boolean {
  return Date.now() - timestamp > REGISTRY_CONFIG.CACHE_TTL_MS
}

async function loadCacheFromDisk(): Promise<Registry | null> {
  try {
    const text = await fs.readFile(REGISTRY_CONFIG.CACHE_PATH, "utf-8")
    const parsed = yaml.load(text)
    const validated = RegistrySchema.parse(parsed)
    log.info("loaded registry from cache", { path: REGISTRY_CONFIG.CACHE_PATH })
    return validated
  } catch (error) {
    if (error instanceof z.ZodError) {
      log.warn("invalid registry cache format", { errors: error.issues.slice(0, 3) })
    }
    return null
  }
}

async function fetchRemoteRegistry(): Promise<Registry | null> {
  try {
    log.info("fetching registry from remote", { url: REGISTRY_CONFIG.REMOTE_URL })
    const response = await fetch(REGISTRY_CONFIG.REMOTE_URL, {
      headers: { "User-Agent": "opensploit-cli" },
      signal: AbortSignal.timeout(30000), // 30 second timeout
    })

    if (!response.ok) {
      log.warn("failed to fetch registry", { status: response.status })
      return null
    }

    const text = await response.text()
    const parsed = yaml.load(text)
    const validated = RegistrySchema.parse(parsed)

    // Save to disk cache
    await ensureCacheDir()
    await fs.writeFile(REGISTRY_CONFIG.CACHE_PATH, text, "utf-8")
    log.info("registry cached to disk", { path: REGISTRY_CONFIG.CACHE_PATH })

    return validated
  } catch (error) {
    if (error instanceof z.ZodError) {
      log.warn("invalid registry format from remote", { errors: error.issues.slice(0, 3) })
    } else {
      log.warn("error fetching registry", { error: String(error) })
    }
    return null
  }
}

interface GetRegistryResult {
  registry: Registry
  cacheStatus: "fresh" | "stale" | "new"
}

async function getRegistry(): Promise<GetRegistryResult> {
  const now = Date.now()

  // Check memory cache first (for performance within session)
  if (memoryCache && !isCacheStale(memoryCache.timestamp)) {
    return { registry: memoryCache.registry, cacheStatus: "fresh" }
  }

  // Check disk cache
  const cacheTimestamp = await getCacheTimestamp()
  const diskCache = cacheTimestamp ? await loadCacheFromDisk() : null

  // If disk cache is fresh, use it
  if (diskCache && cacheTimestamp && !isCacheStale(cacheTimestamp)) {
    memoryCache = { registry: diskCache, timestamp: cacheTimestamp }
    return { registry: diskCache, cacheStatus: "fresh" }
  }

  // Try to fetch from remote
  const remote = await fetchRemoteRegistry()
  if (remote) {
    memoryCache = { registry: remote, timestamp: now }
    return { registry: remote, cacheStatus: "new" }
  }

  // Fall back to stale disk cache
  if (diskCache) {
    log.warn("using stale cache, remote fetch failed")
    memoryCache = { registry: diskCache, timestamp: cacheTimestamp! }
    return { registry: diskCache, cacheStatus: "stale" }
  }

  // No registry available
  throw new Error("Registry unavailable. Check network connection and try 'opensploit update'.")
}

// =============================================================================
// Search Logic
// =============================================================================

function buildSearchText(tool: RegistryTool): string {
  const parts: string[] = [
    tool.name,
    tool.description,
    ...(tool.capabilities || []),
    ...(tool.routing?.use_for || []),
    ...(tool.routing?.triggers || []),
  ]

  // Add method names and descriptions
  if (tool.methods) {
    for (const [methodName, method] of Object.entries(tool.methods)) {
      parts.push(methodName)
      parts.push(method.description)
      if (method.when_to_use) {
        parts.push(method.when_to_use)
      }
    }
  }

  return parts.join(" ").toLowerCase()
}

function countKeywordMatches(query: string, searchText: string): number {
  const queryWords = query
    .toLowerCase()
    .split(/\s+/)
    .filter((w) => w.length > 1)
  let score = 0

  for (const word of queryWords) {
    // Exact word match gets higher score
    const regex = new RegExp(`\\b${word}\\b`, "g")
    const exactMatches = (searchText.match(regex) || []).length
    score += exactMatches * 3

    // Partial match (word contained in text)
    if (searchText.includes(word)) {
      score += 1
    }
  }

  // Bonus for query appearing as a phrase
  if (searchText.includes(query.toLowerCase())) {
    score += 5
  }

  return score
}

function checkAntiPatterns(query: string, tool: RegistryTool): string | undefined {
  const neverUseFor = tool.routing?.never_use_for || []
  const queryLower = query.toLowerCase()

  for (const pattern of neverUseFor) {
    if (typeof pattern === "string") {
      if (queryLower.includes(pattern.toLowerCase())) {
        return `${tool.name} should not be used for "${pattern}"`
      }
    } else if (pattern.task && queryLower.includes(pattern.task.toLowerCase())) {
      const alternative = Array.isArray(pattern.use_instead) ? pattern.use_instead.join(" or ") : pattern.use_instead
      const reason = pattern.reason ? ` (${pattern.reason})` : ""
      return `${tool.name} should not be used for "${pattern.task}". Use ${alternative} instead${reason}.`
    }
  }

  return undefined
}

function normalizeNeverUseFor(entries: Array<string | NeverUseForEntry>): NeverUseForEntry[] {
  return entries.map((entry) => {
    if (typeof entry === "string") {
      return { task: entry, use_instead: "" }
    }
    return entry
  })
}

function extractSuggestedAlternatives(tool: RegistryTool): string[] {
  const alternatives = new Set<string>()

  // From prefer_over
  for (const alt of tool.routing?.prefer_over || []) {
    alternatives.add(alt)
  }

  // From never_use_for.use_instead
  for (const entry of tool.routing?.never_use_for || []) {
    if (typeof entry !== "string" && entry.use_instead) {
      const useInstead = Array.isArray(entry.use_instead) ? entry.use_instead : [entry.use_instead]
      for (const alt of useInstead) {
        if (alt) alternatives.add(alt)
      }
    }
  }

  return Array.from(alternatives)
}

function formatToolResult(toolId: string, tool: RegistryTool, warning?: string): ToolResult {
  const methods: ToolMethodResult[] = []

  if (tool.methods) {
    for (const [methodName, method] of Object.entries(tool.methods)) {
      methods.push({
        name: methodName,
        description: method.description,
        when_to_use: method.when_to_use,
        next_step: method.next_step,
        params: method.params || {},
        returns: method.returns,
      })
    }
  }

  return {
    tool: toolId,
    name: tool.name,
    description: tool.description,
    image: tool.image,
    routing: {
      use_for: tool.routing?.use_for || [],
      triggers: tool.routing?.triggers,
      never_use_for: tool.routing?.never_use_for ? normalizeNeverUseFor(tool.routing.never_use_for) : undefined,
      prefer_over: tool.routing?.prefer_over,
    },
    suggested_alternatives: extractSuggestedAlternatives(tool),
    capabilities: tool.capabilities || [],
    phases: tool.phases || [],
    requirements: tool.requirements,
    methods,
    warning,
  }
}

interface ScoredTool {
  toolId: string
  tool: RegistryTool
  score: number
  warning?: string
}

function searchTools(
  registry: Registry,
  query: string,
  phase?: string,
  capability?: string,
  limit: number = 5
): { results: ToolResult[]; warnings: string[] } {
  const scoredTools: ScoredTool[] = []
  const warnings: string[] = []

  for (const [toolId, tool] of Object.entries(registry.tools)) {
    // Phase filter
    if (phase && !tool.phases?.includes(phase)) {
      continue
    }

    // Capability filter
    if (capability && !tool.capabilities?.includes(capability)) {
      continue
    }

    // Keyword matching
    const searchText = buildSearchText(tool)
    const score = countKeywordMatches(query, searchText)

    // Check anti-patterns
    const antiPatternWarning = checkAntiPatterns(query, tool)
    if (antiPatternWarning) {
      warnings.push(antiPatternWarning)
    }

    if (score > 0) {
      scoredTools.push({ toolId, tool, score, warning: antiPatternWarning })
    }
  }

  // Sort by score descending
  scoredTools.sort((a, b) => b.score - a.score)

  // Format top results
  const results = scoredTools.slice(0, limit).map((st) => formatToolResult(st.toolId, st.tool, st.warning))

  return { results, warnings: [...new Set(warnings)] }
}

// =============================================================================
// Output Formatting
// =============================================================================

function formatOutput(result: ToolSearchResult): string {
  const lines: string[] = []

  lines.push(`# Tool Registry Search Results`)
  lines.push(``)
  lines.push(`**Query:** ${result.query}`)
  if (result.phase) lines.push(`**Phase Filter:** ${result.phase}`)
  if (result.capability) lines.push(`**Capability Filter:** ${result.capability}`)
  lines.push(`**Results:** ${result.results.length} tools found`)
  lines.push(`**Registry Version:** ${result.registry_version}`)
  if (result.cache_status === "stale") {
    lines.push(`**Warning:** Using cached registry. Run 'opensploit update' to refresh.`)
  }
  lines.push(``)

  if (result.anti_pattern_warnings.length > 0) {
    lines.push(`## Warnings`)
    for (const warning of result.anti_pattern_warnings) {
      lines.push(`- ⚠️ ${warning}`)
    }
    lines.push(``)
  }

  if (result.results.length === 0) {
    lines.push(`No tools found matching your query. Try different keywords or remove filters.`)
    lines.push(``)
    lines.push(`**Valid phases:** ${VALID_PHASES.join(", ")}`)
    return lines.join("\n")
  }

  lines.push(`---`)
  lines.push(``)

  for (const tool of result.results) {
    lines.push(`## ${tool.name}${tool.warning ? " ⚠️" : ""}`)
    lines.push(``)
    lines.push(`${tool.description}`)
    lines.push(``)

    if (tool.warning) {
      lines.push(`> **Warning:** ${tool.warning}`)
      lines.push(``)
    }

    lines.push(`- **Tool ID:** \`${tool.tool}\``)
    if (tool.image) lines.push(`- **Image:** \`${tool.image}\``)
    lines.push(`- **Phases:** ${tool.phases.join(", ") || "any"}`)
    lines.push(`- **Capabilities:** ${tool.capabilities.join(", ") || "general"}`)

    if (tool.requirements) {
      const reqs: string[] = []
      if (tool.requirements.network) reqs.push("network")
      if (tool.requirements.privileged) {
        reqs.push(`privileged${tool.requirements.privileged_reason ? ` (${tool.requirements.privileged_reason})` : ""}`)
      }
      if (reqs.length > 0) {
        lines.push(`- **Requirements:** ${reqs.join(", ")}`)
      }
    }

    if (tool.routing.use_for && tool.routing.use_for.length > 0) {
      lines.push(`- **Use for:** ${tool.routing.use_for.join(", ")}`)
    }

    if (tool.suggested_alternatives && tool.suggested_alternatives.length > 0) {
      lines.push(`- **See also:** ${tool.suggested_alternatives.join(", ")}`)
    }

    if (tool.methods.length > 0) {
      lines.push(``)
      lines.push(`### Methods`)
      lines.push(``)

      for (const method of tool.methods) {
        lines.push(`#### \`${method.name}\``)
        lines.push(``)
        lines.push(`${method.description}`)
        if (method.when_to_use) {
          lines.push(``)
          lines.push(`*When to use:* ${method.when_to_use}`)
        }

        if (method.params && Object.keys(method.params).length > 0) {
          lines.push(``)
          lines.push(`**Parameters:**`)
          for (const [paramName, param] of Object.entries(method.params)) {
            const required = param.required ? " (required)" : ""
            const defaultVal = param.default !== undefined ? ` [default: ${param.default}]` : ""
            lines.push(`- \`${paramName}\`${required}: ${param.description || param.type}${defaultVal}`)
          }
        }

        if (method.returns && Object.keys(method.returns).length > 0) {
          lines.push(``)
          lines.push(`**Returns:**`)
          for (const [returnName, ret] of Object.entries(method.returns)) {
            lines.push(`- \`${returnName}\`: ${ret.description || ret.type}`)
          }
        }

        if (method.next_step) {
          lines.push(``)
          lines.push(`*Next step:* ${method.next_step}`)
        }

        lines.push(``)
      }
    }

    lines.push(`---`)
    lines.push(``)
  }

  lines.push(`*To use a tool, invoke it via MCP with the tool ID and method name.*`)

  return lines.join("\n")
}

// =============================================================================
// Tool Definition
// =============================================================================

export const ToolRegistrySearchTool = Tool.define("tool_registry_search", {
  description: DESCRIPTION,
  parameters: z.object({
    query: z.string().describe("Natural language query to search for tools (e.g., 'port scanning', 'SQL injection')"),
    phase: z
      .enum(VALID_PHASES)
      .optional()
      .describe("Filter by security phase: reconnaissance, enumeration, exploitation, post-exploitation"),
    capability: z
      .string()
      .optional()
      .describe("Filter by specific capability (e.g., 'sql_injection', 'port_scanning', 'web_fuzzing')"),
    limit: z.number().optional().default(5).describe("Maximum number of results to return (default: 5)"),
  }),
  async execute(params, _ctx) {
    const { query, phase, capability, limit = 5 } = params

    log.info("searching tool registry", { query, phase, capability, limit })

    // Get registry with caching
    const { registry, cacheStatus } = await getRegistry()

    // Search tools
    const { results, warnings } = searchTools(registry, query, phase, capability, limit)

    // Build result
    const searchResult: ToolSearchResult = {
      query,
      phase,
      capability,
      results,
      anti_pattern_warnings: warnings,
      registry_version: registry.version,
      cache_status: cacheStatus,
    }

    // Format output
    const output = formatOutput(searchResult)

    return {
      output,
      title: `Tool search: ${query} (${results.length} results)`,
      metadata: {
        query,
        phase,
        capability,
        results_count: results.length,
        registry_version: registry.version,
        cache_status: cacheStatus,
        warnings: warnings.length > 0 ? warnings : undefined,
      },
    }
  },
})
