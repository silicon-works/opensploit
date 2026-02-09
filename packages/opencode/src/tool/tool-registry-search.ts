import z from "zod"
import { Tool } from "./tool"
import DESCRIPTION from "./tool-registry-search.txt"
import path from "path"
import os from "os"
import fs from "fs/promises"
import yaml from "js-yaml"
import * as lancedb from "@lancedb/lancedb"
import { Log } from "../util/log"
import {
  updateSearchContext,
  getToolContext,
  unifiedSearch,
  formatUnifiedResults,
  type SearchResult,
  type ScoredTool,
  type SearchContext,
} from "../memory"
import {
  importFromLance,
  importFromYAML,
  loadRegistry,
  getStoredHash,
  needsUpdate,
  hasVectors,
  TOOLS_TABLE_NAME,
} from "../memory/tools"
import { getConnection } from "../memory/database"
import { getEmbeddingService } from "../memory/embedding"

const log = Log.create({ service: "tool.registry-search" })

// =============================================================================
// Configuration
// =============================================================================

const REGISTRY_CONFIG = {
  REMOTE_URL: "https://opensploit.ai/registry.yaml",
  REMOTE_HASH_URL: "https://opensploit.ai/registry.sha256",
  REMOTE_LANCE_URL: "https://opensploit.ai/registry.lance.tar.gz",
  CACHE_DIR: path.join(os.homedir(), ".opensploit"),
  CACHE_PATH: path.join(os.homedir(), ".opensploit", "registry.yaml"),
  LANCE_CACHE_PATH: path.join(os.homedir(), ".opensploit", "registry.lance.tar.gz"),
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
    use_instead: z.union([z.string(), z.array(z.string())]).optional(),
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
}).passthrough() // Allow extra fields like see_also, warnings, internal

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
  registry_hash: string
  cache_status?: "fresh" | "stale" | "new"
}

// =============================================================================
// Registry Fetching — Hash-Based Freshness
// =============================================================================

interface CacheInfo {
  registry: Registry
  hash: string
  timestamp: number
}

let memoryCache: CacheInfo | null = null

/** Cached result of hasVectors() — reset on registry import */
let _vectorsAvailable: boolean | null = null

async function ensureCacheDir(): Promise<void> {
  try {
    await fs.mkdir(REGISTRY_CONFIG.CACHE_DIR, { recursive: true })
  } catch {
    // Directory may already exist
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

/**
 * Compute SHA-256 hash of string content.
 */
async function computeHash(content: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(content)
  const hashBuffer = await crypto.subtle.digest("SHA-256", data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("")
}

/**
 * Fetch remote registry hash (64 bytes, very fast).
 */
async function fetchRemoteHash(): Promise<string | null> {
  try {
    const response = await fetch(REGISTRY_CONFIG.REMOTE_HASH_URL, {
      headers: { "User-Agent": "opensploit-cli" },
      signal: AbortSignal.timeout(5000), // 5 second timeout — it's tiny
    })
    if (!response.ok) return null
    const text = await response.text()
    return text.trim()
  } catch {
    return null
  }
}

/**
 * Download and import .lance archive.
 */
async function downloadAndImportLance(hash: string): Promise<boolean> {
  try {
    log.info("downloading registry .lance archive", { url: REGISTRY_CONFIG.REMOTE_LANCE_URL })
    const response = await fetch(REGISTRY_CONFIG.REMOTE_LANCE_URL, {
      headers: { "User-Agent": "opensploit-cli" },
      signal: AbortSignal.timeout(60000), // 60 second timeout — larger file
    })
    if (!response.ok) {
      log.warn("failed to download .lance archive", { status: response.status })
      return false
    }

    await ensureCacheDir()
    const buffer = await response.arrayBuffer()
    await fs.writeFile(REGISTRY_CONFIG.LANCE_CACHE_PATH, Buffer.from(buffer))

    await importFromLance(REGISTRY_CONFIG.LANCE_CACHE_PATH, hash)
    _vectorsAvailable = null // Reset cache — new import may change vector availability
    log.info("imported registry from .lance archive")

    // Clean up tar file
    try { await fs.unlink(REGISTRY_CONFIG.LANCE_CACHE_PATH) } catch { /* ok */ }
    return true
  } catch (error) {
    log.warn("lance archive import failed", { error: String(error) })
    return false
  }
}

/**
 * Download YAML and import to LanceDB (fallback).
 */
async function downloadAndImportYAML(hash: string): Promise<Registry | null> {
  try {
    log.info("fetching registry YAML", { url: REGISTRY_CONFIG.REMOTE_URL })
    const response = await fetch(REGISTRY_CONFIG.REMOTE_URL, {
      headers: { "User-Agent": "opensploit-cli" },
      signal: AbortSignal.timeout(30000),
    })
    if (!response.ok) return null

    const text = await response.text()
    const parsed = yaml.load(text)
    const validated = RegistrySchema.parse(parsed)

    // Save to disk cache
    await ensureCacheDir()
    await fs.writeFile(REGISTRY_CONFIG.CACHE_PATH, text, "utf-8")

    // Import into LanceDB with FTS index (no vectors)
    await importFromYAML(validated.tools, hash)
    _vectorsAvailable = null // Reset cache — YAML import has no vectors
    log.info("imported registry from YAML fallback")

    return validated
  } catch (error) {
    log.warn("YAML registry fetch/import failed", { error: String(error) })
    return null
  }
}

/**
 * Load registry from LanceDB and reconstruct into Registry format.
 */
async function loadFromLanceDB(): Promise<{ registry: Registry; hash: string } | null> {
  try {
    const result = await loadRegistry()
    if (!result) return null

    // Version is not stored in LanceDB (only per-tool data is). Hardcoded
    // to satisfy RegistrySchema. Version checking was replaced by hash-based
    // freshness, so this value is unused for any logic.
    const parsed = { version: "2.0", tools: result.tools }
    const validated = RegistrySchema.parse(parsed)
    log.info("loaded registry from LanceDB", { hash: result.hash.slice(0, 16) })
    return { registry: validated, hash: result.hash }
  } catch (error) {
    log.debug("LanceDB registry load failed", { error: String(error) })
    return null
  }
}

interface GetRegistryResult {
  registry: Registry
  hash: string
  cacheStatus: "fresh" | "stale" | "new"
}

/**
 * Get the registry with hash-based freshness checking.
 *
 * Flow:
 * 1. Memory cache (instant, within session)
 * 2. Fetch remote hash (64 bytes, <100ms)
 * 3. Compare to stored hash
 * 4. Match → load from LanceDB (instant)
 * 5. Mismatch → download .lance archive → importFromLance()
 * 6. .lance fails → download YAML → importFromYAML()
 * 7. All remote fail → use existing LanceDB or YAML disk cache
 */
async function getRegistry(): Promise<GetRegistryResult> {
  const now = Date.now()

  // 1. Check memory cache (within-session performance)
  if (memoryCache && !isCacheStale(memoryCache.timestamp)) {
    return { registry: memoryCache.registry, hash: memoryCache.hash, cacheStatus: "fresh" }
  }

  // 2. Fetch remote hash (tiny, fast)
  const remoteHash = await fetchRemoteHash()

  if (remoteHash) {
    // 3. Compare to stored hash
    const isStale = await needsUpdate(remoteHash)

    if (!isStale) {
      // 4. Hash matches — load from LanceDB (instant, no download needed)
      const lanceResult = await loadFromLanceDB()
      if (lanceResult) {
        memoryCache = { registry: lanceResult.registry, hash: lanceResult.hash, timestamp: now }
        return { registry: lanceResult.registry, hash: lanceResult.hash, cacheStatus: "fresh" }
      }
    }

    // 5. Hash mismatch or LanceDB empty — try downloading .lance archive
    const lanceImported = await downloadAndImportLance(remoteHash)
    if (lanceImported) {
      const lanceResult = await loadFromLanceDB()
      if (lanceResult) {
        memoryCache = { registry: lanceResult.registry, hash: remoteHash, timestamp: now }
        return { registry: lanceResult.registry, hash: remoteHash, cacheStatus: "new" }
      }
    }

    // 6. .lance failed — fall back to YAML download
    const yamlRegistry = await downloadAndImportYAML(remoteHash)
    if (yamlRegistry) {
      memoryCache = { registry: yamlRegistry, hash: remoteHash, timestamp: now }
      return { registry: yamlRegistry, hash: remoteHash, cacheStatus: "new" }
    }
  }

  // 7. All remote failed — try existing LanceDB (stale)
  const staleResult = await loadFromLanceDB()
  if (staleResult) {
    log.warn("using stale LanceDB data, remote unavailable")
    memoryCache = { registry: staleResult.registry, hash: staleResult.hash, timestamp: now }
    return { registry: staleResult.registry, hash: staleResult.hash, cacheStatus: "stale" }
  }

  // Final fallback — disk cache YAML
  const diskCache = await loadCacheFromDisk()
  if (diskCache) {
    log.warn("using YAML disk cache, remote and LanceDB both unavailable")
    const fallbackHash = await computeHash(JSON.stringify(diskCache))
    // Import to LanceDB so search works
    try {
      await importFromYAML(diskCache.tools, fallbackHash)
      _vectorsAvailable = null
    } catch { /* non-critical */ }
    memoryCache = { registry: diskCache, hash: fallbackHash, timestamp: now }
    return { registry: diskCache, hash: fallbackHash, cacheStatus: "stale" }
  }

  throw new Error("Registry unavailable. Check network connection and try 'opensploit update'.")
}

// =============================================================================
// Routing Bonus / Penalty Functions (kept from original)
// =============================================================================

/**
 * Bug Fix 1: Triggers should be matched as regex patterns
 * Doc 22 §Part 1, Bug 1 (lines 274-290)
 */
function calculateTriggerBonus(query: string, tool: RegistryTool): number {
  let bonus = 0
  const triggers = tool.routing?.triggers || []

  for (const trigger of triggers) {
    try {
      const regex = new RegExp(trigger, "i")
      if (regex.test(query)) {
        bonus += 35
        log.debug("trigger regex matched", { tool: tool.name, trigger, query })
      }
    } catch {
      log.debug("invalid trigger regex", { tool: tool.name, trigger })
    }
  }

  return bonus
}

/**
 * Bug Fix 2: use_for should receive bonus weighting
 * Doc 22 §Part 1, Bug 2 (lines 292-309)
 */
function calculateUseForBonus(query: string, tool: RegistryTool): number {
  let bonus = 0
  const queryLower = query.toLowerCase()
  const useForList = tool.routing?.use_for || []

  for (const useFor of useForList) {
    const useForLower = useFor.toLowerCase()

    if (queryLower.includes(useForLower)) {
      bonus += 8
    } else if (useForLower.includes(queryLower)) {
      bonus += 5
    } else {
      const useForWords = useForLower.split(/\s+/)
      const queryWords = queryLower.split(/\s+/)
      const overlap = useForWords.filter((w) =>
        queryWords.some((qw) => qw.startsWith(w) || w.startsWith(qw) || qw === w)
      )
      if (overlap.length >= 2) {
        bonus += 3
      }
    }
  }

  return bonus
}

/**
 * Bug Fix 3: never_use_for should penalize score
 * Doc 22 §Part 1, Bug 3 (lines 311-326)
 */
function calculateNeverUseForPenalty(query: string, tool: RegistryTool): number {
  let penalty = 0
  const queryLower = query.toLowerCase()
  const neverUseFor = tool.routing?.never_use_for || []

  for (const pattern of neverUseFor) {
    const task = typeof pattern === "string" ? pattern : pattern.task
    if (task && queryLower.includes(task.toLowerCase())) {
      penalty -= 15
    }
  }

  return penalty
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

  for (const alt of tool.routing?.prefer_over || []) {
    alternatives.add(alt)
  }

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

// =============================================================================
// Search Logic — LanceDB Hybrid Search
// =============================================================================

interface LocalScoredTool {
  toolId: string
  tool: RegistryTool
  score: number
  warning?: string
}

interface SearchToolsResult {
  results: ToolResult[]
  warnings: string[]
  scoredResults: Array<{ tool: string; score: number; description: string }>
}

/**
 * Search tools using LanceDB hybrid search (FTS + vector via RRF).
 *
 * When vectors are available (from .lance archive):
 *   → FTS (BM25) + vector (cosine) combined via RRF reranker
 * When no vectors (YAML import):
 *   → FTS-only search
 * Routing bonuses/penalties applied on top of LanceDB _score.
 */
async function searchToolsLance(
  registry: Registry,
  query: string,
  phase?: string,
  capability?: string,
  limit: number = 5
): Promise<SearchToolsResult> {
  const warnings: string[] = []

  try {
    const db = await getConnection()
    const tables = await db.tableNames()

    if (!tables.includes(TOOLS_TABLE_NAME)) {
      // No tools table yet — fall back to in-memory search
      return searchToolsInMemory(registry, query, phase, capability, limit)
    }

    const table = await db.openTable(TOOLS_TABLE_NAME)

    // Use cached value (reset on registry import) to avoid per-search table query
    if (_vectorsAvailable === null) {
      _vectorsAvailable = await hasVectors()
    }
    const vectorsAvailable = _vectorsAvailable

    let results: any[]

    if (vectorsAvailable) {
      // Try hybrid search: FTS + vector combined via RRF
      const embeddingService = getEmbeddingService()
      const embedding = await embeddingService.embed(query)
      const queryVector = embedding?.dense ?? null

      if (queryVector) {
        // Hybrid: FTS (BM25) + vector (cosine) combined via RRF
        try {
          const reranker = await lancedb.rerankers.RRFReranker.create()
          results = await table
            .query()
            .nearestTo(new Float32Array(queryVector))
            .fullTextSearch(query)
            .rerank(reranker)
            .select(["id", "name", "description", "search_text", "phases_json",
                     "capabilities_json", "routing_json", "methods_json", "raw_json"])
            .limit(limit * 4) // Over-fetch for post-filtering
            .toArray()
        } catch (error) {
          // Hybrid search failed (e.g. no FTS index) — fall back to vector only
          log.warn("hybrid search failed, trying vector-only", { error: String(error) })
          results = await table
            .search(queryVector)
            .select(["id", "name", "description", "search_text", "phases_json",
                     "capabilities_json", "routing_json", "methods_json", "raw_json"])
            .limit(limit * 4)
            .toArray()
        }
      } else {
        // Embedding unavailable — FTS only
        results = await searchFTSOnly(table, query, limit * 4)
      }
    } else {
      // No vectors (YAML import) — FTS only
      results = await searchFTSOnly(table, query, limit * 4)
    }

    // Apply routing bonuses on top of LanceDB scores
    const scored = applyRoutingBonuses(results, registry, query, phase, capability, warnings)

    // Sort by combined score
    scored.sort((a, b) => b.score - a.score)

    // Take top results
    const topResults = scored.slice(0, limit)

    log.debug("lance search scores", {
      query,
      phase,
      hybrid: vectorsAvailable,
      topResults: topResults.slice(0, 5).map((t) => ({ tool: t.toolId, score: t.score })),
    })

    const formattedResults = topResults.map((st) => formatToolResult(st.toolId, st.tool, st.warning))
    const scoredResults = topResults.map((st) => ({
      tool: st.toolId,
      score: st.score,
      description: st.tool.description,
    }))

    return { results: formattedResults, warnings: [...new Set(warnings)], scoredResults }
  } catch (error) {
    log.warn("LanceDB search failed, falling back to in-memory", { error: String(error) })
    return searchToolsInMemory(registry, query, phase, capability, limit)
  }
}

/**
 * FTS-only search on the tools table.
 */
async function searchFTSOnly(table: lancedb.Table, query: string, limit: number): Promise<any[]> {
  try {
    return await table
      .search(query, "fts")
      .select(["id", "name", "description", "search_text", "phases_json",
               "capabilities_json", "routing_json", "methods_json", "raw_json"])
      .limit(limit)
      .toArray()
  } catch (error) {
    // FTS index may not exist — fall back to full scan
    log.warn("FTS search failed, using full scan", { error: String(error) })
    return await table.query()
      .select(["id", "name", "description", "search_text", "phases_json",
               "capabilities_json", "routing_json", "methods_json", "raw_json"])
      .limit(10000)
      .toArray()
  }
}

/**
 * Apply routing bonuses/penalties on LanceDB results.
 */
function applyRoutingBonuses(
  results: any[],
  registry: Registry,
  query: string,
  phase: string | undefined,
  capability: string | undefined,
  warnings: string[]
): LocalScoredTool[] {
  const scored: LocalScoredTool[] = []

  for (const row of results) {
    const toolId = row.id as string
    const tool = registry.tools[toolId]
    if (!tool) continue

    // Capability filter (hard filter)
    if (capability && !tool.capabilities?.includes(capability)) {
      continue
    }

    // Base score from LanceDB (_score for FTS, _distance for vector)
    let baseScore = 0
    if (row._score != null) {
      baseScore = row._score
    } else if (row._distance != null) {
      // Convert distance to similarity (lower distance = higher score)
      baseScore = 1 / (1 + row._distance)
    } else {
      // No score from LanceDB — give a small base for full-scan results
      baseScore = 0.1
    }

    // Normalize base score to a reasonable range for combining with bonuses
    // LanceDB BM25 scores can vary widely; scale to ~0-50 range
    const normalizedBase = Math.min(baseScore * 10, 50)

    let score = normalizedBase

    // Apply routing bonuses/penalties
    score += calculateTriggerBonus(query, tool)
    score += calculateUseForBonus(query, tool)
    score += calculateNeverUseForPenalty(query, tool)

    // Phase boost
    if (phase && tool.phases?.includes(phase)) {
      score += 5
    }

    // Anti-pattern warnings
    const antiPatternWarning = checkAntiPatterns(query, tool)
    if (antiPatternWarning) {
      warnings.push(antiPatternWarning)
    }

    if (score > 0) {
      scored.push({ toolId, tool, score, warning: antiPatternWarning })
    }
  }

  return scored
}

/**
 * In-memory fallback search (when LanceDB is completely unavailable).
 * Uses the original keyword matching algorithm.
 */
function searchToolsInMemory(
  registry: Registry,
  query: string,
  phase?: string,
  capability?: string,
  limit: number = 5
): SearchToolsResult {
  const scoredTools: LocalScoredTool[] = []
  const warnings: string[] = []

  for (const [toolId, tool] of Object.entries(registry.tools)) {
    if (capability && !tool.capabilities?.includes(capability)) {
      continue
    }

    // Simple keyword matching
    const searchText = [
      tool.name, tool.description,
      ...(tool.capabilities || []),
    ].join(" ").toLowerCase()

    const queryWords = query.toLowerCase().split(/\s+/).filter((w) => w.length > 1)
    let score = 0
    for (const word of queryWords) {
      const regex = new RegExp(`\\b${word}\\b`, "g")
      score += (searchText.match(regex) || []).length * 3
      if (searchText.includes(word)) score += 1
    }
    if (searchText.includes(query.toLowerCase())) score += 5

    // Routing bonuses
    score += calculateTriggerBonus(query, tool)
    score += calculateUseForBonus(query, tool)
    score += calculateNeverUseForPenalty(query, tool)

    if (phase && tool.phases?.includes(phase)) {
      score += 5
    }

    const antiPatternWarning = checkAntiPatterns(query, tool)
    if (antiPatternWarning) warnings.push(antiPatternWarning)

    if (score > 0) {
      scoredTools.push({ toolId, tool, score, warning: antiPatternWarning })
    }
  }

  scoredTools.sort((a, b) => b.score - a.score)

  const topScoredTools = scoredTools.slice(0, limit)
  const results = topScoredTools.map((st) => formatToolResult(st.toolId, st.tool, st.warning))
  const scoredResults = topScoredTools.map((st) => ({
    tool: st.toolId,
    score: st.score,
    description: st.tool.description,
  }))

  return { results, warnings: [...new Set(warnings)], scoredResults }
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
  lines.push(`**Registry Hash:** ${result.registry_hash.slice(0, 16)}...`)
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
    explain: z.boolean().optional().default(false).describe("Include detailed score breakdown for debugging ranking decisions"),
  }),
  async execute(params, ctx) {
    const { query, phase, capability, limit = 5, explain = false } = params

    log.info("searching tool registry", { query, phase, capability, limit, explain })

    // Get registry with hash-based freshness
    const { registry, hash, cacheStatus } = await getRegistry()

    // Search tools via LanceDB hybrid search
    const { results, warnings, scoredResults } = await searchToolsLance(registry, query, phase, capability, limit)

    // Update tool context for experience tracking
    try {
      const searchResultsForContext: SearchResult[] = scoredResults.map((sr) => ({
        tool: sr.tool,
        score: sr.score,
        description: sr.description,
      }))
      updateSearchContext(ctx.sessionID, query, searchResultsForContext)
    } catch (error) {
      log.warn("failed to update search context", { error: String(error) })
    }

    // Build result
    const searchResult: ToolSearchResult = {
      query,
      phase,
      capability,
      results,
      anti_pattern_warnings: warnings,
      registry_hash: hash,
      cache_status: cacheStatus,
    }

    // Format base output
    let output = formatOutput(searchResult)

    // Phase 5: Unified Search with experiences and insights
    try {
      const toolContext = getToolContext(ctx.sessionID)
      const scoredToolsForUnified: ScoredTool[] = scoredResults.map((sr) => {
        const fullResult = results.find((r) => r.tool === sr.tool)
        return {
          id: sr.tool,
          name: fullResult?.name ?? sr.tool,
          score: sr.score,
          description: sr.description,
          phases: fullResult?.phases,
          capabilities: fullResult?.capabilities,
          routing: fullResult?.routing
            ? {
                use_for: fullResult.routing.use_for,
                triggers: fullResult.routing.triggers,
                never_use_for: fullResult.routing.never_use_for,
              }
            : undefined,
        }
      })

      const searchContext: SearchContext = {
        phase: toolContext?.currentPhase ?? phase,
        toolsTried: toolContext?.toolsTried,
        recentSuccesses: toolContext?.recentSuccesses,
      }

      const unifiedResult = await unifiedSearch(query, scoredToolsForUnified, searchContext, explain)

      const memoryOutput = formatUnifiedResults(unifiedResult)
      if (memoryOutput.trim()) {
        output += "\n" + memoryOutput
      }
    } catch (error) {
      log.warn("unified search failed, returning tool-only results", { error: String(error) })
    }

    return {
      output,
      title: `Tool search: ${query} (${results.length} results)`,
      metadata: {
        query,
        phase,
        capability,
        results_count: results.length,
        registry_hash: hash,
        cache_status: cacheStatus,
        warnings: warnings.length > 0 ? warnings : undefined,
      },
    }
  },
})
