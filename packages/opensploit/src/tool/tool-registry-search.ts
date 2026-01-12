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

// =============================================================================
// Schema Definitions
// =============================================================================

// Tool routing rules - defines when to use/not use a tool
// never_use_for can be either simple strings or detailed objects
const NeverUseForItemSchema = z.union([
  z.string(),
  z.object({
    task: z.string(),
    use_instead: z.union([z.string(), z.array(z.string())]),
    reason: z.string(),
  }),
])

const RoutingRuleSchema = z.object({
  use_for: z.array(z.string()).optional().default([]),
  never_use_for: z.array(NeverUseForItemSchema).optional().default([]),
  triggers: z.array(z.string()).optional().default([]),
  prefer_over: z.array(z.string()).optional().default([]),
})

// Phase gating - which tools are appropriate for each phase
const PhaseGatingSchema = z.object({
  required: z.array(z.string()).optional().default([]),
  recommended: z.array(z.string()).optional().default([]),
  optional: z.array(z.string()).optional().default([]),
  discouraged: z
    .array(
      z.object({
        tool: z.string(),
        reason: z.string(),
      }),
    )
    .optional()
    .default([]),
  unlocks_after: z.array(z.string()).optional().default([]),
})

// Skill definition - composite workflow tools
const SkillStepSchema = z.object({
  tool: z.string(),
  purpose: z.string(),
  depends_on: z.string().optional(),
  condition: z.string().optional(),
  uses_session: z.boolean().optional(),
  auto_config: z.array(z.string()).optional(),
})

const SkillSchema = z.object({
  description: z.string(),
  use_for: z.string(),
  params: z.record(z.string(), z.any()).optional(),
  orchestrates: z.array(SkillStepSchema),
})

// Method schema
const RawMethodSchema = z.object({
  description: z.string(),
  when_to_use: z.string().optional(),
  next_step: z.string().optional(), // Workflow guidance for what to do after this method
  params: z.record(z.string(), z.any()).optional(),
  returns: z.record(z.string(), z.any()).optional(),
})

// Tool entry schema with full routing support
const RawToolEntry = z.object({
  name: z.string(),
  version: z.string().optional(),
  description: z.string(),
  image: z.string().optional(),
  image_size_mb: z.number().optional(),

  // Selection hierarchy: 1 = Skill, 2 = Specialized, 3 = General-purpose
  selection_level: z.number().min(1).max(3).optional().default(2),

  capabilities: z.array(z.string()).optional().default([]),
  phases: z.array(z.string()).optional().default([]),

  // Routing rules for intelligent tool selection
  routing: RoutingRuleSchema.optional(),

  methods: z.record(z.string(), RawMethodSchema).optional(),
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
})

// Full registry schema
const RawRegistry = z.object({
  version: z.string(),
  updated_at: z.string().optional(),
  phases: z.record(z.string(), PhaseGatingSchema).optional(),
  skills: z.record(z.string(), SkillSchema).optional(),
  tools: z.record(z.string(), RawToolEntry),
})

// =============================================================================
// Type Definitions
// =============================================================================

interface ToolMethod {
  name: string
  description: string
  when_to_use?: string
  next_step?: string
  params?: Record<string, any>
  returns?: Record<string, any>
}

// NeverUseFor can be a simple string or a detailed object
type NeverUseForItem =
  | string
  | {
      task: string
      use_instead: string | string[]
      reason: string
    }

interface ToolRouting {
  use_for: string[]
  never_use_for: NeverUseForItem[]
  triggers: string[]
  prefer_over: string[]
}

interface ToolEntry {
  name: string
  version?: string
  description: string
  image?: string
  selection_level: number // 1 = Skill, 2 = Specialized, 3 = General-purpose
  capabilities: string[]
  phases: string[]
  routing?: ToolRouting
  methods: ToolMethod[]
  requirements?: {
    network?: boolean
    privileged?: boolean
    privileged_reason?: string
  }
  resources?: {
    memory_mb?: number
    cpu?: number
  }
}

interface DiscouragedTool {
  tool: string
  reason: string
}

interface PhaseGating {
  required: string[]
  recommended: string[]
  optional: string[]
  discouraged: DiscouragedTool[]
  unlocks_after: string[]
}

interface SkillStep {
  tool: string
  purpose: string
  depends_on?: string
  condition?: string
  uses_session?: boolean
  auto_config?: string[]
}

interface Skill {
  name: string
  description: string
  use_for: string
  params?: Record<string, any>
  orchestrates: SkillStep[]
}

interface Registry {
  version: string
  updated_at?: string
  phases: Record<string, PhaseGating>
  skills: Record<string, Skill>
  tools: Record<string, ToolEntry>
}

// Search result with scoring details
interface ScoredResult {
  tool?: ToolEntry
  skill?: Skill
  type: "tool" | "skill"
  finalScore: number
  semanticScore: number
  selectionLevelScore: number
  phaseMatchScore: number
  warnings: string[]
  phaseStatus?: "required" | "recommended" | "optional" | "discouraged"
}

// =============================================================================
// Registry Transformation
// =============================================================================

function transformRegistry(raw: z.infer<typeof RawRegistry>): Registry {
  const tools: Record<string, ToolEntry> = {}
  const skills: Record<string, Skill> = {}
  const phases: Record<string, PhaseGating> = {}

  // Transform phases
  if (raw.phases) {
    for (const [phaseName, phaseData] of Object.entries(raw.phases)) {
      phases[phaseName] = {
        required: phaseData.required,
        recommended: phaseData.recommended,
        optional: phaseData.optional,
        discouraged: phaseData.discouraged,
        unlocks_after: phaseData.unlocks_after,
      }
    }
  }

  // Transform skills
  if (raw.skills) {
    for (const [skillName, skillData] of Object.entries(raw.skills)) {
      skills[skillName] = {
        name: skillName,
        description: skillData.description,
        use_for: skillData.use_for,
        params: skillData.params,
        orchestrates: skillData.orchestrates.map((step) => ({
          tool: step.tool,
          purpose: step.purpose,
          depends_on: step.depends_on,
          condition: step.condition,
          uses_session: step.uses_session,
          auto_config: step.auto_config,
        })),
      }
    }
  }

  // Transform tools
  for (const [key, rawTool] of Object.entries(raw.tools)) {
    const methods: ToolMethod[] = []

    if (rawTool.methods) {
      for (const [methodName, methodDef] of Object.entries(rawTool.methods)) {
        methods.push({
          name: methodName,
          description: methodDef.description,
          when_to_use: methodDef.when_to_use,
          next_step: methodDef.next_step,
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
      selection_level: rawTool.selection_level,
      capabilities: rawTool.capabilities,
      phases: rawTool.phases,
      routing: rawTool.routing
        ? {
            use_for: rawTool.routing.use_for,
            never_use_for: rawTool.routing.never_use_for,
            triggers: rawTool.routing.triggers,
            prefer_over: rawTool.routing.prefer_over,
          }
        : undefined,
      methods,
      requirements: rawTool.requirements,
      resources: rawTool.resources,
    }
  }

  return {
    version: raw.version,
    updated_at: raw.updated_at,
    phases,
    skills,
    tools,
  }
}

// =============================================================================
// Registry Caching
// =============================================================================

let cachedRegistry: Registry | null = null
let cacheTimestamp = 0

async function ensureRegistryDir(): Promise<void> {
  try {
    await fs.mkdir(REGISTRY_DIR, { recursive: true })
  } catch {
    // Directory may already exist
  }
}

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

    await ensureRegistryDir()
    await fs.writeFile(REGISTRY_PATH, text, "utf-8")
    log.info("registry cached to disk", { path: REGISTRY_PATH })

    return transformRegistry(validated)
  } catch (error) {
    log.warn("error fetching registry", { error: String(error) })
    return null
  }
}

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

async function getRegistry(): Promise<Registry> {
  const now = Date.now()

  if (cachedRegistry && now - cacheTimestamp < CACHE_MAX_AGE_MS) {
    return cachedRegistry
  }

  const fresh = await fetchRegistry()
  if (fresh) {
    cachedRegistry = fresh
    cacheTimestamp = now
    return fresh
  }

  const cached = await loadCachedRegistry()
  if (cached) {
    cachedRegistry = cached
    cacheTimestamp = now
    return cached
  }

  log.warn("no registry available, returning empty")
  return {
    version: "0.0.0",
    phases: {},
    skills: {},
    tools: {},
  }
}

// =============================================================================
// RAG Scoring Implementation
// =============================================================================

/**
 * Calculate semantic similarity score (0-1)
 * Uses keyword matching as a proxy for semantic similarity
 */
function calculateSemanticScore(
  text: string,
  query: string,
  useFor: string[],
  triggers: string[],
): number {
  const queryLower = query.toLowerCase()
  const words = queryLower.split(/\s+/).filter((w) => w.length > 2)
  const textLower = text.toLowerCase()

  let matches = 0
  let totalChecks = words.length

  // Check word matches in text
  for (const word of words) {
    if (textLower.includes(word)) {
      matches++
    }
  }

  // Check use_for conditions
  for (const condition of useFor) {
    totalChecks++
    const condLower = condition.toLowerCase()
    if (condLower.includes(queryLower) || queryLower.includes(condLower)) {
      matches += 2 // Higher weight for use_for matches
    } else {
      for (const word of words) {
        if (condLower.includes(word)) {
          matches++
          break
        }
      }
    }
  }

  // Check triggers
  for (const trigger of triggers) {
    totalChecks++
    const trigLower = trigger.toLowerCase()
    for (const word of words) {
      if (trigLower.includes(word)) {
        matches++
        break
      }
    }
  }

  return totalChecks > 0 ? Math.min(matches / totalChecks, 1) : 0
}

/**
 * Calculate selection level score
 * Level 1 (Skills) = 1.0, Level 2 (Specialized) = 0.7, Level 3 (General) = 0.3
 */
function calculateSelectionLevelScore(level: number): number {
  switch (level) {
    case 1:
      return 1.0 // Skills - highest priority
    case 2:
      return 0.7 // Specialized tools
    case 3:
      return 0.3 // General-purpose tools
    default:
      return 0.5
  }
}

/**
 * Calculate phase match score
 * Required = 1.0, Recommended = 0.9, Optional = 0.5, Discouraged = 0.1, No match = 0.3
 */
function calculatePhaseMatchScore(
  toolName: string,
  phase: string | undefined,
  phaseGating: Record<string, PhaseGating>,
): { score: number; status?: "required" | "recommended" | "optional" | "discouraged" } {
  if (!phase || !phaseGating[phase]) {
    return { score: 0.5 } // Neutral if no phase specified
  }

  const gating = phaseGating[phase]

  if (gating.required.includes(toolName)) {
    return { score: 1.0, status: "required" }
  }
  if (gating.recommended.includes(toolName)) {
    return { score: 0.9, status: "recommended" }
  }
  if (gating.optional.includes(toolName)) {
    return { score: 0.5, status: "optional" }
  }
  if (gating.discouraged.some((d) => d.tool === toolName)) {
    return { score: 0.1, status: "discouraged" }
  }

  return { score: 0.3 } // Not explicitly listed
}

/**
 * Check for anti-patterns and generate warnings
 * Returns warnings when query matches never_use_for conditions
 */
function checkAntiPatterns(tool: ToolEntry, query: string): string[] {
  const warnings: string[] = []
  const queryLower = query.toLowerCase()
  const words = queryLower.split(/\s+/).filter((w) => w.length > 2)

  if (!tool.routing?.never_use_for) {
    return warnings
  }

  for (const item of tool.routing.never_use_for) {
    // Handle both string and object formats
    const task = typeof item === "string" ? item : item.task
    const taskLower = task.toLowerCase()
    let matches = false

    // Check if query matches the anti-pattern task
    if (taskLower.includes(queryLower) || queryLower.includes(taskLower)) {
      matches = true
    } else {
      for (const word of words) {
        if (taskLower.includes(word)) {
          matches = true
          break
        }
      }
    }

    if (matches) {
      if (typeof item === "string") {
        // Simple string format - just warn about the task
        warnings.push(`WARNING: ${tool.name} is NOT recommended for "${task}".`)
      } else {
        // Detailed object format - include alternatives and reason
        const alternatives = Array.isArray(item.use_instead) ? item.use_instead.join(", ") : item.use_instead
        warnings.push(`WARNING: ${tool.name} is NOT recommended for "${task}". Use ${alternatives} instead. Reason: ${item.reason}`)
      }
    }
  }

  return warnings
}

/**
 * Calculate final RAG score using weighted formula:
 * final_score = (semantic_similarity × 0.4) + (selection_level_score × 0.4) + (phase_match × 0.2)
 */
function calculateFinalScore(
  tool: ToolEntry,
  query: string,
  phase: string | undefined,
  registry: Registry,
): ScoredResult {
  // Build searchable text from tool
  const searchText = [
    tool.name,
    tool.description,
    ...tool.capabilities,
    ...tool.methods.map((m) => `${m.description} ${m.when_to_use || ""}`),
  ].join(" ")

  const semanticScore = calculateSemanticScore(
    searchText,
    query,
    tool.routing?.use_for || [],
    tool.routing?.triggers || [],
  )

  const selectionLevelScore = calculateSelectionLevelScore(tool.selection_level)

  const { score: phaseMatchScore, status: phaseStatus } = calculatePhaseMatchScore(
    tool.name,
    phase,
    registry.phases,
  )

  // Weighted formula from requirements
  const finalScore = semanticScore * 0.4 + selectionLevelScore * 0.4 + phaseMatchScore * 0.2

  // Check for anti-patterns
  const warnings = checkAntiPatterns(tool, query)

  return {
    tool,
    type: "tool",
    finalScore,
    semanticScore,
    selectionLevelScore,
    phaseMatchScore,
    warnings,
    phaseStatus,
  }
}

/**
 * Score a skill (composite workflow)
 * Skills are always Level 1 (highest priority)
 */
function scoreSkill(skill: Skill, query: string): ScoredResult {
  const searchText = [skill.description, skill.use_for, ...skill.orchestrates.map((s) => s.purpose)].join(" ")

  const semanticScore = calculateSemanticScore(searchText, query, [skill.use_for], [])

  // Skills are always Level 1
  const selectionLevelScore = 1.0

  // Skills don't have phase gating (they span phases)
  const phaseMatchScore = 0.7

  const finalScore = semanticScore * 0.4 + selectionLevelScore * 0.4 + phaseMatchScore * 0.2

  return {
    skill,
    type: "skill",
    finalScore,
    semanticScore,
    selectionLevelScore,
    phaseMatchScore,
    warnings: [],
  }
}

// =============================================================================
// Output Formatting
// =============================================================================

function formatToolOutput(result: ScoredResult): string {
  if (result.type === "skill" && result.skill) {
    return formatSkillOutput(result)
  }

  const tool = result.tool!
  let output = `## ${tool.name} (v${tool.version || "latest"})\n\n`

  // Add selection level indicator
  const levelLabels = { 1: "SKILL", 2: "SPECIALIZED", 3: "GENERAL-PURPOSE" }
  const levelLabel = levelLabels[tool.selection_level as 1 | 2 | 3] || "UNKNOWN"
  output += `**Selection Level:** ${levelLabel} (Level ${tool.selection_level})\n`

  // Add phase status if available
  if (result.phaseStatus) {
    const statusEmoji = {
      required: "✅ REQUIRED",
      recommended: "👍 RECOMMENDED",
      optional: "➖ OPTIONAL",
      discouraged: "⚠️ DISCOURAGED",
    }
    output += `**Phase Status:** ${statusEmoji[result.phaseStatus]}\n`
  }

  output += `**Description:** ${tool.description}\n`
  output += `**Phases:** ${tool.phases.join(", ") || "any"}\n`
  output += `**Capabilities:** ${tool.capabilities.join(", ") || "general"}\n`

  // Add routing guidance
  if (tool.routing?.use_for && tool.routing.use_for.length > 0) {
    output += `\n**Best Used For:**\n`
    for (const use of tool.routing.use_for) {
      output += `- ${use}\n`
    }
  }

  // Add warnings
  if (result.warnings.length > 0) {
    output += `\n**⚠️ WARNINGS:**\n`
    for (const warning of result.warnings) {
      output += `- ${warning}\n`
    }
  }

  if (tool.image) {
    output += `\n**Image:** ${tool.image}\n`
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

function formatSkillOutput(result: ScoredResult): string {
  const skill = result.skill!
  let output = `## 🔧 SKILL: ${skill.name}\n\n`
  output += `**Selection Level:** SKILL (Level 1) - HIGHEST PRIORITY\n`
  output += `**Description:** ${skill.description}\n`
  output += `**Use For:** ${skill.use_for}\n\n`

  output += `### Orchestrated Tools\n\n`
  output += `This skill automatically orchestrates the following tools in sequence:\n\n`

  for (let i = 0; i < skill.orchestrates.length; i++) {
    const step = skill.orchestrates[i]
    output += `${i + 1}. **${step.tool}** - ${step.purpose}\n`
    if (step.depends_on) {
      output += `   - *Depends on:* ${step.depends_on}\n`
    }
    if (step.condition) {
      output += `   - *Condition:* ${step.condition}\n`
    }
  }

  if (skill.params) {
    output += `\n### Parameters\n\n`
    for (const [paramName, paramInfo] of Object.entries(skill.params)) {
      const info = paramInfo as Record<string, any>
      const required = info.required ? " (required)" : ""
      output += `- \`${paramName}\`${required}: ${info.description || info.type}\n`
    }
  }

  output += `\n> **Recommendation:** Use this skill instead of invoking individual tools for ${skill.use_for.toLowerCase()}.\n`

  return output
}

function formatAntiPatternWarnings(warnings: string[], query: string): string {
  if (warnings.length === 0) return ""

  let output = `\n## ⚠️ Anti-Pattern Warnings\n\n`
  output += `The following warnings were detected for your query "${query}":\n\n`

  for (const warning of warnings) {
    output += `- ${warning}\n`
  }

  output += `\n> These warnings indicate that some tools in the results may not be appropriate for your task. Consider using the suggested alternatives.\n`

  return output
}

// =============================================================================
// Tool Definition
// =============================================================================

export const ToolRegistrySearchTool = Tool.define("tool_registry_search", {
  description: DESCRIPTION,
  parameters: z.object({
    query: z.string().describe("Natural language query to search for tools (e.g., 'port scanning', 'SQL injection')"),
    phase: z
      .enum(["reconnaissance", "enumeration", "exploitation", "post-exploitation"])
      .optional()
      .describe("Filter by pentest phase - affects ranking and shows phase-appropriate tools"),
    capability: z.string().optional().describe("Filter by specific capability (e.g., 'port_scanning', 'sql_injection')"),
    limit: z.number().optional().default(5).describe("Maximum number of results to return"),
    list_all: z.boolean().optional().default(false).describe("List ALL available tools (ignores query, returns comprehensive list)"),
  }),
  async execute(params, _ctx) {
    const { query, phase, capability, limit = 5, list_all = false } = params

    // Handle list_all mode - returns all tools grouped by category
    if (list_all) {
      log.info("listing all tools")
      const registry = await getRegistry()

      let output = `# All Available MCP Tools\n\n`
      output += `**Registry Version:** ${registry.version}\n`
      output += `**Total Tools:** ${Object.keys(registry.tools).length}\n`
      output += `**Total Skills:** ${Object.keys(registry.skills).length}\n\n`

      // Group tools by phase
      const toolsByPhase: Record<string, ToolEntry[]> = {
        reconnaissance: [],
        enumeration: [],
        exploitation: [],
        "post-exploitation": [],
        multi: [],
      }

      for (const tool of Object.values(registry.tools)) {
        if (tool.phases.length === 0 || tool.phases.length > 2) {
          toolsByPhase["multi"].push(tool)
        } else {
          for (const p of tool.phases) {
            if (toolsByPhase[p]) {
              toolsByPhase[p].push(tool)
            }
          }
        }
      }

      // Output skills first
      if (Object.keys(registry.skills).length > 0) {
        output += `## Skills (Level 1 - Highest Priority)\n\n`
        for (const [name, skill] of Object.entries(registry.skills)) {
          output += `- **${name}**: ${skill.description}\n`
        }
        output += `\n`
      }

      // Output tools by phase
      for (const [phaseName, tools] of Object.entries(toolsByPhase)) {
        if (tools.length === 0) continue
        output += `## ${phaseName.charAt(0).toUpperCase() + phaseName.slice(1)} Tools\n\n`
        for (const tool of tools) {
          const levelLabels: Record<number, string> = { 1: "SKILL", 2: "SPECIALIZED", 3: "GENERAL" }
          output += `- **${tool.name}** [${levelLabels[tool.selection_level] || "L" + tool.selection_level}]: ${tool.description}\n`
        }
        output += `\n`
      }

      output += `---\n\n`
      output += `*Use \`tool_registry_search\` with a specific query to get detailed information about a tool.*\n`

      return {
        output,
        title: `All tools (${Object.keys(registry.tools).length} tools, ${Object.keys(registry.skills).length} skills)`,
        metadata: {
          results: Object.keys(registry.tools).length + Object.keys(registry.skills).length,
          registry_version: registry.version,
        },
      }
    }

    log.info("searching tool registry", { query, phase, capability })

    const registry = await getRegistry()

    // Score all tools and skills
    const scoredResults: ScoredResult[] = []

    // Score skills first (Level 1 priority)
    for (const [, skill] of Object.entries(registry.skills)) {
      const result = scoreSkill(skill, query)
      if (result.semanticScore > 0.1) {
        scoredResults.push(result)
      }
    }

    // Score tools
    for (const [, tool] of Object.entries(registry.tools)) {
      // Apply capability filter if specified
      if (capability) {
        const capLower = capability.toLowerCase()
        if (!tool.capabilities.some((c) => c.toLowerCase().includes(capLower))) {
          continue
        }
      }

      const result = calculateFinalScore(tool, query, phase, registry)
      if (result.semanticScore > 0.05) {
        scoredResults.push(result)
      }
    }

    // Sort by final score descending
    scoredResults.sort((a, b) => b.finalScore - a.finalScore)

    // Take top results
    const topResults = scoredResults.slice(0, limit)

    // Collect all warnings for anti-pattern summary
    const allWarnings = topResults.flatMap((r) => r.warnings)

    if (topResults.length === 0) {
      return {
        output: `No tools found matching query: "${query}"${phase ? ` in phase: ${phase}` : ""}${capability ? ` with capability: ${capability}` : ""}\n\nTry a different query or check available phases: reconnaissance, enumeration, exploitation, post-exploitation`,
        title: `Tool search: ${query}`,
        metadata: {
          results: 0,
          registry_version: registry.version,
        },
      }
    }

    // Format output
    let output = `# Tool Registry Search Results\n\n`
    output += `**Query:** ${query}\n`
    if (phase) output += `**Phase Filter:** ${phase}\n`
    if (capability) output += `**Capability Filter:** ${capability}\n`
    output += `**Results:** ${topResults.length} tools/skills found\n`
    output += `**Scoring:** semantic(40%) + selection_level(40%) + phase_match(20%)\n\n`

    // Add anti-pattern warnings at the top if any
    if (allWarnings.length > 0) {
      output += formatAntiPatternWarnings([...new Set(allWarnings)], query)
    }

    output += `---\n\n`

    for (const result of topResults) {
      output += formatToolOutput(result)
      output += `\n*Score: ${(result.finalScore * 100).toFixed(1)}% (semantic: ${(result.semanticScore * 100).toFixed(0)}%, level: ${(result.selectionLevelScore * 100).toFixed(0)}%, phase: ${(result.phaseMatchScore * 100).toFixed(0)}%)*\n\n`
      output += "---\n\n"
    }

    output += `\n## Tool Selection Hierarchy\n\n`
    output += `1. **Skills (Level 1)** - Use these first if available. They orchestrate multiple tools automatically.\n`
    output += `2. **Specialized (Level 2)** - Use for specific tasks (e.g., sqlmap for SQLi, hydra for brute force).\n`
    output += `3. **General-purpose (Level 3)** - Only use when specialized tools don't apply. Justify your choice.\n\n`
    output += `*To use a tool, invoke it via \`mcp_tool\` with the appropriate method and parameters.*`

    return {
      output,
      title: `Tool search: ${query} (${topResults.length} results)`,
      metadata: {
        results: topResults.length,
        registry_version: registry.version,
      },
    }
  },
})
