/**
 * Unified Search
 *
 * Implements Doc 22 §Part 4 (lines 822-1082)
 *
 * Provides unified search across:
 * - Tools (from YAML registry, keyword + routing bonuses)
 * - Experiences (from LanceDB, vector similarity)
 * - Insights (from LanceDB, vector similarity weighted by confidence)
 *
 * Results are combined using Reciprocal Rank Fusion (RRF) which works
 * across different scoring systems by using ranked positions.
 */

import { Log } from "../util/log"
import { getExperiencesTable, getInsightsTable, initializeMemorySystem } from "./database"
import { getEmbeddingService } from "./embedding"
import type { Experience, Insight } from "./schema"
import type { ToolContext } from "./context"

const log = Log.create({ service: "memory.search" })

// =============================================================================
// Types
// =============================================================================

/** Base interface for scored items */
interface ScoredItem {
  id: string
  score: number
  [key: string]: unknown
}

/** Scored tool result (from YAML registry search) */
export interface ScoredTool extends ScoredItem {
  name: string
  description: string
  phases?: string[]
  capabilities?: string[]
  routing?: {
    use_for?: string[]
    triggers?: string[]
    never_use_for?: unknown[]
  }
}

/** Scored experience result (from LanceDB) */
export interface ScoredExperience extends ScoredItem {
  action: {
    query: string
    tool_selected: string
    tool_input: string
  }
  outcome: {
    success: boolean
    result_summary: string
    failure_reason?: string
    recovery?: {
      tool: string
      method: string
      worked: boolean
    }
  }
  context: {
    phase: string
    target_characteristics?: string[]
  }
}

/** Scored insight result (from LanceDB) */
export interface ScoredInsight extends ScoredItem {
  rule: string
  confidence: number
  suggestion: {
    prefer: string
    over?: string
    when: string
  }
  created_from: string[]
}

/** Type of result item */
export type ResultType = "tool" | "experience" | "insight"

/** Ranked item after RRF fusion */
export interface RankedItem {
  /** Prefixed ID: "tool:nmap", "exp:exp_123", "ins:ins_456" */
  id: string
  /** RRF score (higher is better) */
  score: number
  /** Type of result */
  type: ResultType
  /** Original data */
  data: ScoredTool | ScoredExperience | ScoredInsight
}

/** Context for search (from ToolContext) */
export interface SearchContext {
  /** Current pentest phase */
  phase?: string
  /** Tools already tried this session */
  toolsTried?: string[]
  /** Tools that succeeded recently */
  recentSuccesses?: string[]
}

/** Result of unified search */
export interface UnifiedSearchResult {
  /** Query that was searched */
  query: string
  /** Combined and ranked results */
  results: RankedItem[]
  /** Tool results (for backwards compatibility) */
  tools: ScoredTool[]
  /** Experience results */
  experiences: ScoredExperience[]
  /** Insight results */
  insights: ScoredInsight[]
  /** Whether embedding was available */
  embeddingAvailable: boolean
  /** Optional explanation (when explain=true) */
  explanation?: string
}

// =============================================================================
// Experience Search
// =============================================================================

/**
 * Search experiences using LanceDB vector similarity
 *
 * Implements Doc 22 §Part 4 (lines 915-937)
 *
 * @param query - Search query text
 * @param queryEmbedding - Pre-computed query embedding (null if unavailable)
 * @param limit - Maximum results to return
 */
export async function searchExperiencesLance(
  query: string,
  queryEmbedding: number[] | null,
  limit: number = 10
): Promise<ScoredExperience[]> {
  if (!queryEmbedding) {
    // No embedding available - skip experience search
    log.debug("skipping experience search - no embedding")
    return []
  }

  try {
    // Ensure database is initialized
    await initializeMemorySystem()

    const table = await getExperiencesTable()
    const results = await table
      .search(queryEmbedding)
      .limit(limit)
      .toArray()

    // Convert to ScoredExperience format
    return results.map((exp) => {
      const experience = exp as unknown as Experience & { _distance?: number }
      // LanceDB returns _distance (lower is better), convert to score (higher is better)
      // Using 1 / (1 + distance) to convert distance to similarity score
      const score = 1 / (1 + (experience._distance ?? 1))

      return {
        id: experience.id,
        score,
        action: experience.action,
        outcome: experience.outcome,
        context: experience.context,
      } as ScoredExperience
    })
  } catch (error) {
    log.warn("experience search failed", { error: String(error) })
    return []
  }
}

// =============================================================================
// Insight Search
// =============================================================================

/**
 * Search insights using LanceDB vector similarity
 *
 * Implements Doc 22 §Part 4 (lines 939-961)
 *
 * Results are weighted by confidence score.
 *
 * @param query - Search query text
 * @param queryEmbedding - Pre-computed query embedding (null if unavailable)
 * @param minConfidence - Minimum confidence threshold (default: 0.3)
 * @param limit - Maximum results to return
 */
export async function searchInsightsLance(
  query: string,
  queryEmbedding: number[] | null,
  minConfidence: number = 0.3,
  limit: number = 5
): Promise<ScoredInsight[]> {
  if (!queryEmbedding) {
    // No embedding available - skip insight search
    log.debug("skipping insight search - no embedding")
    return []
  }

  try {
    // Ensure database is initialized
    await initializeMemorySystem()

    const table = await getInsightsTable()

    // Search with confidence filter
    const results = await table
      .search(queryEmbedding)
      .where(`confidence > ${minConfidence}`)
      .limit(limit)
      .toArray()

    // Convert to ScoredInsight format with confidence weighting
    return results.map((ins) => {
      const insight = ins as unknown as Insight & { _distance?: number }
      // Convert distance to similarity and weight by confidence
      const baseSimilarity = 1 / (1 + (insight._distance ?? 1))
      const score = baseSimilarity * insight.confidence

      return {
        id: insight.id,
        score,
        rule: insight.rule,
        confidence: insight.confidence,
        suggestion: insight.suggestion,
        created_from: insight.created_from,
      } as ScoredInsight
    })
  } catch (error) {
    log.warn("insight search failed", { error: String(error) })
    return []
  }
}

// =============================================================================
// Reciprocal Rank Fusion
// =============================================================================

/** Input for RRF fusion */
interface RRFInput {
  results: ScoredItem[]
  weight: number
  type: ResultType
}

/**
 * Reciprocal Rank Fusion - combines ranked lists from different sources
 *
 * Implements Doc 22 §Part 4 (lines 1003-1030)
 *
 * RRF works across different scoring systems because it operates on
 * ranked positions, not raw scores. This makes it ideal for combining
 * results from different sources (tools, experiences, insights).
 *
 * IDs are prefixed by type: "tool:nmap", "exp:exp_123", "ins:ins_456"
 *
 * @param resultSets - Array of result sets with weights and types
 * @param k - RRF constant (default: 60, standard value)
 */
export function reciprocalRankFusion(
  resultSets: RRFInput[],
  k: number = 60
): RankedItem[] {
  const scores = new Map<string, RankedItem>()

  for (const { results, weight, type } of resultSets) {
    for (let rank = 0; rank < results.length; rank++) {
      const item = results[rank]
      const prefixedId = `${type}:${item.id}`

      // RRF formula: weight * 1 / (k + rank + 1)
      const rrf = weight * (1 / (k + rank + 1))

      const existing = scores.get(prefixedId)
      if (existing) {
        existing.score += rrf
      } else {
        scores.set(prefixedId, {
          id: prefixedId,
          score: rrf,
          type,
          data: item as ScoredTool | ScoredExperience | ScoredInsight,
        })
      }
    }
  }

  // Sort by RRF score descending
  return Array.from(scores.values()).sort((a, b) => b.score - a.score)
}

// =============================================================================
// Explanation Formatting
// =============================================================================

/**
 * Format detailed score explanation for --explain flag
 *
 * Implements Doc 22 §Part 4 (lines 1036-1082)
 *
 * Shows why each tool received its ranking, including:
 * - Base similarity score
 * - Routing bonuses (triggers, use_for)
 * - Routing penalties (never_use_for)
 * - Context bonuses (phase match, recent success)
 * - Context penalties (already tried)
 */
export function formatExplanation(
  query: string,
  toolResults: ScoredTool[],
  context: SearchContext,
  experienceResults: ScoredExperience[],
  insightResults: ScoredInsight[]
): string {
  const lines: string[] = [`\n## Score Breakdown for: "${query}"\n`]

  // Tool explanations
  if (toolResults.length > 0) {
    lines.push("### Tool Scores\n")
    for (const tool of toolResults.slice(0, 5)) {
      const parts: string[] = []

      // Base score
      parts.push(`- Base keyword score: ${tool.score.toFixed(2)}`)

      // Phase bonus
      if (context.phase && tool.phases?.includes(context.phase)) {
        parts.push(`- Phase match (${context.phase}): included in base`)
      }

      // Already tried penalty
      if (context.toolsTried?.includes(tool.id)) {
        parts.push(`- Note: Already tried this session`)
      }

      // Recency bonus
      if (context.recentSuccesses?.includes(tool.id)) {
        parts.push(`- Recent success this session: boost applied`)
      }

      lines.push(`**${tool.name}** (score: ${tool.score.toFixed(2)})`)
      lines.push(parts.join("\n"))
      lines.push("")
    }
  }

  // Experience explanations
  if (experienceResults.length > 0) {
    lines.push("### Relevant Experiences\n")
    for (const exp of experienceResults.slice(0, 3)) {
      const status = exp.outcome.success ? "succeeded" : "failed"
      const recovery = exp.outcome.recovery
        ? ` → recovered with ${exp.outcome.recovery.tool}`
        : ""
      lines.push(
        `- **${exp.action.tool_selected}** ${status}${recovery} (similarity: ${exp.score.toFixed(3)})`
      )
      lines.push(`  Query: "${exp.action.query.slice(0, 50)}..."`)
    }
    lines.push("")
  }

  // Insight explanations
  if (insightResults.length > 0) {
    lines.push("### Applicable Insights\n")
    for (const ins of insightResults.slice(0, 3)) {
      lines.push(
        `- **${ins.suggestion.prefer}** over ${ins.suggestion.over || "alternatives"}`
      )
      lines.push(`  When: ${ins.suggestion.when}`)
      lines.push(
        `  Confidence: ${(ins.confidence * 100).toFixed(0)}% (from ${ins.created_from.length} experiences)`
      )
    }
    lines.push("")
  }

  return lines.join("\n")
}

// =============================================================================
// Unified Result Formatting
// =============================================================================

/**
 * Format experience for display in search results
 */
export function formatExperienceForDisplay(exp: ScoredExperience): string {
  const status = exp.outcome.success ? "✓" : "✗"
  const recovery = exp.outcome.recovery
    ? ` → Recovered with ${exp.outcome.recovery.tool}`
    : ""

  let result = `${status} Used **${exp.action.tool_selected}**`

  if (exp.outcome.success) {
    result += `: ${exp.outcome.result_summary.slice(0, 100)}`
  } else {
    result += ` (${exp.outcome.failure_reason || "failed"})${recovery}`
  }

  return result
}

/**
 * Format insight for display in search results
 */
export function formatInsightForDisplay(ins: ScoredInsight): string {
  const confidence = (ins.confidence * 100).toFixed(0)
  let result = `💡 **Insight** (${confidence}% confidence): ${ins.rule}`

  if (ins.suggestion.prefer) {
    result += `\n   → Prefer **${ins.suggestion.prefer}**`
    if (ins.suggestion.over) {
      result += ` over ${ins.suggestion.over}`
    }
    if (ins.suggestion.when) {
      result += ` when ${ins.suggestion.when}`
    }
  }

  return result
}

// =============================================================================
// Main Unified Search
// =============================================================================

/**
 * Unified search across tools, experiences, and insights
 *
 * Implements Doc 22 §Part 4 (lines 831-864)
 *
 * This function:
 * 1. Embeds the query (if embedding service available)
 * 2. Searches all sources in parallel
 * 3. Combines results using Reciprocal Rank Fusion
 * 4. Formats output with optional explanation
 *
 * @param query - Search query
 * @param toolResults - Pre-computed tool results (from YAML registry search)
 * @param context - Search context (phase, tools tried, etc.)
 * @param explain - Whether to include detailed explanation
 */
export async function unifiedSearch(
  query: string,
  toolResults: ScoredTool[],
  context: SearchContext,
  explain: boolean = false
): Promise<UnifiedSearchResult> {
  log.info("unified search", { query, explain, toolCount: toolResults.length })

  // 1. Get query embedding (if available)
  const embeddingService = getEmbeddingService()
  const embedding = await embeddingService.embed(query)
  const queryEmbedding = embedding?.dense ?? null

  // 2. Search experiences and insights in parallel
  const [experienceResults, insightResults] = await Promise.all([
    searchExperiencesLance(query, queryEmbedding),
    searchInsightsLance(query, queryEmbedding),
  ])

  log.debug("search results", {
    tools: toolResults.length,
    experiences: experienceResults.length,
    insights: insightResults.length,
    embeddingAvailable: queryEmbedding !== null,
  })

  // 3. Combine with Reciprocal Rank Fusion
  // Weights from Doc 22: tools=1.0, experiences=0.8, insights=1.2
  const combined = reciprocalRankFusion([
    { results: toolResults, weight: 1.0, type: "tool" },
    { results: experienceResults, weight: 0.8, type: "experience" },
    { results: insightResults, weight: 1.2, type: "insight" },
  ])

  // 4. Build result
  const result: UnifiedSearchResult = {
    query,
    results: combined,
    tools: toolResults,
    experiences: experienceResults,
    insights: insightResults,
    embeddingAvailable: queryEmbedding !== null,
  }

  // 5. Add explanation if requested
  if (explain) {
    result.explanation = formatExplanation(
      query,
      toolResults,
      context,
      experienceResults,
      insightResults
    )
  }

  return result
}

/**
 * Format unified search results for display
 *
 * Creates a markdown-formatted output that includes:
 * - Tool recommendations
 * - Relevant past experiences
 * - Applicable insights
 */
export function formatUnifiedResults(result: UnifiedSearchResult): string {
  const lines: string[] = []

  // Add experience section if we have relevant experiences
  if (result.experiences.length > 0) {
    lines.push("\n### Relevant Experience (from past engagements)\n")
    for (const exp of result.experiences.slice(0, 2)) {
      lines.push(`> ${formatExperienceForDisplay(exp)}`)
    }
    lines.push("")
  }

  // Add insight section if we have applicable insights
  if (result.insights.length > 0) {
    lines.push("### Insights\n")
    for (const ins of result.insights.slice(0, 2)) {
      lines.push(formatInsightForDisplay(ins))
      lines.push("")
    }
  }

  // Add explanation if present
  if (result.explanation) {
    lines.push(result.explanation)
  }

  // Note if embedding wasn't available
  if (!result.embeddingAvailable && (result.experiences.length === 0 && result.insights.length === 0)) {
    lines.push("\n*Note: Semantic search unavailable. Results based on keyword matching only.*\n")
  }

  return lines.join("\n")
}
