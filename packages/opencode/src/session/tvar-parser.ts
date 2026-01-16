/**
 * TVAR Parser
 *
 * Extracts structured TVAR (Thought-Verify-Action-Result) data from agent text output.
 * TVAR is the reasoning framework for pentest agents.
 *
 * Requirements (Feature 09):
 * - REQ-RSN-002: Parse TVAR pattern from text
 * - REQ-RSN-034: Extract into structured TVARBlock
 */

import { Log } from "../util/log"

const log = Log.create({ service: "tvar-parser" })

/**
 * Phase enum for pentest workflow
 */
export type Phase = "reconnaissance" | "enumeration" | "exploitation" | "post_exploitation" | "reporting"

/**
 * Parsed TVAR block with position information for stripping
 */
export interface TVARBlock {
  thought: string
  verify: string
  action?: string
  result?: string
  raw: string // Original text for stripping
  startIndex: number
  endIndex: number
}

/**
 * Validation result for TVAR quality checks
 */
export interface ValidationResult {
  valid: boolean
  issues: string[]
}

/**
 * Parse TVAR blocks from text output.
 * Returns all complete TVAR blocks found (requires at least thought + verify).
 *
 * The parser is flexible:
 * - thought and verify are REQUIRED
 * - action and result are OPTIONAL (may come separately)
 */
export function parseTVAR(text: string): TVARBlock[] {
  const blocks: TVARBlock[] = []

  // Find all <thought> tags as starting points
  const thoughtRegex = /<thought>([\s\S]*?)<\/thought>/gi
  let match: RegExpExecArray | null

  while ((match = thoughtRegex.exec(text)) !== null) {
    const thoughtStart = match.index
    const thought = match[1].trim()

    // Look for <verify> after this thought (REQUIRED)
    const afterThought = text.slice(match.index + match[0].length)
    const verifyMatch = afterThought.match(/<verify>([\s\S]*?)<\/verify>/i)

    if (!verifyMatch) {
      // Need at least thought + verify for a valid TVAR block
      continue
    }

    const verify = verifyMatch[1].trim()
    const verifyEnd = match.index + match[0].length + verifyMatch.index! + verifyMatch[0].length

    // Look for optional <action> after verify
    const afterVerify = text.slice(verifyEnd)
    const actionMatch = afterVerify.match(/^[\s\n]*<action>([\s\S]*?)<\/action>/i)
    const action = actionMatch ? actionMatch[1].trim() : undefined
    const actionEnd = actionMatch ? verifyEnd + actionMatch.index! + actionMatch[0].length : verifyEnd

    // Look for optional <result> after action (or verify if no action)
    const afterAction = text.slice(actionEnd)
    const resultMatch = afterAction.match(/^[\s\n]*<result>([\s\S]*?)<\/result>/i)
    const result = resultMatch ? resultMatch[1].trim() : undefined

    // Calculate end index
    let endIndex = verifyEnd
    if (actionMatch) endIndex = actionEnd
    if (resultMatch) endIndex = actionEnd + resultMatch.index! + resultMatch[0].length

    const raw = text.slice(thoughtStart, endIndex)

    blocks.push({
      thought,
      verify,
      action,
      result,
      raw,
      startIndex: thoughtStart,
      endIndex,
    })

    log.info("parsed", {
      thoughtLen: thought.length,
      verifyLen: verify.length,
      hasAction: !!action,
      hasResult: !!result,
    })
  }

  return blocks
}

/**
 * Check if text contains valid TVAR reasoning.
 * Minimum requirement: thought + verify tags present.
 */
export function hasTVAR(text: string): boolean {
  return /<thought>[\s\S]*?<\/thought>/i.test(text) && /<verify>[\s\S]*?<\/verify>/i.test(text)
}

/**
 * Extract the phase from TVAR thought/verify content using keyword matching.
 * Returns undefined if phase cannot be determined.
 */
export function extractPhase(block: TVARBlock): Phase | undefined {
  const combined = `${block.thought} ${block.verify}`.toLowerCase()

  // Reconnaissance indicators
  if (
    combined.includes("reconnaissance") ||
    combined.includes("recon") ||
    combined.includes("port scan") ||
    combined.includes("discovery") ||
    combined.includes("initial scan") ||
    combined.includes("attack surface") ||
    combined.includes("identify target")
  ) {
    return "reconnaissance"
  }

  // Enumeration indicators
  if (
    combined.includes("enumeration") ||
    combined.includes("enumerate") ||
    combined.includes("directory") ||
    combined.includes("vhost") ||
    combined.includes("fuzzing") ||
    combined.includes("subdomain") ||
    combined.includes("service version") ||
    combined.includes("banner grab")
  ) {
    return "enumeration"
  }

  // Exploitation indicators
  if (
    combined.includes("exploitation") ||
    combined.includes("exploit") ||
    combined.includes("attack") ||
    combined.includes("injection") ||
    combined.includes("rce") ||
    combined.includes("shell") ||
    combined.includes("payload") ||
    combined.includes("reverse shell")
  ) {
    return "exploitation"
  }

  // Post-exploitation indicators
  if (
    combined.includes("post-exploitation") ||
    combined.includes("post_exploitation") ||
    combined.includes("privilege") ||
    combined.includes("privesc") ||
    combined.includes("lateral") ||
    combined.includes("persistence") ||
    combined.includes("root") ||
    combined.includes("escalat")
  ) {
    return "post_exploitation"
  }

  // Reporting indicators
  if (
    combined.includes("report") ||
    combined.includes("summary") ||
    combined.includes("findings") ||
    combined.includes("document") ||
    combined.includes("conclude")
  ) {
    return "reporting"
  }

  return undefined
}

/**
 * Validate that TVAR block has proper reasoning before tool use.
 * Used for quality checks and anti-pattern detection.
 */
export function validateTVARBeforeToolCall(block: TVARBlock): ValidationResult {
  const issues: string[] = []

  // Check thought has substance
  if (block.thought.length < 20) {
    issues.push("Thought is too brief - should explain objective and context")
  }

  // Check verify has tool consideration
  const verifyLower = block.verify.toLowerCase()
  if (
    !verifyLower.includes("tool") &&
    !verifyLower.includes("phase") &&
    !verifyLower.includes("anti-pattern") &&
    !verifyLower.includes("appropriate") &&
    !verifyLower.includes("should") &&
    !verifyLower.includes("using")
  ) {
    issues.push("Verify should check tool selection, phase appropriateness, or anti-patterns")
  }

  // Check for common anti-patterns mentioned in verify
  if (
    verifyLower.includes("curl") &&
    !verifyLower.includes("not curl") &&
    !verifyLower.includes("instead of curl") &&
    !verifyLower.includes("don't use curl") &&
    (verifyLower.includes("sql") || verifyLower.includes("injection") || verifyLower.includes("brute"))
  ) {
    issues.push("Using curl for task where specialized tool (sqlmap, hydra) would be better")
  }

  if (verifyLower.includes("custom") && (verifyLower.includes("code") || verifyLower.includes("script"))) {
    if (!verifyLower.includes("not") && !verifyLower.includes("avoid") && !verifyLower.includes("instead")) {
      issues.push("Considering custom code when MCP tools should be used")
    }
  }

  return {
    valid: issues.length === 0,
    issues,
  }
}

/**
 * Strip TVAR blocks from text, returning clean text without TVAR tags.
 * Blocks should be sorted by startIndex descending to avoid index shifting.
 */
export function stripTVARBlocks(text: string, blocks: TVARBlock[]): string {
  if (blocks.length === 0) return text

  // Sort by position descending to avoid index shifting
  const sorted = [...blocks].sort((a, b) => b.startIndex - a.startIndex)

  let result = text
  for (const block of sorted) {
    result = result.slice(0, block.startIndex) + result.slice(block.endIndex)
  }

  return result.trim()
}
