/**
 * TVAR Parser - Extracts structured TVAR (Thought-Verify-Action-Result) data from agent text output
 *
 * The agent outputs TVAR reasoning in XML-like tags:
 * <thought>...</thought>
 * <verify>...</verify>
 * <action>...</action>
 * <result>...</result>
 */

export interface TVARBlock {
  thought: string
  verify: string
  action?: string
  result?: string
  raw: string // Original text that was parsed
  startIndex: number
  endIndex: number
}

/**
 * Parse TVAR blocks from text output
 * Returns all complete and partial TVAR blocks found
 */
export function parseTVAR(text: string): TVARBlock[] {
  const blocks: TVARBlock[] = []

  // Find all <thought> tags as starting points
  const thoughtRegex = /<thought>([\s\S]*?)<\/thought>/gi
  let match: RegExpExecArray | null

  while ((match = thoughtRegex.exec(text)) !== null) {
    const thoughtStart = match.index
    const thought = match[1].trim()

    // Look for <verify> after this thought
    const afterThought = text.slice(match.index + match[0].length)
    const verifyMatch = afterThought.match(/<verify>([\s\S]*?)<\/verify>/i)

    if (!verifyMatch) continue // Need at least thought + verify

    const verify = verifyMatch[1].trim()
    const verifyEnd = match.index + match[0].length + verifyMatch.index! + verifyMatch[0].length

    // Look for optional <action> after verify
    const afterVerify = text.slice(verifyEnd)
    const actionMatch = afterVerify.match(/<action>([\s\S]*?)<\/action>/i)
    const action = actionMatch ? actionMatch[1].trim() : undefined

    // Look for optional <result> after action (or verify if no action)
    const searchFrom = actionMatch ? verifyEnd + actionMatch.index! + actionMatch[0].length : verifyEnd
    const afterAction = text.slice(searchFrom)
    const resultMatch = afterAction.match(/<result>([\s\S]*?)<\/result>/i)
    const result = resultMatch ? resultMatch[1].trim() : undefined

    // Calculate end index
    let endIndex = verifyEnd
    if (actionMatch) endIndex = verifyEnd + actionMatch.index! + actionMatch[0].length
    if (resultMatch) endIndex = searchFrom + resultMatch.index! + resultMatch[0].length

    blocks.push({
      thought,
      verify,
      action,
      result,
      raw: text.slice(thoughtStart, endIndex),
      startIndex: thoughtStart,
      endIndex,
    })
  }

  return blocks
}

/**
 * Check if text contains TVAR reasoning
 */
export function hasTVAR(text: string): boolean {
  return /<thought>[\s\S]*?<\/thought>/i.test(text) && /<verify>[\s\S]*?<\/verify>/i.test(text)
}

/**
 * Extract the phase from TVAR thought/verify content
 */
export function extractPhase(
  block: TVARBlock,
): "reconnaissance" | "enumeration" | "exploitation" | "post_exploitation" | "reporting" | undefined {
  const combined = `${block.thought} ${block.verify}`.toLowerCase()

  if (
    combined.includes("reconnaissance") ||
    combined.includes("recon") ||
    combined.includes("port scan") ||
    combined.includes("discovery")
  ) {
    return "reconnaissance"
  }
  if (
    combined.includes("enumeration") ||
    combined.includes("enumerate") ||
    combined.includes("directory") ||
    combined.includes("vhost") ||
    combined.includes("fuzzing")
  ) {
    return "enumeration"
  }
  if (
    combined.includes("exploitation") ||
    combined.includes("exploit") ||
    combined.includes("attack") ||
    combined.includes("injection") ||
    combined.includes("rce")
  ) {
    return "exploitation"
  }
  if (
    combined.includes("post-exploitation") ||
    combined.includes("post_exploitation") ||
    combined.includes("privilege") ||
    combined.includes("lateral") ||
    combined.includes("persistence")
  ) {
    return "post_exploitation"
  }
  if (combined.includes("report") || combined.includes("summary") || combined.includes("findings")) {
    return "reporting"
  }

  return undefined
}

/**
 * Validate that TVAR block has proper reasoning before tool use
 */
export function validateTVARBeforeToolCall(block: TVARBlock): { valid: boolean; issues: string[] } {
  const issues: string[] = []

  // Check thought has substance
  if (block.thought.length < 20) {
    issues.push("Thought is too brief - should explain objective and context")
  }

  // Check verify has anti-pattern consideration
  const verifyLower = block.verify.toLowerCase()
  if (
    !verifyLower.includes("tool") &&
    !verifyLower.includes("phase") &&
    !verifyLower.includes("anti-pattern") &&
    !verifyLower.includes("appropriate")
  ) {
    issues.push("Verify should check tool selection, phase appropriateness, or anti-patterns")
  }

  // Check for common anti-patterns mentioned in verify
  if (verifyLower.includes("curl") && !verifyLower.includes("not curl") && !verifyLower.includes("instead of curl")) {
    issues.push("Using curl when specialized tool might be better")
  }

  if (verifyLower.includes("custom") && verifyLower.includes("code")) {
    issues.push("Considering custom code when MCP tools should be used")
  }

  return {
    valid: issues.length === 0,
    issues,
  }
}
