import path from "path"
import os from "os"
import fs from "fs/promises"
import { ulid } from "ulid"
import { Log } from "../util/log"
import { Token } from "../util/token"
import { OutputIndexer, type OutputIndex } from "./output-indexer"

const log = Log.create({ service: "tool.output-store" })

/**
 * Output Store - Stores large tool outputs externally to prevent context overflow
 *
 * Instead of putting 150KB of nmap output directly in context:
 * 1. Store the full output in ~/.opensploit/outputs/{session}/{output_id}.json
 * 2. Return a summary + reference to the agent
 * 3. Agent can use read_tool_output to retrieve specific sections if needed
 */

const OUTPUTS_DIR = path.join(os.homedir(), ".opensploit", "outputs")

// Threshold for storing output externally (in characters)
// ~5000 chars ≈ 1250 tokens, leaving plenty of room for context
const STORE_THRESHOLD_CHARS = 5000

// Maximum chars to include in summary preview
const SUMMARY_PREVIEW_CHARS = 2000

export interface StoredOutput {
  id: string
  sessionId: string
  toolName: string
  method: string
  timestamp: number
  sizeBytes: number
  sizeTokensEstimate: number
  lineCount: number
  contentType: "text" | "json" | "binary"
  preview: string
  fullPath: string
  indexed: boolean
  indexInfo?: {
    recordCount: number
    types: string[]
  }
}

export interface StoreResult {
  stored: boolean
  output: string // Either full output (if small) or summary with reference
  reference?: StoredOutput
}

export namespace OutputStore {
  /**
   * Ensure the outputs directory exists for a session
   */
  async function ensureSessionDir(sessionId: string): Promise<string> {
    const sessionDir = path.join(OUTPUTS_DIR, sessionId)
    await fs.mkdir(sessionDir, { recursive: true })
    return sessionDir
  }

  /**
   * Generate a summary of the output with key information
   */
  function generateSummary(
    content: string,
    toolName: string,
    method: string,
    stored: StoredOutput,
    indexSummary?: { total: number; byType: Record<string, number>; byStatus?: Record<string, number> }
  ): string {
    let summary = `# ${toolName}.${method} Result\n\n`
    summary += `**Output indexed for search** - ${stored.sizeBytes.toLocaleString()} bytes (~${stored.sizeTokensEstimate.toLocaleString()} tokens)\n\n`

    // If we have index summary, show structured info instead of raw preview
    if (indexSummary && indexSummary.total > 0) {
      summary += `## Indexed Records: ${indexSummary.total.toLocaleString()}\n\n`

      // Show breakdown by type
      summary += `**By Type:**\n`
      for (const [type, count] of Object.entries(indexSummary.byType)) {
        summary += `- ${type}: ${count.toLocaleString()}\n`
      }
      summary += "\n"

      // Show breakdown by status if available
      if (indexSummary.byStatus && Object.keys(indexSummary.byStatus).length > 0) {
        summary += `**By Status:**\n`
        const sortedStatuses = Object.entries(indexSummary.byStatus).sort(([a], [b]) => a.localeCompare(b))
        for (const [status, count] of sortedStatuses) {
          summary += `- ${status}: ${count.toLocaleString()}\n`
        }
        summary += "\n"
      }

      summary += `## How to Search\n\n`
      summary += `Use \`read_tool_output\` with the reference ID and a search query:\n\n`
      summary += "```\n"
      summary += `read_tool_output:\n`
      summary += `  outputId: "${stored.id}"\n`
      summary += `  search: "admin"           # Find paths containing "admin"\n`
      summary += `  search: "status:200"      # Find 200 OK responses\n`
      summary += `  search: "status:403"      # Find 403 Forbidden\n`
      summary += "```\n\n"
    } else {
      // Fallback to preview for non-indexed outputs
      const lines = content.split("\n")
      const firstLines = lines.slice(0, 15).join("\n")

      summary += `## Preview (first 15 lines)\n\n`
      summary += "```\n"
      summary += firstLines.slice(0, SUMMARY_PREVIEW_CHARS)
      if (firstLines.length > SUMMARY_PREVIEW_CHARS) {
        summary += "\n... [preview truncated]"
      }
      summary += "\n```\n\n"
    }

    summary += `## Reference\n\n`
    summary += `- **ID**: \`${stored.id}\`\n`
    summary += `- **Records**: ${stored.indexInfo?.recordCount ?? stored.lineCount}\n`
    summary += `- **Size**: ${stored.sizeBytes.toLocaleString()} bytes\n`

    return summary
  }

  /**
   * Determine if output should be stored externally based on size
   */
  export function shouldStore(content: string): boolean {
    return content.length > STORE_THRESHOLD_CHARS
  }

  /**
   * Store a tool output and return either the full output or a summary with reference
   */
  export async function store(input: {
    sessionId: string
    toolName: string
    method: string
    content: string
    contentType?: "text" | "json" | "binary"
  }): Promise<StoreResult> {
    const { sessionId, toolName, method, content, contentType = "text" } = input

    // If output is small enough, return it directly
    if (!shouldStore(content)) {
      return {
        stored: false,
        output: content,
      }
    }

    // Generate unique ID and store
    const outputId = ulid()
    const sessionDir = await ensureSessionDir(sessionId)
    const outputPath = path.join(sessionDir, `${outputId}.txt`)

    // Write full content to file
    await fs.writeFile(outputPath, content, "utf-8")

    const lines = content.split("\n")
    const sizeBytes = Buffer.byteLength(content, "utf-8")
    const sizeTokensEstimate = Token.estimate(content)

    // Index the output for RAG-based search
    let indexInfo: OutputIndex | null = null
    let indexSummary: { total: number; byType: Record<string, number>; byStatus?: Record<string, number> } | null = null

    try {
      indexInfo = await OutputIndexer.index({
        sessionId,
        outputId,
        tool: toolName,
        method,
        content,
      })

      // Get summary statistics for the indexed data
      indexSummary = await OutputIndexer.getSummary(outputId)

      log.info("indexed output for RAG search", {
        outputId,
        toolName,
        method,
        recordCount: indexInfo.recordCount,
        types: indexInfo.types,
      })
    } catch (error) {
      log.warn("failed to index output, falling back to raw storage", {
        outputId,
        error: error instanceof Error ? error.message : String(error),
      })
    }

    const stored: StoredOutput = {
      id: outputId,
      sessionId,
      toolName,
      method,
      timestamp: Date.now(),
      sizeBytes,
      sizeTokensEstimate,
      lineCount: lines.length,
      contentType,
      preview: content.slice(0, 500),
      fullPath: outputPath,
      indexed: indexInfo !== null,
      indexInfo: indexInfo
        ? {
            recordCount: indexInfo.recordCount,
            types: indexInfo.types,
          }
        : undefined,
    }

    // Write metadata
    const metaPath = path.join(sessionDir, `${outputId}.meta.json`)
    await fs.writeFile(metaPath, JSON.stringify(stored, null, 2), "utf-8")

    log.info("stored large output externally", {
      outputId,
      toolName,
      method,
      sizeBytes,
      sizeTokensEstimate,
      lineCount: lines.length,
      indexed: stored.indexed,
    })

    // Generate summary for the agent (with index info if available)
    const summary = generateSummary(content, toolName, method, stored, indexSummary ?? undefined)

    return {
      stored: true,
      output: summary,
      reference: stored,
    }
  }

  /**
   * Retrieve a stored output by ID
   */
  export async function retrieve(
    outputId: string,
    options?: {
      startLine?: number
      endLine?: number
      search?: string
      maxChars?: number
    }
  ): Promise<{ found: boolean; content?: string; metadata?: StoredOutput; error?: string }> {
    // Search for the output across all sessions
    try {
      const sessions = await fs.readdir(OUTPUTS_DIR).catch(() => [])

      for (const session of sessions) {
        const metaPath = path.join(OUTPUTS_DIR, session, `${outputId}.meta.json`)
        const outputPath = path.join(OUTPUTS_DIR, session, `${outputId}.txt`)

        try {
          const metaContent = await fs.readFile(metaPath, "utf-8")
          const metadata = JSON.parse(metaContent) as StoredOutput

          let content = await fs.readFile(outputPath, "utf-8")

          // Apply filters
          if (options?.startLine !== undefined || options?.endLine !== undefined) {
            const lines = content.split("\n")
            const start = options.startLine ?? 0
            const end = options.endLine ?? lines.length
            content = lines.slice(start, end).join("\n")
          }

          if (options?.search) {
            const lines = content.split("\n")
            const matchingLines = lines.filter((line) =>
              line.toLowerCase().includes(options.search!.toLowerCase())
            )
            content = matchingLines.join("\n")
          }

          if (options?.maxChars && content.length > options.maxChars) {
            content = content.slice(0, options.maxChars) + "\n\n... [output truncated at maxChars limit]"
          }

          return { found: true, content, metadata }
        } catch {
          // Not in this session, continue
        }
      }

      return { found: false, error: `Output ${outputId} not found` }
    } catch (error) {
      return { found: false, error: `Error retrieving output: ${error}` }
    }
  }

  /**
   * List all stored outputs for a session
   */
  export async function list(sessionId: string): Promise<StoredOutput[]> {
    const sessionDir = path.join(OUTPUTS_DIR, sessionId)
    const outputs: StoredOutput[] = []

    try {
      const files = await fs.readdir(sessionDir)
      const metaFiles = files.filter((f) => f.endsWith(".meta.json"))

      for (const metaFile of metaFiles) {
        try {
          const content = await fs.readFile(path.join(sessionDir, metaFile), "utf-8")
          outputs.push(JSON.parse(content))
        } catch {
          // Skip invalid files
        }
      }
    } catch {
      // Session directory doesn't exist
    }

    return outputs.sort((a, b) => b.timestamp - a.timestamp)
  }

  /**
   * Clean up old outputs (older than maxAgeMs)
   */
  export async function cleanup(maxAgeMs: number = 24 * 60 * 60 * 1000): Promise<number> {
    let cleaned = 0
    const now = Date.now()

    try {
      const sessions = await fs.readdir(OUTPUTS_DIR).catch(() => [])

      for (const session of sessions) {
        const sessionDir = path.join(OUTPUTS_DIR, session)
        const files = await fs.readdir(sessionDir).catch(() => [])
        const metaFiles = files.filter((f) => f.endsWith(".meta.json"))

        for (const metaFile of metaFiles) {
          try {
            const content = await fs.readFile(path.join(sessionDir, metaFile), "utf-8")
            const metadata = JSON.parse(content) as StoredOutput

            if (now - metadata.timestamp > maxAgeMs) {
              const outputId = metaFile.replace(".meta.json", "")
              await fs.unlink(path.join(sessionDir, `${outputId}.txt`)).catch(() => {})
              await fs.unlink(path.join(sessionDir, metaFile)).catch(() => {})
              cleaned++
            }
          } catch {
            // Skip invalid files
          }
        }

        // Remove empty session directories
        const remaining = await fs.readdir(sessionDir).catch(() => [])
        if (remaining.length === 0) {
          await fs.rmdir(sessionDir).catch(() => {})
        }
      }
    } catch {
      // Outputs directory doesn't exist
    }

    if (cleaned > 0) {
      log.info("cleaned up old outputs", { cleaned })
    }

    return cleaned
  }
}
