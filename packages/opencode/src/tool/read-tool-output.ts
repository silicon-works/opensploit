import z from "zod"
import { Tool } from "./tool"
import path from "path"
import os from "os"
import fs from "fs/promises"
import { Log } from "../util/log"

const log = Log.create({ service: "tool.read-tool-output" })

// =============================================================================
// Stub Implementation for Feature 08 (Output Store)
// =============================================================================
// This is a simplified stub that reads stored tool outputs from disk.
// Full implementation will include:
// - Structured output indexing
// - Search within outputs
// - Line range selection
// - Integration with tool output processor

const OUTPUTS_DIR = path.join(os.homedir(), ".opensploit", "outputs")

const DESCRIPTION = `Retrieve stored tool output by reference ID.

When tool outputs are too large to fit in context, they are stored externally
and a reference ID is returned. Use this tool to retrieve the full output
or specific portions of it.

**Parameters:**
- output_id: The reference ID returned when the output was stored
- session_id: Session ID to scope the output lookup
- start_line: Optional starting line number (1-indexed)
- end_line: Optional ending line number
- search: Optional search string to filter output

**Note:** This is a stub implementation. Full version (Feature 08) will include
structured indexing, field-based search, and intelligent summarization.`

export const ReadToolOutputTool = Tool.define("read_tool_output", {
  description: DESCRIPTION,
  parameters: z.object({
    output_id: z.string().describe("Reference ID of the stored output"),
    session_id: z.string().describe("Session ID to scope the lookup"),
    start_line: z.number().optional().describe("Starting line number (1-indexed)"),
    end_line: z.number().optional().describe("Ending line number"),
    search: z.string().optional().describe("Search string to filter output lines"),
    max_lines: z.number().optional().default(100).describe("Maximum lines to return (default: 100)"),
  }),
  async execute(params, ctx) {
    const { output_id, session_id, start_line, end_line, search, max_lines = 100 } = params

    log.info("read_tool_output", { output_id, session_id, start_line, end_line, search })

    // Construct output path
    const outputPath = path.join(OUTPUTS_DIR, session_id, `${output_id}.txt`)

    try {
      // Check if file exists
      await fs.access(outputPath)

      // Read file content
      const content = await fs.readFile(outputPath, "utf-8")
      let lines = content.split("\n")
      const totalLines = lines.length

      // Apply line range if specified
      if (start_line !== undefined || end_line !== undefined) {
        const start = (start_line ?? 1) - 1 // Convert to 0-indexed
        const end = end_line ?? lines.length
        lines = lines.slice(start, end)
      }

      // Apply search filter if specified
      if (search) {
        const searchLower = search.toLowerCase()
        lines = lines.filter(line => line.toLowerCase().includes(searchLower))
      }

      // Apply max lines limit
      const truncated = lines.length > max_lines
      if (truncated) {
        lines = lines.slice(0, max_lines)
      }

      // Build output
      let output = lines.join("\n")

      // Add metadata header
      const header = [
        `Output ID: ${output_id}`,
        `Total lines: ${totalLines}`,
        `Showing: ${lines.length} lines`,
        truncated ? `(truncated to ${max_lines} lines)` : "",
        search ? `Search filter: "${search}"` : "",
        "---",
      ].filter(Boolean).join("\n")

      output = header + "\n" + output

      return {
        output,
        title: `read_tool_output: ${output_id}`,
        metadata: {
          output_id,
          session_id,
          total_lines: totalLines,
          returned_lines: lines.length,
          truncated,
        },
      }
    } catch (error) {
      // File not found or other error
      const errorMessage = error instanceof Error ? error.message : String(error)

      if (errorMessage.includes("ENOENT")) {
        return {
          output: `Output not found: ${output_id}\n\nThe referenced output may have expired or the session ID may be incorrect.\n\nPath checked: ${outputPath}`,
          title: `read_tool_output: not found`,
          metadata: {
            output_id,
            session_id,
            total_lines: 0,
            returned_lines: 0,
            truncated: false,
          },
        }
      }

      return {
        output: `Error reading output: ${errorMessage}`,
        title: `read_tool_output: error`,
        metadata: {
          output_id,
          session_id,
          total_lines: 0,
          returned_lines: 0,
          truncated: false,
        },
      }
    }
  },
})

// =============================================================================
// Helper function to store tool output (for use by other tools)
// =============================================================================

export async function storeToolOutput(
  sessionId: string,
  outputId: string,
  content: string
): Promise<string> {
  const sessionDir = path.join(OUTPUTS_DIR, sessionId)
  await fs.mkdir(sessionDir, { recursive: true })

  const outputPath = path.join(sessionDir, `${outputId}.txt`)
  await fs.writeFile(outputPath, content, "utf-8")

  log.info("stored tool output", { sessionId, outputId, size: content.length })

  return outputId
}

export async function generateOutputId(): Promise<string> {
  // Simple ID generation - full implementation would use more robust IDs
  return `output_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`
}
