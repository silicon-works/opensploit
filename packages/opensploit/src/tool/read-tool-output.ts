import z from "zod"
import { Tool } from "./tool"
import { OutputStore } from "./output-store"

const DESCRIPTION = `Retrieve stored tool output by reference ID.

When security tools produce large outputs (nmap scans, enumeration results, etc.),
the output is stored externally to prevent context overflow. Use this tool to retrieve
the full output or search within it.

## Usage

1. **Get full output**: Just provide the reference ID
2. **Get specific lines**: Use startLine/endLine to retrieve a range
3. **Search within output**: Use the search parameter to filter lines containing a keyword
4. **Limit size**: Use maxChars to cap the response size

## Examples

Retrieve full output:
  outputId: "01JFXYZ123ABC"

Get lines 100-200:
  outputId: "01JFXYZ123ABC"
  startLine: 100
  endLine: 200

Search for open ports:
  outputId: "01JFXYZ123ABC"
  search: "open"

Get first 5000 chars:
  outputId: "01JFXYZ123ABC"
  maxChars: 5000`

interface ToolResult {
  output: string
  title: string
  metadata: {
    outputId: string
    found: boolean
    linesReturned?: number
    error?: string
  }
}

export const ReadToolOutputTool = Tool.define("read_tool_output", {
  description: DESCRIPTION,
  parameters: z.object({
    outputId: z.string().describe("The reference ID of the stored output (from mcp_tool results)"),
    startLine: z.number().optional().describe("Start reading from this line number (0-indexed)"),
    endLine: z.number().optional().describe("Stop reading at this line number (exclusive)"),
    search: z.string().optional().describe("Filter to lines containing this substring (case-insensitive)"),
    maxChars: z.number().optional().describe("Maximum characters to return (default: unlimited)"),
  }),
  async execute(params, _ctx): Promise<ToolResult> {
    const { outputId, startLine, endLine, search, maxChars } = params

    const result = await OutputStore.retrieve(outputId, {
      startLine,
      endLine,
      search,
      maxChars,
    })

    if (!result.found) {
      return {
        output: `Output not found: ${result.error}\n\nThe output may have been cleaned up (outputs expire after 24 hours) or the ID may be incorrect.`,
        title: `Error: Output not found`,
        metadata: { outputId, found: false, error: result.error },
      }
    }

    const lines = result.content!.split("\n").length
    let header = `# Retrieved Output: ${outputId}\n\n`

    if (result.metadata) {
      header += `**Tool**: ${result.metadata.toolName}.${result.metadata.method}\n`
      header += `**Original size**: ${result.metadata.sizeBytes.toLocaleString()} bytes (${result.metadata.lineCount} lines)\n`
    }

    if (startLine !== undefined || endLine !== undefined) {
      header += `**Line range**: ${startLine ?? 0} - ${endLine ?? "end"}\n`
    }

    if (search) {
      header += `**Search filter**: "${search}"\n`
    }

    header += `**Lines returned**: ${lines}\n\n`
    header += "---\n\n"

    return {
      output: header + result.content,
      title: `Output ${outputId} (${lines} lines)`,
      metadata: { outputId, found: true, linesReturned: lines },
    }
  },
})
