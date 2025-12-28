import z from "zod"
import { Tool } from "./tool"
import { OutputStore } from "./output-store"
import { OutputIndexer } from "./output-indexer"

const DEFAULT_SEARCH_LIMIT = 50

const DESCRIPTION = `Search and retrieve indexed tool output by reference ID.

When security tools produce large outputs (ffuf, nmap, etc.), they are parsed and indexed
for efficient search. Use this tool to find specific results without loading everything.

## Search Examples

Find directories with 200 status:
  outputId: "01JFXYZ123ABC"
  search: "status:200"

Find admin-related paths:
  outputId: "01JFXYZ123ABC"
  search: "admin"

Find open ports:
  outputId: "01JFXYZ123ABC"
  search: "open"

Find specific CVEs:
  outputId: "01JFXYZ123ABC"
  search: "CVE-2024"

## Search Syntax

- Simple text: \`admin\` - matches any record containing "admin"
- Field search: \`status:200\` - matches records where status field is 200
- Multiple terms: \`admin status:200\` - all terms must match (AND)

## Limits

- Default: Returns top ${DEFAULT_SEARCH_LIMIT} matching records
- Use limit parameter to adjust (max 200)`

interface ToolResult {
  output: string
  title: string
  metadata: {
    outputId: string
    found: boolean
    matchCount?: number
    totalMatches?: number
    error?: string
  }
}

export const ReadToolOutputTool = Tool.define("read_tool_output", {
  description: DESCRIPTION,
  parameters: z.object({
    outputId: z.string().describe("The reference ID of the stored output"),
    search: z.string().optional().describe("Search query (e.g., 'admin', 'status:200', 'open')"),
    type: z.string().optional().describe("Filter by record type (e.g., 'directory', 'port', 'vulnerability')"),
    limit: z.number().optional().describe(`Maximum records to return (default: ${DEFAULT_SEARCH_LIMIT}, max: 200)`),
  }),
  async execute(params, _ctx): Promise<ToolResult> {
    const { outputId, search, type } = params
    const limit = Math.min(params.limit ?? DEFAULT_SEARCH_LIMIT, 200)

    // First check if we have an indexed version
    const indexInfo = await OutputIndexer.getIndex(outputId)

    if (indexInfo) {
      // Use indexed search
      const query = search || ""
      const result = await OutputIndexer.search(outputId, query, {
        limit,
        type,
      })

      if (!result) {
        return {
          output: `Output ${outputId} not found or search failed.`,
          title: `Error: Search failed`,
          metadata: { outputId, found: false, error: "Search failed" },
        }
      }

      // Format results
      let output = `# Search Results: ${outputId}\n\n`
      output += `**Query**: ${search || "(all records)"}\n`
      output += `**Matches**: ${result.records.length} of ${result.totalMatches} total\n`
      output += `**Tool**: ${indexInfo.tool}.${indexInfo.method}\n\n`

      if (result.records.length === 0) {
        output += `No matching records found. Try a different search query.\n`
      } else {
        output += `## Results\n\n`

        // Group by type for cleaner output
        const byType: Record<string, typeof result.records> = {}
        for (const record of result.records) {
          if (!byType[record.type]) byType[record.type] = []
          byType[record.type].push(record)
        }

        for (const [recordType, records] of Object.entries(byType)) {
          output += `### ${recordType} (${records.length})\n\n`

          if (recordType === "directory") {
            // Table format for directories
            output += `| Path | Status | Size |\n`
            output += `|------|--------|------|\n`
            for (const r of records) {
              const path = r.data.path || r.data.url || ""
              const status = r.data.status || ""
              const size = r.data.size || ""
              output += `| ${path} | ${status} | ${size} |\n`
            }
          } else if (recordType === "port") {
            // Table format for ports
            output += `| Port | Protocol | State | Service | Version |\n`
            output += `|------|----------|-------|---------|----------|\n`
            for (const r of records) {
              output += `| ${r.data.port} | ${r.data.protocol} | ${r.data.state} | ${r.data.service || ""} | ${r.data.version || ""} |\n`
            }
          } else if (recordType === "vulnerability") {
            // List format for vulns
            for (const r of records) {
              const cve = r.data.cve || ""
              const desc = r.data.description || r.text
              output += `- ${cve ? `**${cve}**: ` : ""}${desc}\n`
            }
          } else {
            // Generic format
            for (const r of records) {
              output += `- ${r.text}\n`
            }
          }
          output += "\n"
        }

        if (result.totalMatches > result.records.length) {
          output += `\n> Showing ${result.records.length} of ${result.totalMatches} matches. Use a more specific search or increase limit.\n`
        }
      }

      return {
        output,
        title: `Search: ${result.records.length} results`,
        metadata: {
          outputId,
          found: true,
          matchCount: result.records.length,
          totalMatches: result.totalMatches,
        },
      }
    }

    // Fall back to raw retrieval with limit for non-indexed outputs
    const rawResult = await OutputStore.retrieve(outputId, {
      search,
      maxChars: 10000,
    })

    if (!rawResult.found) {
      return {
        output: `Output not found: ${rawResult.error}\n\nThe output may have been cleaned up or the ID is incorrect.`,
        title: `Error: Output not found`,
        metadata: { outputId, found: false, error: rawResult.error },
      }
    }

    const lines = rawResult.content!.split("\n").length
    let output = `# Retrieved Output: ${outputId}\n\n`

    if (rawResult.metadata) {
      output += `**Tool**: ${rawResult.metadata.toolName}.${rawResult.metadata.method}\n`
      output += `**Note**: This output was not indexed. Showing raw content (limited).\n\n`
    }

    output += "---\n\n"
    output += rawResult.content

    return {
      output,
      title: `Output ${outputId} (${lines} lines)`,
      metadata: { outputId, found: true, matchCount: lines },
    }
  },
})
