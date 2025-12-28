/**
 * Output Indexer - Parses and indexes large tool outputs for RAG-based retrieval
 *
 * Instead of truncating large outputs, we:
 * 1. Parse them into structured records
 * 2. Store records in a searchable format
 * 3. Allow semantic/keyword queries to retrieve relevant portions
 */

import path from "path"
import fs from "fs/promises"
import os from "os"
import { Log } from "../util/log"

const log = Log.create({ service: "tool.output-indexer" })

const INDEX_DIR = path.join(os.homedir(), ".opensploit", "output-index")

/**
 * Parsed record from tool output
 */
export interface ParsedRecord {
  id: string
  tool: string
  method: string
  type: string // e.g., "directory", "port", "vulnerability"
  data: Record<string, unknown>
  text: string // searchable text representation
  timestamp: number
}

/**
 * Index metadata
 */
export interface OutputIndex {
  id: string
  sessionId: string
  tool: string
  method: string
  recordCount: number
  types: string[]
  timestamp: number
  filePath: string
}

/**
 * Search result
 */
export interface SearchResult {
  records: ParsedRecord[]
  totalMatches: number
  query: string
  indexId: string
}

/**
 * Parser function type
 */
type OutputParser = (output: string, tool: string, method: string) => ParsedRecord[]

/**
 * Tool-specific parsers
 */
const parsers: Record<string, Record<string, OutputParser>> = {
  ffuf: {
    dir_fuzz: parseFfufOutput,
    vhost_fuzz: parseFfufOutput,
  },
  nmap: {
    port_scan: parseNmapOutput,
    service_scan: parseNmapOutput,
    vuln_scan: parseNmapVulnOutput,
  },
  nikto: {
    scan: parseNiktoOutput,
  },
  gobuster: {
    dir: parseGobusterOutput,
  },
}

/**
 * Parse ffuf directory/vhost fuzzing output
 */
function parseFfufOutput(output: string, tool: string, method: string): ParsedRecord[] {
  const records: ParsedRecord[] = []
  const lines = output.split("\n")
  const timestamp = Date.now()

  // ffuf output format: URL [Status: XXX, Size: XXX, Words: XXX, Lines: XXX]
  // Or JSON format
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()
    if (!line) continue

    // Try to parse as structured line
    const match = line.match(
      /^(https?:\/\/[^\s]+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)(?:,\s*Words:\s*(\d+))?(?:,\s*Lines:\s*(\d+))?\]/i
    )

    if (match) {
      const [, url, status, size, words, lineCount] = match
      const urlPath = new URL(url).pathname

      records.push({
        id: `${tool}-${method}-${i}`,
        tool,
        method,
        type: "directory",
        data: {
          url,
          path: urlPath,
          status: parseInt(status),
          size: parseInt(size),
          words: words ? parseInt(words) : null,
          lines: lineCount ? parseInt(lineCount) : null,
        },
        text: `${urlPath} status:${status} size:${size}`,
        timestamp,
      })
      continue
    }

    // Try simpler format: /path [status]
    const simpleMatch = line.match(/^(\/[^\s]*)\s+\[(\d+)\]/)
    if (simpleMatch) {
      const [, urlPath, status] = simpleMatch
      records.push({
        id: `${tool}-${method}-${i}`,
        tool,
        method,
        type: "directory",
        data: {
          path: urlPath,
          status: parseInt(status),
        },
        text: `${urlPath} status:${status}`,
        timestamp,
      })
      continue
    }

    // Try JSON format (ffuf -o json)
    try {
      if (line.startsWith("{")) {
        const json = JSON.parse(line)
        if (json.url || json.input) {
          records.push({
            id: `${tool}-${method}-${i}`,
            tool,
            method,
            type: "directory",
            data: json,
            text: `${json.url || json.input?.FUZZ || ""} status:${json.status || ""} size:${json.length || json.size || ""}`,
            timestamp,
          })
        }
      }
    } catch {
      // Not JSON, skip
    }
  }

  return records
}

/**
 * Parse nmap port/service scan output
 */
function parseNmapOutput(output: string, tool: string, method: string): ParsedRecord[] {
  const records: ParsedRecord[] = []
  const lines = output.split("\n")
  const timestamp = Date.now()

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()

    // Match: PORT/PROTOCOL STATE SERVICE VERSION
    // e.g., "22/tcp open ssh OpenSSH 8.9p1 Ubuntu"
    const portMatch = line.match(/^(\d+)\/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)(?:\s+(.*))?$/)

    if (portMatch) {
      const [, port, protocol, state, service, version] = portMatch
      records.push({
        id: `${tool}-${method}-${i}`,
        tool,
        method,
        type: "port",
        data: {
          port: parseInt(port),
          protocol,
          state,
          service,
          version: version?.trim() || null,
        },
        text: `port:${port} ${protocol} ${state} ${service} ${version || ""}`.trim(),
        timestamp,
      })
    }
  }

  return records
}

/**
 * Parse nmap vulnerability scan output
 */
function parseNmapVulnOutput(output: string, tool: string, method: string): ParsedRecord[] {
  const records: ParsedRecord[] = []
  const lines = output.split("\n")
  const timestamp = Date.now()

  let currentVuln: Partial<ParsedRecord["data"]> | null = null
  let vulnIndex = 0

  for (const line of lines) {
    const trimmed = line.trim()

    // CVE reference
    const cveMatch = trimmed.match(/CVE-\d{4}-\d+/gi)
    if (cveMatch) {
      for (const cve of cveMatch) {
        records.push({
          id: `${tool}-vuln-${vulnIndex++}`,
          tool,
          method,
          type: "vulnerability",
          data: {
            cve: cve.toUpperCase(),
            description: trimmed,
          },
          text: `${cve} ${trimmed}`,
          timestamp,
        })
      }
    }

    // VULNERABLE indicator
    if (trimmed.includes("VULNERABLE") || trimmed.includes("vulnerable")) {
      records.push({
        id: `${tool}-vuln-${vulnIndex++}`,
        tool,
        method,
        type: "vulnerability",
        data: {
          status: "vulnerable",
          description: trimmed,
        },
        text: trimmed,
        timestamp,
      })
    }
  }

  return records
}

/**
 * Parse nikto web scanner output
 */
function parseNiktoOutput(output: string, tool: string, method: string): ParsedRecord[] {
  const records: ParsedRecord[] = []
  const lines = output.split("\n")
  const timestamp = Date.now()

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()

    // Nikto finding format: + OSVDB-XXXX: /path: description
    // Or: + /path: description
    const findingMatch = line.match(/^\+\s+(OSVDB-\d+:\s+)?([^:]+):\s+(.+)$/)

    if (findingMatch) {
      const [, osvdb, path, description] = findingMatch
      records.push({
        id: `${tool}-${method}-${i}`,
        tool,
        method,
        type: "vulnerability",
        data: {
          osvdb: osvdb?.replace(": ", "") || null,
          path: path.trim(),
          description: description.trim(),
        },
        text: `${path} ${description}`,
        timestamp,
      })
    }
  }

  return records
}

/**
 * Parse gobuster directory output
 */
function parseGobusterOutput(output: string, tool: string, method: string): ParsedRecord[] {
  const records: ParsedRecord[] = []
  const lines = output.split("\n")
  const timestamp = Date.now()

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()

    // Gobuster format: /path (Status: 200) [Size: 1234]
    const match = line.match(/^(\/\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?/)

    if (match) {
      const [, urlPath, status, size] = match
      records.push({
        id: `${tool}-${method}-${i}`,
        tool,
        method,
        type: "directory",
        data: {
          path: urlPath,
          status: parseInt(status),
          size: size ? parseInt(size) : null,
        },
        text: `${urlPath} status:${status} size:${size || ""}`,
        timestamp,
      })
    }
  }

  return records
}

/**
 * Generic fallback parser - splits into lines and creates basic records
 */
function genericParser(output: string, tool: string, method: string): ParsedRecord[] {
  const records: ParsedRecord[] = []
  const lines = output.split("\n")
  const timestamp = Date.now()

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()
    if (!line || line.length < 5) continue // Skip empty/short lines

    records.push({
      id: `${tool}-${method}-${i}`,
      tool,
      method,
      type: "line",
      data: { line: i, content: line },
      text: line,
      timestamp,
    })
  }

  return records
}

export namespace OutputIndexer {
  /**
   * Parse and index tool output
   */
  export async function index(input: {
    sessionId: string
    outputId: string
    tool: string
    method: string
    content: string
  }): Promise<OutputIndex> {
    const { sessionId, outputId, tool, method, content } = input

    // Get appropriate parser
    const parser = parsers[tool]?.[method] || genericParser

    // Parse output into records
    const records = parser(content, tool, method)

    log.info("indexed tool output", {
      tool,
      method,
      recordCount: records.length,
    })

    // Ensure index directory exists
    const sessionDir = path.join(INDEX_DIR, sessionId)
    await fs.mkdir(sessionDir, { recursive: true })

    // Write records as newline-delimited JSON (efficient for streaming)
    const indexPath = path.join(sessionDir, `${outputId}.ndjson`)
    const ndjson = records.map((r) => JSON.stringify(r)).join("\n")
    await fs.writeFile(indexPath, ndjson, "utf-8")

    // Collect unique types
    const types = [...new Set(records.map((r) => r.type))]

    // Create and save index metadata
    const index: OutputIndex = {
      id: outputId,
      sessionId,
      tool,
      method,
      recordCount: records.length,
      types,
      timestamp: Date.now(),
      filePath: indexPath,
    }

    const metaPath = path.join(sessionDir, `${outputId}.index.json`)
    await fs.writeFile(metaPath, JSON.stringify(index, null, 2), "utf-8")

    return index
  }

  /**
   * Search indexed output
   */
  export async function search(
    outputId: string,
    query: string,
    options?: {
      limit?: number
      type?: string
      filters?: Record<string, unknown>
    }
  ): Promise<SearchResult | null> {
    const limit = options?.limit ?? 50
    const typeFilter = options?.type
    const filters = options?.filters ?? {}

    // Find the index
    try {
      const sessions = await fs.readdir(INDEX_DIR).catch(() => [])

      for (const session of sessions) {
        const indexPath = path.join(INDEX_DIR, session, `${outputId}.ndjson`)

        try {
          const content = await fs.readFile(indexPath, "utf-8")
          const records: ParsedRecord[] = content
            .split("\n")
            .filter((line) => line.trim())
            .map((line) => JSON.parse(line))

          // Search and filter records
          const queryLower = query.toLowerCase()
          const queryTerms = queryLower.split(/\s+/).filter((t) => t.length > 0)

          const matches = records.filter((record) => {
            // Type filter
            if (typeFilter && record.type !== typeFilter) return false

            // Field filters (e.g., status=200)
            for (const [key, value] of Object.entries(filters)) {
              if (record.data[key] !== value) return false
            }

            // Text search - all terms must match
            const textLower = record.text.toLowerCase()
            return queryTerms.every((term) => {
              // Support field:value syntax in query
              if (term.includes(":")) {
                const [field, val] = term.split(":")
                const dataVal = String(record.data[field] ?? "").toLowerCase()
                return dataVal.includes(val) || dataVal === val
              }
              return textLower.includes(term)
            })
          })

          return {
            records: matches.slice(0, limit),
            totalMatches: matches.length,
            query,
            indexId: outputId,
          }
        } catch {
          // Not in this session
          continue
        }
      }

      return null
    } catch (error) {
      log.error("search failed", { outputId, error })
      return null
    }
  }

  /**
   * Get index metadata
   */
  export async function getIndex(outputId: string): Promise<OutputIndex | null> {
    try {
      const sessions = await fs.readdir(INDEX_DIR).catch(() => [])

      for (const session of sessions) {
        const metaPath = path.join(INDEX_DIR, session, `${outputId}.index.json`)

        try {
          const content = await fs.readFile(metaPath, "utf-8")
          return JSON.parse(content) as OutputIndex
        } catch {
          continue
        }
      }

      return null
    } catch {
      return null
    }
  }

  /**
   * Get summary statistics for indexed output
   */
  export async function getSummary(outputId: string): Promise<{
    total: number
    byType: Record<string, number>
    byStatus?: Record<string, number>
    sample: ParsedRecord[]
  } | null> {
    try {
      const sessions = await fs.readdir(INDEX_DIR).catch(() => [])

      for (const session of sessions) {
        const indexPath = path.join(INDEX_DIR, session, `${outputId}.ndjson`)

        try {
          const content = await fs.readFile(indexPath, "utf-8")
          const records: ParsedRecord[] = content
            .split("\n")
            .filter((line) => line.trim())
            .map((line) => JSON.parse(line))

          // Count by type
          const byType: Record<string, number> = {}
          const byStatus: Record<string, number> = {}

          for (const record of records) {
            byType[record.type] = (byType[record.type] || 0) + 1

            // Count by status code for directory/port records
            const status = record.data.status || record.data.state
            if (status) {
              const statusKey = String(status)
              byStatus[statusKey] = (byStatus[statusKey] || 0) + 1
            }
          }

          // Sample records (first 5 of each type)
          const sample: ParsedRecord[] = []
          const seenTypes = new Set<string>()
          for (const record of records) {
            if (!seenTypes.has(record.type) || sample.filter((r) => r.type === record.type).length < 3) {
              sample.push(record)
              seenTypes.add(record.type)
              if (sample.length >= 15) break
            }
          }

          return {
            total: records.length,
            byType,
            byStatus: Object.keys(byStatus).length > 0 ? byStatus : undefined,
            sample,
          }
        } catch {
          continue
        }
      }

      return null
    } catch {
      return null
    }
  }
}
