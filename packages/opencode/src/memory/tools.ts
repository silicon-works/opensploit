/**
 * Tool Registry Storage in LanceDB
 *
 * Stores tool registry data in LanceDB with support for:
 * - Pre-built .lance archives (with BGE-M3 vectors + FTS index from CI)
 * - YAML fallback (plaintext import with client-side FTS, no vectors)
 * - Hash-based freshness (SHA-256 content hash replaces version-based sync)
 *
 * Search modes:
 * - Hybrid (FTS + vector via RRF) when pre-built vectors available
 * - FTS-only when imported from YAML (no embedding server needed)
 * - Keyword fallback when neither FTS nor vectors available
 */

import * as lancedb from "@lancedb/lancedb"
import { Schema, Field, Utf8, Float32, FixedSizeList } from "apache-arrow"
import { Log } from "@/util/log"
import { getConnection, OPENSPLOIT_LANCE_PATH } from "./database"
import { VECTOR_DIMENSIONS } from "./schema"
import * as fs from "fs/promises"
import * as path from "path"

const log = Log.create({ service: "memory.tools" })

// =============================================================================
// Schema
// =============================================================================

/**
 * Tools table schema — plaintext + optional vectors.
 *
 * Pre-built .lance archives include search_text (FTS indexed) and
 * tool_vector (BGE-M3 1024-dim). YAML fallback populates search_text
 * but leaves tool_vector null.
 *
 * Note: This schema is not used for table creation — importFromLance()
 * file-copies the CI-built table, and importFromYAML() lets LanceDB
 * infer the schema from data rows. It serves as a type reference and
 * documentation of the expected column layout.
 */
export const toolSchema = new Schema([
  new Field("id", new Utf8(), false),                // tool ID (e.g., "nmap")
  new Field("name", new Utf8(), false),              // display name
  new Field("description", new Utf8(), false),       // tool description
  new Field("version", new Utf8(), true),            // tool version
  new Field("image", new Utf8(), true),              // Docker image
  new Field("phases_json", new Utf8(), false),       // JSON array of phases
  new Field("capabilities_json", new Utf8(), false), // JSON array of capabilities
  new Field("routing_json", new Utf8(), false),      // JSON: { use_for, triggers, never_use_for, prefer_over }
  new Field("methods_json", new Utf8(), false),      // JSON: { methodName: MethodDef }
  new Field("requirements_json", new Utf8(), true),  // JSON: { network, privileged, ... }
  new Field("resources_json", new Utf8(), true),     // JSON: { memory_mb, cpu }
  new Field("raw_json", new Utf8(), false),          // Full tool entry as JSON for reconstruction
  new Field("search_text", new Utf8(), false),       // Concatenated searchable text for FTS
  new Field("registry_hash", new Utf8(), false),     // SHA-256 content hash for freshness
])

export const TOOLS_TABLE_NAME = "tools"

// =============================================================================
// Types
// =============================================================================

/** Row in the tools table */
export interface ToolRow {
  id: string
  name: string
  description: string
  version: string
  image: string
  phases_json: string
  capabilities_json: string
  routing_json: string
  methods_json: string
  requirements_json: string
  resources_json: string
  raw_json: string
  search_text: string
  registry_hash: string
  tool_vector?: number[]
}

// =============================================================================
// Search Text Builder
// =============================================================================

/**
 * Build concatenated search text for FTS indexing.
 *
 * Includes: name, description, capabilities, method descriptions,
 * method when_to_use, and routing.use_for phrases.
 *
 * IMPORTANT: This logic is duplicated in the CI build script at
 * mcp-tools/scripts/build-registry-lance.py:build_search_text().
 * Both must stay in sync for consistent FTS results between
 * CI-built indexes and YAML-fallback client-built indexes.
 */
function buildSearchText(tool: Record<string, any>): string {
  const parts: string[] = [
    tool.name ?? "",
    tool.description ?? "",
    ...(tool.capabilities ?? []),
  ]

  // Method names, descriptions, and when_to_use
  if (tool.methods) {
    for (const [methodName, method] of Object.entries(tool.methods as Record<string, any>)) {
      parts.push(methodName)
      parts.push(method.description ?? "")
      if (method.when_to_use) {
        parts.push(method.when_to_use)
      }
    }
  }

  // Routing use_for phrases (high-signal for search)
  const routing = tool.routing ?? {}
  for (const phrase of routing.use_for ?? []) {
    parts.push(phrase)
  }

  return parts.filter(Boolean).join(" ")
}

// =============================================================================
// Import from Pre-Built .lance Archive (CI pipeline)
// =============================================================================

/**
 * Import tools from a pre-built .lance tar.gz archive.
 *
 * The archive is produced by CI (build-registry-lance.py) and contains:
 * - Plaintext fields (id, name, description, etc.)
 * - search_text with pre-built FTS index
 * - tool_vector with BGE-M3 1024-dim embeddings
 * - registry_hash for freshness checks
 *
 * Extracts the archive, then replaces the tools table in the active
 * LanceDB database by dropping and re-importing from the extracted data.
 *
 * @param tarPath - Path to registry.lance.tar.gz
 * @param registryHash - Expected hash (for verification)
 */
export async function importFromLance(
  tarPath: string,
  registryHash: string
): Promise<{ imported: number }> {
  // Extract to temp location
  const extractDir = path.join(path.dirname(tarPath), "lance-extract")
  try {
    await fs.rm(extractDir, { recursive: true, force: true })
  } catch { /* may not exist */ }
  await fs.mkdir(extractDir, { recursive: true })

  const proc = Bun.spawnSync(["tar", "-xzf", tarPath, "-C", extractDir])
  if (proc.exitCode !== 0) {
    throw new Error(`tar extraction failed with exit code ${proc.exitCode}`)
  }

  // The archive contains tools.lance/tools.lance/ (DB dir / table dir)
  const sourceTableDir = path.join(extractDir, "tools.lance", "tools.lance")
  const stat = await fs.stat(sourceTableDir).catch(() => null)
  if (!stat?.isDirectory()) {
    throw new Error(`Expected tools.lance/tools.lance directory in archive, not found`)
  }

  // Copy the table directly into the main LanceDB directory.
  // This avoids the read-convert-write cycle which crashes Bun due to
  // Arrow Vector memory issues with bulk row conversion.
  const mainToolsDir = path.join(OPENSPLOIT_LANCE_PATH, "tools.lance")
  try {
    await fs.rm(mainToolsDir, { recursive: true, force: true })
  } catch { /* may not exist */ }
  await fs.cp(sourceTableDir, mainToolsDir, { recursive: true })

  // Remove FTS indices from CI (Python lancedb FTS is incompatible with TS client)
  const indicesDir = path.join(mainToolsDir, "_indices")
  try {
    await fs.rm(indicesDir, { recursive: true, force: true })
  } catch { /* may not exist */ }

  // Verify the import and get row count
  const db = await getConnection()
  const table = await db.openTable(TOOLS_TABLE_NAME)
  const count = await table.countRows()

  if (count === 0) {
    throw new Error("Imported .lance archive contains no tool rows")
  }

  // Verify archive hash matches expected (integrity check)
  const firstRow = (await table.query().limit(1).toArray())[0]
  const storedHash = firstRow.registry_hash as string
  if (storedHash !== registryHash) {
    throw new Error(
      `Archive integrity check failed: expected hash ${registryHash.slice(0, 16)}..., ` +
      `got ${storedHash?.slice(0, 16) ?? "null"}...`
    )
  }

  // Check if vectors are present
  const hasVectors = firstRow.tool_vector != null

  // Recreate FTS index (compatible with TS client)
  try {
    await table.createIndex("search_text", { config: lancedb.Index.fts(), replace: true })
    log.info("created FTS index on imported tools")
  } catch (error) {
    log.warn("FTS index creation failed on imported tools", { error: String(error) })
  }

  // Cleanup extracted files
  try {
    await fs.rm(extractDir, { recursive: true, force: true })
  } catch { /* non-critical */ }

  log.info("imported_tools_from_lance", {
    count,
    hash: registryHash.slice(0, 16),
    hasVectors,
  })

  return { imported: count }
}

// =============================================================================
// Import from YAML (fallback)
// =============================================================================

/**
 * Import tools from parsed YAML registry into LanceDB.
 *
 * This is the fallback path when .lance archives are unavailable.
 * Creates search_text on client side and builds FTS index.
 * No vectors (tool_vector is omitted) — FTS-only search.
 *
 * @param registryTools - Record<toolId, toolData> from parsed YAML
 * @param registryHash - SHA-256 hash of registry content
 */
export async function importFromYAML(
  registryTools: Record<string, any>,
  registryHash: string
): Promise<{ imported: number }> {
  const db = await getConnection()
  const existingTables = await db.tableNames()

  // Build rows with client-side search_text
  const rows: Omit<ToolRow, "tool_vector">[] = []
  for (const [toolId, tool] of Object.entries(registryTools)) {
    rows.push({
      id: toolId,
      name: tool.name ?? toolId,
      description: tool.description ?? "",
      version: tool.version ?? "",
      image: tool.image ?? "",
      phases_json: JSON.stringify(tool.phases ?? []),
      capabilities_json: JSON.stringify(tool.capabilities ?? []),
      routing_json: JSON.stringify(tool.routing ?? {}),
      methods_json: JSON.stringify(tool.methods ?? {}),
      requirements_json: JSON.stringify(tool.requirements ?? {}),
      resources_json: JSON.stringify(tool.resources ?? {}),
      raw_json: JSON.stringify(tool),
      search_text: buildSearchText(tool),
      registry_hash: registryHash,
    })
  }

  if (rows.length === 0) {
    log.warn("no tools to import from YAML")
    return { imported: 0 }
  }

  // Drop and recreate for full refresh
  if (existingTables.includes(TOOLS_TABLE_NAME)) {
    await db.dropTable(TOOLS_TABLE_NAME)
  }

  const table = await db.createTable(TOOLS_TABLE_NAME, rows as unknown as Record<string, unknown>[])

  // Create FTS index on search_text
  try {
    await table.createIndex("search_text", { config: lancedb.Index.fts(), replace: true })
    log.info("created FTS index on YAML-imported tools")
  } catch (error) {
    log.warn("FTS index creation failed", { error: String(error) })
  }

  log.info("imported_tools_from_yaml", {
    count: rows.length,
    hash: registryHash.slice(0, 16),
  })

  return { imported: rows.length }
}

// =============================================================================
// Load / Query
// =============================================================================

/**
 * Load all tools from LanceDB and reconstruct them into the Registry format.
 * Returns null if the tools table doesn't exist or is empty.
 */
export async function loadRegistry(): Promise<{
  hash: string
  tools: Record<string, any>
} | null> {
  try {
    const db = await getConnection()
    const tables = await db.tableNames()

    if (!tables.includes(TOOLS_TABLE_NAME)) {
      return null
    }

    const table = await db.openTable(TOOLS_TABLE_NAME)
    // LanceDB v0.15.0 defaults to limit(10); use explicit high limit to get all tools
    const results = await table.query().limit(10000).toArray()

    if (results.length === 0) {
      return null
    }

    // Reconstruct registry format
    const tools: Record<string, any> = {}
    let hash = ""

    for (const row of results) {
      const toolId = row.id as string
      const rawJson = row.raw_json as string
      hash = row.registry_hash as string

      try {
        tools[toolId] = JSON.parse(rawJson)
      } catch {
        log.warn("failed to parse tool row", { toolId })
      }
    }

    if (Object.keys(tools).length === 0) {
      return null
    }

    log.info("loaded_tools_from_lancedb", {
      count: Object.keys(tools).length,
      hash: hash.slice(0, 16),
    })

    return { hash, tools }
  } catch (error) {
    log.warn("failed to load tools from lancedb", { error: String(error) })
    return null
  }
}

/**
 * Get the registry hash stored in LanceDB (without loading all tools).
 */
export async function getStoredHash(): Promise<string | null> {
  try {
    const db = await getConnection()
    const tables = await db.tableNames()

    if (!tables.includes(TOOLS_TABLE_NAME)) {
      return null
    }

    const table = await db.openTable(TOOLS_TABLE_NAME)
    const results = await table.query().limit(1).toArray()

    if (results.length === 0) {
      return null
    }

    return results[0].registry_hash as string
  } catch {
    return null
  }
}

/**
 * Check if an update is needed (hash mismatch or missing table).
 */
export async function needsUpdate(remoteHash: string): Promise<boolean> {
  const stored = await getStoredHash()
  return stored !== remoteHash
}

/**
 * Check if the tools table has pre-built vectors (from .lance import).
 * Returns false if table doesn't exist or has no vectors.
 */
export async function hasVectors(): Promise<boolean> {
  try {
    const db = await getConnection()
    const tables = await db.tableNames()
    if (!tables.includes(TOOLS_TABLE_NAME)) return false

    const table = await db.openTable(TOOLS_TABLE_NAME)
    const results = await table.query().limit(1).toArray()
    if (results.length === 0) return false

    return results[0].tool_vector != null
  } catch {
    return false
  }
}
