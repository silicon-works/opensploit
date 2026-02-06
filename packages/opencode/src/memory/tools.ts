/**
 * Tool Registry Storage in LanceDB
 *
 * Stores tool registry data as plaintext rows in LanceDB.
 * No embedding vectors — uses the existing keyword scoring algorithm
 * from tool-registry-search.ts for search.
 *
 * This replaces ~/.opensploit/registry.yaml as the primary storage,
 * with YAML as a fallback if LanceDB is unavailable.
 *
 * Each tool is stored as a row with JSON-serialized complex fields
 * (methods, routing, etc.) for easy reconstruction.
 */

import * as lancedb from "@lancedb/lancedb"
import { Schema, Field, Utf8, Int32 } from "apache-arrow"
import { Log } from "@/util/log"
import { getConnection } from "./database"

const log = Log.create({ service: "memory.tools" })

// =============================================================================
// Schema
// =============================================================================

/**
 * Tools table schema — plaintext, no vectors.
 * Complex fields (methods, routing, phases, etc.) stored as JSON strings.
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
  new Field("registry_version", new Utf8(), false),  // Registry version for staleness check
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
  registry_version: string
}

// =============================================================================
// Import / Sync
// =============================================================================

/**
 * Import tools from a parsed registry into LanceDB.
 * Replaces all existing rows (full refresh on version change).
 *
 * @param registryTools - Record<toolId, toolData> from parsed YAML
 * @param registryVersion - Registry version string
 */
export async function importFromRegistry(
  registryTools: Record<string, any>,
  registryVersion: string
): Promise<{ imported: number }> {
  const db = await getConnection()
  const existingTables = await db.tableNames()

  // Build rows
  const rows: ToolRow[] = []
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
      registry_version: registryVersion,
    })
  }

  if (rows.length === 0) {
    log.warn("no tools to import")
    return { imported: 0 }
  }

  // Drop and recreate to do a full refresh
  if (existingTables.includes(TOOLS_TABLE_NAME)) {
    await db.dropTable(TOOLS_TABLE_NAME)
  }

  await db.createTable(TOOLS_TABLE_NAME, rows as unknown as Record<string, unknown>[])

  log.info("imported_tools", {
    count: rows.length,
    version: registryVersion,
  })

  return { imported: rows.length }
}

/**
 * Load all tools from LanceDB and reconstruct them into the Registry format.
 * Returns null if the tools table doesn't exist or is empty.
 */
export async function loadRegistry(): Promise<{
  version: string
  tools: Record<string, any>
} | null> {
  try {
    const db = await getConnection()
    const tables = await db.tableNames()

    if (!tables.includes(TOOLS_TABLE_NAME)) {
      return null
    }

    const table = await db.openTable(TOOLS_TABLE_NAME)
    const results = await table.query().toArray()

    if (results.length === 0) {
      return null
    }

    // Reconstruct registry format
    const tools: Record<string, any> = {}
    let version = ""

    for (const row of results) {
      const toolId = row.id as string
      const rawJson = row.raw_json as string
      version = row.registry_version as string

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
      version,
    })

    return { version, tools }
  } catch (error) {
    log.warn("failed to load tools from lancedb", { error: String(error) })
    return null
  }
}

/**
 * Get the registry version stored in LanceDB (without loading all tools).
 */
export async function getStoredVersion(): Promise<string | null> {
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

    return results[0].registry_version as string
  } catch {
    return null
  }
}

/**
 * Check if a sync is needed (version mismatch or missing table).
 */
export async function needsSync(currentVersion: string): Promise<boolean> {
  const stored = await getStoredVersion()
  return stored !== currentVersion
}
