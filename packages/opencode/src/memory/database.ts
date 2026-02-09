/**
 * LanceDB Memory System Database
 *
 * Implements Doc 22 §Part 6 (lines 1780-1824)
 * - Database initialization at ~/.opensploit/opensploit.lance/
 * - Table creation: experiences, insights
 * - FTS index creation for hybrid search
 * - Idempotent initialization (safe to call multiple times)
 */

import * as lancedb from "@lancedb/lancedb"
import * as fs from "fs/promises"
import * as path from "path"
import * as os from "os"
import { experienceSchema, insightSchema, patternSchema, type MemoryMetadata } from "./schema"
import { toolSchema, TOOLS_TABLE_NAME } from "./tools"

// =============================================================================
// Constants
// =============================================================================

/** LanceDB database path - Doc 22 §Part 6 (line 1783) */
export const OPENSPLOIT_LANCE_PATH = path.join(
  os.homedir(),
  ".opensploit",
  "opensploit.lance"
)

/** Metadata file path */
const METADATA_PATH = path.join(os.homedir(), ".opensploit", "metadata.json")

/** Current schema version - 6.1 adds P2 metadata fields (confidence, last_accessed, access_count, superseded_by) */
const SCHEMA_VERSION = "6.1"

// =============================================================================
// Database Connection
// =============================================================================

/** Cached database connection */
let dbConnection: lancedb.Connection | null = null

/**
 * Get or create the LanceDB connection
 *
 * Uses a singleton pattern to reuse the connection across calls.
 */
export async function getConnection(): Promise<lancedb.Connection> {
  if (dbConnection) {
    return dbConnection
  }

  // Ensure directory exists
  await fs.mkdir(path.dirname(OPENSPLOIT_LANCE_PATH), { recursive: true })

  dbConnection = await lancedb.connect(OPENSPLOIT_LANCE_PATH)
  return dbConnection
}

/**
 * Close the database connection
 *
 * Call this during shutdown to clean up resources.
 */
export async function closeConnection(): Promise<void> {
  if (dbConnection) {
    // LanceDB connections are automatically cleaned up
    // but we null the reference to force re-connection if needed
    dbConnection = null
  }
}

// =============================================================================
// Initialization
// =============================================================================

/**
 * Check if the memory system has been initialized
 */
async function isInitialized(): Promise<boolean> {
  try {
    const content = await fs.readFile(METADATA_PATH, "utf-8")
    const metadata: MemoryMetadata = JSON.parse(content)
    return metadata.initialized === true
  } catch {
    return false
  }
}

/**
 * Write metadata file after successful initialization
 */
async function writeMetadata(): Promise<void> {
  const metadata: MemoryMetadata = {
    initialized: true,
    timestamp: new Date().toISOString(),
    version: SCHEMA_VERSION,
  }
  await fs.writeFile(METADATA_PATH, JSON.stringify(metadata, null, 2))
}

/**
 * Initialize the memory system
 *
 * Implements Doc 22 §Part 6 (lines 1785-1824)
 *
 * Creates:
 * - experiences table (empty, learns from real engagements)
 * - insights table (empty, extracted from experience patterns)
 * - FTS indexes for hybrid search
 *
 * This function is idempotent - safe to call multiple times.
 * If already initialized, returns early without changes.
 *
 * @returns true if initialized, false if already initialized
 */
export async function initializeMemorySystem(): Promise<boolean> {
  // Check if already initialized
  if (await isInitialized()) {
    return false
  }

  const db = await getConnection()

  // Get list of existing tables to avoid errors
  const existingTables = await db.tableNames()

  // Create experiences table if not exists
  // Doc 22 §Part 6 (lines 1797-1802)
  if (!existingTables.includes("experiences")) {
    await db.createEmptyTable("experiences", experienceSchema)
  }

  // Create insights table if not exists
  // Doc 22 §Part 6 (lines 1804-1807)
  if (!existingTables.includes("insights")) {
    await db.createEmptyTable("insights", insightSchema)
  }

  // Create patterns table if not exists
  // Doc 13 §Initialization (lines 1084-1110)
  if (!existingTables.includes("patterns")) {
    await db.createEmptyTable("patterns", patternSchema)
  }

  // Tools table is created/populated by tools.ts importFromLance() or importFromYAML()
  // when the registry is first loaded. No empty table needed here
  // since tools are always bulk-inserted from the archive or YAML source.
  // FTS indexes are created during import (see tools.ts).

  // Write metadata to mark as initialized
  await writeMetadata()

  return true
}

// =============================================================================
// Table Access
// =============================================================================

/**
 * Get the experiences table
 *
 * @throws Error if table doesn't exist (call initializeMemorySystem first)
 */
export async function getExperiencesTable(): Promise<lancedb.Table> {
  const db = await getConnection()
  return await db.openTable("experiences")
}

/**
 * Get the insights table
 *
 * @throws Error if table doesn't exist (call initializeMemorySystem first)
 */
export async function getInsightsTable(): Promise<lancedb.Table> {
  const db = await getConnection()
  return await db.openTable("insights")
}

/**
 * Get the patterns table
 * Doc 13 §Storage (lines 1006-1110)
 *
 * @throws Error if table doesn't exist (call initializeMemorySystem first)
 */
export async function getPatternsTable(): Promise<lancedb.Table> {
  const db = await getConnection()
  return await db.openTable("patterns")
}

/**
 * Get the tools table
 *
 * @throws Error if table doesn't exist (import tools first via importFromLance/importFromYAML)
 */
export async function getToolsTable(): Promise<lancedb.Table> {
  const db = await getConnection()
  return await db.openTable(TOOLS_TABLE_NAME)
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Get the current memory system status
 */
export async function getMemoryStatus(): Promise<{
  initialized: boolean
  path: string
  tables: string[]
  metadata?: MemoryMetadata
}> {
  const status: {
    initialized: boolean
    path: string
    tables: string[]
    metadata?: MemoryMetadata
  } = {
    initialized: false,
    path: OPENSPLOIT_LANCE_PATH,
    tables: [],
  }

  try {
    const content = await fs.readFile(METADATA_PATH, "utf-8")
    status.metadata = JSON.parse(content)
    status.initialized = status.metadata?.initialized === true
  } catch {
    // Not initialized
  }

  if (status.initialized) {
    try {
      const db = await getConnection()
      status.tables = await db.tableNames()
    } catch {
      // Database not accessible
    }
  }

  return status
}

/**
 * Reset the memory system (for testing only)
 *
 * WARNING: This deletes all experiences and insights!
 */
export async function resetMemorySystem(): Promise<void> {
  // Close any existing connection
  await closeConnection()

  // Delete the database directory
  try {
    await fs.rm(OPENSPLOIT_LANCE_PATH, { recursive: true, force: true })
  } catch {
    // Directory may not exist
  }

  // Delete metadata
  try {
    await fs.unlink(METADATA_PATH)
  } catch {
    // File may not exist
  }
}
