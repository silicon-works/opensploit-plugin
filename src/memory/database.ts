/**
 * LanceDB Memory System Database
 *
 * Implements Doc 22 §Part 6 (lines 1780-1824)
 * - Database initialization at ~/.opensploit/opensploit.lance/
 * - Table creation: experiences, insights
 * - FTS index creation for hybrid search
 * - Idempotent initialization (safe to call multiple times)
 */

// Suppress LanceDB Rust-level warnings that corrupt the TUI (writes to stderr)
if (!process.env["LANCE_LOG"]) {
  process.env["LANCE_LOG"] = "error"
}

import * as lancedb from "@lancedb/lancedb"
import * as fs from "fs/promises"
import * as path from "path"
import * as os from "os"
import { createLog } from "../util/log"
import { experienceSchema, insightSchema, patternSchema, type MemoryMetadata } from "./schema"
import { toolSchema, TOOLS_TABLE_NAME } from "./tools"

const log = createLog("memory.database")

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

/** Current schema version - 7.0 adds method-level tool rows, sparse_json to experiences/insights */
const SCHEMA_VERSION = "7.0"

/** Previous schema version for migration detection */
const PREVIOUS_SCHEMA_VERSION = "6.1"

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
 * Check if a schema migration is needed (old version → new version).
 * Returns the old version string if migration needed, null otherwise.
 */
async function checkMigrationNeeded(): Promise<string | null> {
  try {
    const content = await fs.readFile(METADATA_PATH, "utf-8")
    const metadata: MemoryMetadata = JSON.parse(content)
    if (metadata.initialized && metadata.version && metadata.version !== SCHEMA_VERSION) {
      return metadata.version
    }
  } catch {
    // Not initialized or corrupt — no migration needed
  }
  return null
}

/**
 * Migrate from v6.1 to v7.0.
 *
 * v7.0 adds sparse_json to experiences/insights Arrow schemas.
 * Since experiences and insights are learning data that rebuilds over time,
 * we drop and recreate them with the new schema. Tools table is handled
 * separately by importFromLance/importFromYAML.
 */
async function migrateToV7(db: lancedb.Connection): Promise<void> {
  const existingTables = await db.tableNames()

  // Drop and recreate experiences with new schema (includes sparse_json)
  if (existingTables.includes("experiences")) {
    await db.dropTable("experiences")
  }
  await db.createEmptyTable("experiences", experienceSchema)

  // Drop and recreate insights with new schema (includes sparse_json)
  if (existingTables.includes("insights")) {
    await db.dropTable("insights")
  }
  await db.createEmptyTable("insights", insightSchema)

  // Tools table will be recreated on next registry import (method-level rows)
  // Drop it to force a fresh import with the new MethodRow schema
  if (existingTables.includes("tools")) {
    await db.dropTable("tools")
  }
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
  // Check for schema migration
  const oldVersion = await checkMigrationNeeded()
  if (oldVersion) {
    const db = await getConnection()
    if (oldVersion === PREVIOUS_SCHEMA_VERSION) {
      await migrateToV7(db)
    }
    // After migration, continue to ensure all tables exist
    await writeMetadata()
  }

  // Check if already initialized (and up to date)
  if (!oldVersion && await isInitialized()) {
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

  // Pre-seed insights from registry routing metadata if insights table is empty
  // Non-blocking — if embedding service or registry unavailable, skip silently
  try {
    const insightsTable = await db.openTable("insights")
    const insightCount = await insightsTable.countRows()
    if (insightCount === 0) {
      // Dynamically import to avoid circular dependency
      const { loadRegistry } = await import("./tools")
      const { preSeedInsightsFromRegistry } = await import("./insight")
      const registryResult = await loadRegistry()
      if (registryResult) {
        const seeded = await preSeedInsightsFromRegistry(registryResult.tools)
        if (seeded > 0) {
          log.info("pre-seeded insights from registry", { count: seeded })
        }
      }
    }
  } catch {
    // Non-critical — seeding happens on next init or can be triggered manually
  }

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
