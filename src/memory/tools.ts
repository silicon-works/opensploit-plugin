/**
 * Tool Registry Storage in LanceDB — Method-Level Rows
 *
 * Schema v7.0: Each row represents a single (tool, method) pair.
 * A tool with 9 methods produces 9 rows, each with method-specific
 * search_text, method_vector, and sparse_json.
 *
 * Stores tool registry data in LanceDB with support for:
 * - Pre-built .lance archives (with BGE-M3 dense + sparse vectors from CI)
 * - YAML fallback (plaintext import with client-side FTS, no vectors)
 * - Hash-based freshness (SHA-256 content hash replaces version-based sync)
 *
 * Search modes:
 * - Hybrid (FTS + vector + sparse via custom scoring) when pre-built vectors available
 * - FTS-only when imported from YAML (no embedding server needed)
 * - Keyword fallback when neither FTS nor vectors available
 */

// Lazy import — see database.ts for explanation
let _lancedb: typeof import("@lancedb/lancedb") | null = null
async function getLanceDb() {
  if (!_lancedb) {
    if (!process.env["LANCE_LOG"]) process.env["LANCE_LOG"] = "error"
    if (!process.env["RUST_LOG"]) process.env["RUST_LOG"] = "error"
    _lancedb = await import("@lancedb/lancedb")
  }
  return _lancedb
}
import { createLog } from "../util/log"
import { getConnection, OPENSPLOIT_LANCE_PATH } from "./database"
import { VECTOR_DIMENSIONS, type MethodRow } from "./schema"
import * as fs from "fs/promises"
import * as path from "path"

const log = createLog("memory.tools")

// =============================================================================
// Schema (reference only — actual schema inferred from data/CI archive)
// =============================================================================

/**
 * Tools table schema — method-level rows.
 *
 * Pre-built .lance archives include search_text (FTS indexed),
 * method_vector (BGE-M3 1024-dim), and sparse_json (BGE-M3 sparse weights).
 * YAML fallback populates search_text but no vectors.
 *
 * Note: This is exported for reference; importFromLance() file-copies
 * the CI-built table, and importFromYAML() lets LanceDB infer schema.
 */
export { type MethodRow } from "./schema"

export const TOOLS_TABLE_NAME = "tools"

// Re-export the old ToolRow name for backwards compatibility
export type ToolRow = MethodRow

// =============================================================================
// Schema (kept for toolSchema export compatibility)
// =============================================================================

import { Schema, Field, Utf8, Float32, FixedSizeList } from "apache-arrow"

export const toolSchema = new Schema([
  new Field("id", new Utf8(), false),                // "tool_id:method_name"
  new Field("tool_id", new Utf8(), false),
  new Field("method_name", new Utf8(), false),
  new Field("tool_name", new Utf8(), false),
  new Field("tool_description", new Utf8(), false),
  new Field("method_description", new Utf8(), false),
  new Field("when_to_use", new Utf8(), true),
  new Field("search_text", new Utf8(), false),
  new Field("phases_json", new Utf8(), false),
  new Field("capabilities_json", new Utf8(), false),
  new Field("routing_json", new Utf8(), false),
  new Field("methods_json", new Utf8(), false),
  new Field("requirements_json", new Utf8(), true),
  new Field("resources_json", new Utf8(), true),
  new Field("raw_json", new Utf8(), false),
  new Field("see_also_json", new Utf8(), true),
  new Field("registry_hash", new Utf8(), false),
  new Field("sparse_json", new Utf8(), true),
])

// =============================================================================
// Method-Level Search Text Builder
// =============================================================================

/**
 * Build focused per-method search text for FTS indexing.
 *
 * ~100-300 chars per method vs ~1200 chars per tool. BM25 naturally
 * weights routing signals higher because there's less dilution.
 *
 * IMPORTANT: This logic is duplicated in the CI build script at
 * mcp-tools/scripts/build-registry-lance.py:build_method_search_text().
 * Both must stay in sync for consistent FTS results between
 * CI-built indexes and YAML-fallback client-built indexes.
 */
export function buildMethodSearchText(
  tool: Record<string, any>,
  methodName: string,
  method: Record<string, any>
): string {
  const parts: string[] = []

  // Tool name for context
  parts.push(tool.name ?? "")

  // Method identity
  parts.push(methodName)

  // Method-specific documentation
  parts.push(method.description ?? "")
  if (method.when_to_use) {
    parts.push(method.when_to_use)
  }

  // Tool description (brief context)
  parts.push(tool.description ?? "")

  // Routing use_for phrases (high-signal)
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
 * The archive is produced by CI (build-registry-lance.py) and contains
 * method-level rows with:
 * - Plaintext fields (tool_id, method_name, search_text, etc.)
 * - method_vector with BGE-M3 1024-dim embeddings
 * - sparse_json with BGE-M3 learned sparse weights
 * - registry_hash for freshness checks
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

  // Check if vectors are present (method_vector for v7.0)
  const hasVecs = firstRow.method_vector != null

  // Recreate FTS index (compatible with TS client)
  try {
    const lb = await getLanceDb()
    await table.createIndex("search_text", { config: lb.Index.fts(), replace: true })
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
    hasVectors: hasVecs,
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
 * Creates method-level rows with search_text on client side and builds FTS index.
 * No vectors — FTS-only search.
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

  // Build method-level rows
  const rows: Omit<MethodRow, "method_vector" | "sparse_json">[] = []
  for (const [toolId, tool] of Object.entries(registryTools)) {
    const methods = tool.methods ?? {}
    const toolJson = JSON.stringify(tool)
    const phasesJson = JSON.stringify(tool.phases ?? [])
    const capabilitiesJson = JSON.stringify(tool.capabilities ?? [])
    const routingJson = JSON.stringify(tool.routing ?? {})
    const methodsJson = JSON.stringify(methods)
    const requirementsJson = JSON.stringify(tool.requirements ?? {})
    const resourcesJson = JSON.stringify(tool.resources ?? {})
    const seeAlsoJson = JSON.stringify(tool.see_also ?? [])

    const methodEntries = Object.entries(methods as Record<string, any>)

    if (methodEntries.length === 0) {
      // Tool with no methods — single "default" row
      const searchText = buildMethodSearchText(tool, "default", { description: tool.description ?? "" })
      rows.push({
        id: `${toolId}:default`,
        tool_id: toolId,
        method_name: "default",
        tool_name: tool.name ?? toolId,
        tool_description: tool.description ?? "",
        method_description: tool.description ?? "",
        when_to_use: "",
        search_text: searchText,
        phases_json: phasesJson,
        capabilities_json: capabilitiesJson,
        routing_json: routingJson,
        methods_json: methodsJson,
        requirements_json: requirementsJson,
        resources_json: resourcesJson,
        raw_json: toolJson,
        see_also_json: seeAlsoJson,
        registry_hash: registryHash,
      })
    } else {
      for (const [methodName, method] of methodEntries) {
        const searchText = buildMethodSearchText(tool, methodName, method)
        rows.push({
          id: `${toolId}:${methodName}`,
          tool_id: toolId,
          method_name: methodName,
          tool_name: tool.name ?? toolId,
          tool_description: tool.description ?? "",
          method_description: method.description ?? "",
          when_to_use: method.when_to_use ?? "",
          search_text: searchText,
          phases_json: phasesJson,
          capabilities_json: capabilitiesJson,
          routing_json: routingJson,
          methods_json: methodsJson,
          requirements_json: requirementsJson,
          resources_json: resourcesJson,
          raw_json: toolJson,
          see_also_json: seeAlsoJson,
          registry_hash: registryHash,
        })
      }
    }
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
    const lb = await getLanceDb()
    await table.createIndex("search_text", { config: lb.Index.fts(), replace: true })
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
 *
 * Method-level rows share the same tool_id and raw_json.
 * Deduplicate by tool_id — parse raw_json once per tool.
 *
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
    // Method-level table may have ~254 rows; use explicit high limit
    const results = await table.query().limit(10000).toArray()

    if (results.length === 0) {
      return null
    }

    // Deduplicate by tool_id (multiple method rows per tool)
    const tools: Record<string, any> = {}
    let hash = ""
    const seenToolIds = new Set<string>()

    for (const row of results) {
      const toolId = row.tool_id as string
      hash = row.registry_hash as string

      if (seenToolIds.has(toolId)) continue
      seenToolIds.add(toolId)

      const rawJson = row.raw_json as string
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
      rows: results.length,
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
 *
 * Checks for method_vector (v7.0 schema) or tool_vector (v6.1 legacy).
 */
export async function hasVectors(): Promise<boolean> {
  try {
    const db = await getConnection()
    const tables = await db.tableNames()
    if (!tables.includes(TOOLS_TABLE_NAME)) return false

    const table = await db.openTable(TOOLS_TABLE_NAME)
    const results = await table.query().limit(1).toArray()
    if (results.length === 0) return false

    // v7.0 uses method_vector; v6.1 legacy uses tool_vector
    return results[0].method_vector != null || results[0].tool_vector != null
  } catch {
    return false
  }
}
