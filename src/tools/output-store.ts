/**
 * Output Store
 *
 * Intercepts large MCP tool outputs, stores them externally, and provides
 * summaries with query access. This prevents context overflow while
 * maintaining access to full tool results.
 *
 * Requirements (Feature 05):
 * - REQ-ARC-024: Store outputs >5000 chars externally
 * - REQ-ARC-025: Return summaries with reference IDs
 * - REQ-ARC-026: Provide retrieval tool for stored outputs
 * - REQ-ARC-027: Support field:value queries on records
 * - REQ-ARC-028: Outputs associated with sessions
 * - REQ-ARC-029: Clean up old outputs (24 hours)
 *
 * Design Decision:
 * - Use MCP's structured `data` directly, don't re-parse raw_output
 * - Normalize to flat records for simple field:value queries
 */

import path from "path"
import os from "os"
import { mkdirSync, existsSync, writeFileSync, readFileSync, readdirSync, statSync, unlinkSync, rmSync } from "fs"
import { randomBytes } from "crypto"
import { createLog } from "../util/log"
import { normalize, type OutputRecord } from "../util/output-normalizers"

const log = createLog("output-store")

/**
 * Generate a unique output ID.
 * Format: out_{timestamp}_{random}
 */
function generateOutputId(): string {
  const timestamp = Date.now().toString(36)
  const random = randomBytes(4).toString("hex")
  return `out_${timestamp}_${random}`
}

// Configuration
const STORE_THRESHOLD = 5000 // chars - store outputs larger than this
const QUERY_LIMIT_DEFAULT = 50 // max records returned per query
const RETENTION_MS = 24 * 60 * 60 * 1000 // 24 hours

// Sessions directory for output storage
// In the fat fork this came from @/training/training-data — here we inline it
const SESSIONS_DIR = path.join(os.homedir(), ".opensploit", "sessions")

/**
 * Sanitize an ID to prevent path traversal (BUG-OS-1, BUG-OS-2).
 * Rejects IDs containing "..", "/", "\", or null bytes.
 */
function sanitizeId(id: string, label: string): string {
  if (!id || id.includes("..") || id.includes("/") || id.includes("\\") || id.includes("\0")) {
    throw new Error(`Invalid ${label}: must not contain path separators or traversal sequences`)
  }
  return id
}

/**
 * Get outputs directory for a session.
 * ~/.opensploit/sessions/{sessionID}/outputs/
 */
function getSessionOutputsDir(sessionID: string): string {
  return path.join(SESSIONS_DIR, sanitizeId(sessionID, "sessionID"), "outputs")
}

/**
 * Stored output format.
 */
export interface StoredOutput {
  id: string
  tool: string
  method: string
  timestamp: number
  records: OutputRecord[]
  summary: OutputSummary
  rawOutput: string
  sizeBytes: number
}

/**
 * Summary statistics for stored output.
 */
export interface OutputSummary {
  total: number
  byType: Record<string, number>
  byStatus?: Record<string, number>
  preview?: string[]
}

/**
 * Result of the store operation.
 */
export interface StoreResult {
  stored: boolean
  output: string
  outputId?: string
}

/**
 * Check if output should be stored externally.
 */
function shouldStore(data: any, rawOutput: string): boolean {
  const dataSize = data ? JSON.stringify(data).length : 0
  const rawSize = rawOutput?.length ?? 0
  return dataSize + rawSize > STORE_THRESHOLD
}

/**
 * Count records by a field value.
 */
function countBy<T>(items: T[], fn: (item: T) => string | undefined): Record<string, number> {
  const counts: Record<string, number> = {}
  for (const item of items) {
    const key = fn(item)
    if (key !== undefined && key !== "") {
      counts[key] = (counts[key] ?? 0) + 1
    }
  }
  return counts
}

/**
 * Generate summary statistics from normalized records.
 */
function generateSummary(records: OutputRecord[]): OutputSummary {
  const byType = countBy(records, (r) => r.type)

  // Count by status/state (common fields in security tools)
  const byStatus = countBy(records, (r) => r.state ?? r.status?.toString())

  // Generate preview of key values
  const preview: string[] = []
  for (const record of records.slice(0, 10)) {
    if (record.type === "port") {
      preview.push(`${record.port}/${record.protocol} (${record.service || record.state})`)
    } else if (record.type === "directory") {
      preview.push(`${record.path} [${record.status}]`)
    } else if (record.type === "vulnerability") {
      preview.push(record.name ?? record.script ?? record.description?.slice(0, 50) ?? "vuln")
    } else if (record.type === "credential") {
      preview.push(`${record.login}:***@${record.host}`)
    } else {
      // Generic preview
      const values = Object.values(record).filter((v) => typeof v === "string" || typeof v === "number")
      preview.push(values.slice(0, 3).join(", ").slice(0, 50))
    }
  }

  return {
    total: records.length,
    byType,
    ...(Object.keys(byStatus).length > 0 && { byStatus }),
    preview,
  }
}

/**
 * Format summary as text for the agent.
 */
function formatSummary(summary: OutputSummary, tool: string, method: string, outputId: string): string {
  const lines: string[] = []

  lines.push(`## ${tool}.${method} Result`)
  lines.push("")
  lines.push(`**Total Records**: ${summary.total}`)

  // Type breakdown
  if (Object.keys(summary.byType).length > 0) {
    lines.push("")
    lines.push("**By Type**:")
    for (const [type, count] of Object.entries(summary.byType)) {
      lines.push(`- ${type}: ${count}`)
    }
  }

  // Status breakdown
  if (summary.byStatus && Object.keys(summary.byStatus).length > 0) {
    lines.push("")
    lines.push("**By Status**:")
    for (const [status, count] of Object.entries(summary.byStatus)) {
      lines.push(`- ${status}: ${count}`)
    }
  }

  // Preview
  if (summary.preview && summary.preview.length > 0) {
    lines.push("")
    lines.push("**Preview**:")
    for (const item of summary.preview) {
      lines.push(`- ${item}`)
    }
    if (summary.total > summary.preview.length) {
      lines.push(`- ... and ${summary.total - summary.preview.length} more`)
    }
  }

  // Query hint
  lines.push("")
  lines.push("---")
  lines.push(`Query with: \`read_tool_output(id="${outputId}", query="field:value")\``)
  lines.push("")
  lines.push("Examples:")
  lines.push(`- \`read_tool_output(id="${outputId}", query="port:22")\` - find SSH`)
  lines.push(`- \`read_tool_output(id="${outputId}", query="status:200")\` - find successful responses`)
  lines.push(`- \`read_tool_output(id="${outputId}", query="open")\` - text search for "open"`)

  return lines.join("\n")
}

/**
 * Format small output directly for the agent (when under threshold).
 */
function formatDirectOutput(data: any, rawOutput: string): string {
  // If we have structured data, format it nicely
  if (data && typeof data === "object") {
    // Check for summary field (many MCP tools add this)
    if (data.summary) {
      const lines: string[] = []
      lines.push("**Summary**:")
      for (const [key, value] of Object.entries(data.summary)) {
        if (Array.isArray(value)) {
          lines.push(`- ${key}: ${value.slice(0, 10).join(", ")}${value.length > 10 ? "..." : ""}`)
        } else {
          lines.push(`- ${key}: ${value}`)
        }
      }
      return lines.join("\n")
    }
    // Otherwise return JSON
    return JSON.stringify(data, null, 2)
  }
  return rawOutput
}

/**
 * Get output directory for a session.
 * Uses the session archive: ~/.opensploit/sessions/{sessionID}/outputs/
 */
function getSessionDir(sessionId: string): string {
  return getSessionOutputsDir(sessionId)
}

/**
 * Store a large output externally.
 */
export async function store(input: {
  sessionId: string
  tool: string
  method?: string
  data: any
  rawOutput: string
}): Promise<StoreResult> {
  const { sessionId, tool, data, rawOutput } = input
  const method = input.method ?? "execute"

  // Check if we need to store
  if (!shouldStore(data, rawOutput)) {
    return {
      stored: false,
      output: formatDirectOutput(data, rawOutput),
    }
  }

  // Normalize data to flat records
  const records = normalize(tool, data, rawOutput)
  const summary = generateSummary(records)

  // Generate output ID
  const outputId = generateOutputId()

  // Prepare stored output
  const storedOutput: StoredOutput = {
    id: outputId,
    tool,
    method,
    timestamp: Date.now(),
    records,
    summary,
    rawOutput,
    sizeBytes: (data ? JSON.stringify(data).length : 0) + (rawOutput?.length ?? 0),
  }

  // Ensure session directory exists
  const sessionDir = getSessionDir(sessionId)
  if (!existsSync(sessionDir)) {
    mkdirSync(sessionDir, { recursive: true })
  }

  // Write to file
  const outputPath = path.join(sessionDir, `${outputId}.json`)
  writeFileSync(outputPath, JSON.stringify(storedOutput, null, 2), "utf-8")

  log.info("stored", {
    sessionId: sessionId.slice(-8),
    outputId,
    tool,
    records: records.length,
    sizeBytes: storedOutput.sizeBytes,
  })

  // Format summary for agent
  const formattedSummary = formatSummary(summary, tool, method, outputId)

  return {
    stored: true,
    output: formattedSummary,
    outputId,
  }
}

/**
 * Query stored output by ID.
 */
export async function query(input: {
  sessionId: string
  outputId: string
  query?: string
  type?: string
  limit?: number
}): Promise<{
  found: boolean
  records: OutputRecord[]
  total: number
  error?: string
}> {
  const { sessionId, outputId, query: queryStr, type, limit = QUERY_LIMIT_DEFAULT } = input

  // BUG-OS-1/OS-2 fix: sanitize IDs to prevent path traversal
  const safeSessionId = sanitizeId(sessionId, "sessionId")
  const safeOutputId = sanitizeId(outputId, "outputId")

  // Load stored output
  const outputPath = path.join(getSessionDir(safeSessionId), `${safeOutputId}.json`)

  if (!existsSync(outputPath)) {
    return {
      found: false,
      records: [],
      total: 0,
      error: `Output not found: ${outputId}`,
    }
  }

  try {
    const content = readFileSync(outputPath, "utf-8")
    const stored: StoredOutput = JSON.parse(content)

    let records = stored.records

    // Filter by type if specified
    if (type) {
      records = records.filter((r) => r.type === type)
    }

    // Apply query filter
    if (queryStr) {
      // Check for field:value query
      const fieldMatch = queryStr.match(/^(\w+):(.+)$/)
      if (fieldMatch) {
        const [, field, value] = fieldMatch
        records = records.filter((r) => {
          const fieldValue = r[field]
          if (fieldValue === undefined) return false
          // Handle numeric comparison
          if (typeof fieldValue === "number") {
            return fieldValue === parseInt(value, 10)
          }
          // String comparison (case-insensitive)
          return String(fieldValue).toLowerCase() === value.toLowerCase()
        })
      } else {
        // Text search across all string fields
        const searchLower = queryStr.toLowerCase()
        records = records.filter((r) => {
          return Object.values(r).some((v) => {
            if (typeof v === "string") {
              return v.toLowerCase().includes(searchLower)
            }
            return false
          })
        })
      }
    }

    const total = records.length

    // Apply limit
    records = records.slice(0, limit)

    return {
      found: true,
      records,
      total,
    }
  } catch (error) {
    log.error("query failed", { outputId, error })
    return {
      found: false,
      records: [],
      total: 0,
      error: `Failed to read output: ${error instanceof Error ? error.message : String(error)}`,
    }
  }
}

/**
 * Get stored output metadata (without loading full records).
 */
export async function getMetadata(
  sessionId: string,
  outputId: string,
): Promise<{
  found: boolean
  tool?: string
  method?: string
  timestamp?: number
  recordCount?: number
  sizeBytes?: number
}> {
  const safeOutputId = sanitizeId(outputId, "outputId")
  const outputPath = path.join(getSessionDir(sessionId), `${safeOutputId}.json`)

  if (!existsSync(outputPath)) {
    return { found: false }
  }

  try {
    const content = readFileSync(outputPath, "utf-8")
    const stored: StoredOutput = JSON.parse(content)
    return {
      found: true,
      tool: stored.tool,
      method: stored.method,
      timestamp: stored.timestamp,
      recordCount: stored.records.length,
      sizeBytes: stored.sizeBytes,
    }
  } catch {
    return { found: false }
  }
}

/**
 * Get raw output from stored output (for fallback text search).
 */
export async function getRawOutput(sessionId: string, outputId: string): Promise<string | null> {
  const safeOutputId = sanitizeId(outputId, "outputId")
  const outputPath = path.join(getSessionDir(sessionId), `${safeOutputId}.json`)

  if (!existsSync(outputPath)) {
    return null
  }

  try {
    const content = readFileSync(outputPath, "utf-8")
    const stored: StoredOutput = JSON.parse(content)
    return stored.rawOutput
  } catch {
    return null
  }
}

/**
 * Clean up old outputs (older than retention period).
 */
export async function cleanup(): Promise<{ deleted: number }> {
  let deleted = 0
  const cutoff = Date.now() - RETENTION_MS

  if (!existsSync(SESSIONS_DIR)) {
    return { deleted: 0 }
  }

  try {
    // Iterate through session directories in training folder
    const sessions = readdirSync(SESSIONS_DIR)
    for (const sessionId of sessions) {
      const sessionDir = getSessionOutputsDir(sessionId)

      if (!existsSync(sessionDir)) continue

      if (!statSync(sessionDir).isDirectory()) continue

      const files = readdirSync(sessionDir)
      let deletedInSession = 0

      for (const file of files) {
        if (!file.endsWith(".json")) continue

        const filePath = path.join(sessionDir, file)
        try {
          const content = readFileSync(filePath, "utf-8")
          const stored: StoredOutput = JSON.parse(content)

          if (stored.timestamp < cutoff) {
            unlinkSync(filePath)
            deleted++
            deletedInSession++
          }
        } catch {
          // If we can't read the file, check file modification time
          const stat = statSync(filePath)
          if (stat.mtimeMs < cutoff) {
            unlinkSync(filePath)
            deleted++
            deletedInSession++
          }
        }
      }

      // Remove empty session directories
      const remainingFiles = readdirSync(sessionDir)
      if (remainingFiles.length === 0) {
        rmSync(sessionDir, { recursive: true })
      }
    }

    if (deleted > 0) {
      log.info("cleanup completed", { deleted })
    }
  } catch (error) {
    log.error("cleanup failed", { error })
  }

  return { deleted }
}

/**
 * Clean up all outputs for a specific session.
 */
export async function cleanupSession(sessionId: string): Promise<void> {
  const sessionDir = getSessionDir(sessionId)

  if (existsSync(sessionDir)) {
    rmSync(sessionDir, { recursive: true })
    log.info("session cleanup", { sessionId: sessionId.slice(-8) })
  }
}

/**
 * Format query results as text for the agent.
 */
export function formatQueryResults(
  records: OutputRecord[],
  total: number,
  limit: number,
): string {
  if (records.length === 0) {
    return "No matching records found."
  }

  const lines: string[] = []

  // Detect record type to format appropriately
  const recordType = records[0]?.type

  if (recordType === "port") {
    // Format as port table
    lines.push("| Port | Protocol | State | Service | Version |")
    lines.push("|------|----------|-------|---------|---------|")
    for (const r of records) {
      lines.push(`| ${r.port} | ${r.protocol} | ${r.state} | ${r.service || "-"} | ${r.version || "-"} |`)
    }
  } else if (recordType === "directory") {
    // Format as directory table
    lines.push("| Path | Status | Size |")
    lines.push("|------|--------|------|")
    for (const r of records) {
      lines.push(`| ${r.path} | ${r.status} | ${r.length || r.size || "-"} |`)
    }
  } else if (recordType === "vulnerability") {
    // Format as vulnerability list
    for (const r of records) {
      lines.push(`- **${r.name || r.script || r.template_id || "Unknown"}**`)
      if (r.severity) lines.push(`  - Severity: ${r.severity}`)
      if (r.host || r.port) lines.push(`  - Target: ${r.host || ""}${r.port ? ":" + r.port : ""}`)
      if (r.description) lines.push(`  - ${r.description.slice(0, 100)}...`)
      lines.push("")
    }
  } else if (recordType === "credential") {
    // Format credentials (hide passwords)
    lines.push("| Host | Service | Login | Password |")
    lines.push("|------|---------|-------|----------|")
    for (const r of records) {
      lines.push(`| ${r.host} | ${r.service} | ${r.login} | *** |`)
    }
  } else {
    // Generic format - JSON list
    for (const r of records) {
      lines.push(`- ${JSON.stringify(r)}`)
    }
  }

  // Add truncation notice
  if (total > records.length) {
    lines.push("")
    lines.push(`*Showing ${records.length} of ${total} results. Use \`limit\` parameter to see more.*`)
  }

  return lines.join("\n")
}
