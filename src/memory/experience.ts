/**
 * Experience Recording
 *
 * Implements Doc 22 §Part 2 (lines 339-560)
 *
 * Records tool execution outcomes to LanceDB for learning:
 * - Success/failure detection with tool-specific heuristics
 * - Recovery linking when failure → success pattern detected
 * - Deduplication via cosine similarity (threshold: 0.92)
 * - Embedding generation for semantic search
 *
 * The experience collection enables:
 * - Learning which tools work best for specific contexts
 * - Detecting failure → recovery patterns for insights
 * - Improving tool selection ranking over time
 */

import { createLog } from "../util/log"
import { getExperiencesTable, initializeMemorySystem } from "./database"
import { getEmbeddingService } from "./embedding"
import {
  createExperience,
  generateExperienceId,
  EXPERIENCE_DEDUP_THRESHOLD,
  VECTOR_DIMENSIONS,
  type Experience,
} from "./schema"
import { serializeSparse } from "./sparse"
import {
  type ToolContext,
  type PreviousFailure,
  getPreviousFailure,
  clearPreviousFailure,
  recordToolTried,
  recordToolSuccess,
  recordToolFailure as setFailureInContext,
} from "./context"

const log = createLog("memory.experience")

// =============================================================================
// Types
// =============================================================================

/**
 * Tool execution result - normalized output from MCP tools
 *
 * Different tools return different structures, but we normalize to this
 * for success detection and result summarization.
 */
export interface ToolResult {
  /** Tool execution succeeded at the protocol level */
  success?: boolean
  /** Error message if failed */
  error?: string
  /** Raw output text */
  output?: string
  /** HTTP status code (for curl, web tools) */
  status_code?: number
  /** Response body length (for curl) */
  body_length?: number
  /** Open ports found (for nmap) */
  ports?: Array<{ port: number; state: string; service?: string }>
  /** Search results (for searchsploit, ffuf) */
  results?: unknown[]
  /** Credentials found (for hydra) */
  found_credentials?: boolean
  /** SQL injection vulnerable (for sqlmap) */
  vulnerable?: boolean
  /** Databases found (for sqlmap) */
  databases?: string[]
  /** Generic data field */
  data?: unknown
  /** Full result for tools that return structured data */
  [key: string]: unknown
}

/**
 * Parameters passed to a tool invocation
 */
export interface ToolParams {
  tool: string
  method?: string
  args: Record<string, unknown>
}

/**
 * Custom success criteria from registry.yaml
 */
interface SuccessCriteria {
  field: string
  operator: "exists" | "not_empty" | "length_gt" | "equals" | "contains"
  value?: unknown
}

/**
 * Result of recording an experience
 */
export interface RecordExperienceResult {
  /** The recorded experience (or null if deduplicated) */
  experience: Experience | null
  /** Whether this was a duplicate */
  isDuplicate: boolean
  /** Linked recovery info if this was a recovery from previous failure */
  linkedRecovery?: {
    previousExperienceId: string
    previousTool: string
  }
}

// =============================================================================
// Main Recording Function
// =============================================================================

/**
 * Record a tool execution experience to LanceDB
 *
 * Implements Doc 22 §Part 2 (lines 377-433)
 *
 * @param sessionId - Session ID for context lookup
 * @param params - Tool name, method, and arguments
 * @param output - Tool execution result
 * @param context - Tool context with search query and phase info
 * @returns The recorded experience, or null if deduplicated
 */
export async function recordExperience(
  sessionId: string,
  params: ToolParams,
  output: ToolResult,
  context: ToolContext
): Promise<RecordExperienceResult> {
  // Ensure database is initialized
  await initializeMemorySystem()

  // Track that this tool was tried
  recordToolTried(sessionId, params.tool)

  // Evaluate success using tool-specific heuristics
  const success = evaluateSuccess(params.tool, output, context)

  // Build the experience record
  const experienceId = generateExperienceId()
  const result_summary = summarizeResult(output)
  const failure_reason = success ? undefined : detectFailureReason(params.tool, output)

  // Check for recovery from previous failure
  const previousFailure = getPreviousFailure(sessionId)
  let recovery: Experience["outcome"]["recovery"] | undefined
  let linkedRecovery: RecordExperienceResult["linkedRecovery"]

  if (previousFailure && success) {
    // This successful execution recovered from a previous failure
    recovery = {
      tool: params.tool,
      method: params.method || "default",
      worked: true,
    }
    linkedRecovery = {
      previousExperienceId: previousFailure.experienceId,
      previousTool: previousFailure.tool,
    }

    log.info("linked recovery to previous failure", {
      sessionId: sessionId.slice(-8),
      recoveryTool: params.tool,
      failedTool: previousFailure.tool,
      failureReason: previousFailure.reason,
    })

    // Clear the previous failure since we've linked it
    clearPreviousFailure(sessionId)
  }

  // Build experience input
  const experienceInput = {
    id: experienceId,
    action: {
      query: context.lastSearchQuery || "",
      tool_selected: params.tool,
      tool_input: JSON.stringify(params.args),
    },
    outcome: {
      success,
      result_summary,
      failure_reason,
      recovery,
    },
    context: {
      phase: context.currentPhase || "unknown",
      target_characteristics: inferCharacteristics(context),
    },
  }

  // Generate embedding for semantic search
  const embeddingText = formatExperienceForEmbedding(experienceInput as Experience)
  const embeddingService = getEmbeddingService()
  const embedding = await embeddingService.embed(embeddingText)

  // Create the normalized experience record
  const experienceRecord = createExperience({
    ...experienceInput,
    vector: embedding?.dense ?? Array(VECTOR_DIMENSIONS).fill(0),
    sparse_json: serializeSparse(embedding?.sparse ?? null),
  })

  // Check for semantic duplicates (cosine similarity > 0.92)
  const isDuplicate = await checkForDuplicate(experienceRecord, embedding?.dense ?? null)

  if (isDuplicate) {
    log.info("experience deduplicated", {
      sessionId: sessionId.slice(-8),
      tool: params.tool,
      threshold: EXPERIENCE_DEDUP_THRESHOLD,
    })
    return { experience: null, isDuplicate: true }
  }

  // Store the experience
  const table = await getExperiencesTable()
  await table.add([experienceRecord])

  // Cast to Experience type for return
  const experience = experienceRecord as unknown as Experience

  // Update context based on outcome
  if (success) {
    recordToolSuccess(sessionId, params.tool)
  } else {
    // Record failure for potential recovery linking
    setFailureInContext(
      sessionId,
      experienceId,
      params.tool,
      failure_reason || "unknown"
    )
  }

  log.info("experience recorded", {
    sessionId: sessionId.slice(-8),
    id: experienceId.slice(-8),
    tool: params.tool,
    success,
    hasEmbedding: !!embedding,
  })

  return { experience, isDuplicate: false, linkedRecovery }
}

// =============================================================================
// Success Detection
// =============================================================================

/**
 * Evaluate tool success using tool-specific heuristics
 *
 * Implements Doc 22 §Part 2 (lines 487-543)
 *
 * Success is determined by:
 * 1. Custom criteria from registry (if defined)
 * 2. Explicit error field
 * 3. HTTP status codes
 * 4. Response size thresholds
 * 5. Tool-specific overrides for known tools
 */
export function evaluateSuccess(
  tool: string,
  output: ToolResult,
  context: ToolContext
): boolean {
  // Check if tool has custom success criteria in registry
  const toolDef = context.lastSearchResults?.find((t) => t.tool === tool)
  // Note: success_criteria would be added to SearchResult if tools define it
  const customCriteria = (toolDef as unknown as { success_criteria?: SuccessCriteria })
    ?.success_criteria

  if (customCriteria) {
    return evaluateCustomCriteria(customCriteria, output)
  }

  // Generic heuristics (MAST framework categories)

  // 1. Explicit error field
  if (output.error) return false

  // 2. HTTP-style status codes
  if (output.status_code !== undefined) {
    return output.status_code >= 200 && output.status_code < 400
  }

  // 3. Empty response detection
  if (output.body_length !== undefined && output.body_length < 50) {
    return false
  }

  // 4. Tool-specific overrides for known tools
  switch (tool) {
    case "curl":
      return (output.body_length ?? 0) > 200

    case "nmap":
      return (output.ports?.length ?? 0) > 0

    case "searchsploit":
      return (output.results?.length ?? 0) > 0

    case "hydra":
      return output.found_credentials === true

    case "sqlmap":
      return output.vulnerable === true || (output.databases?.length ?? 0) > 0

    case "ffuf":
      return (output.results?.length ?? 0) > 0

    case "nuclei":
      return (output.results?.length ?? 0) > 0

    case "nikto":
      return (output.results?.length ?? 0) > 0

    default:
      // Default: success if no error and has some output
      return !output.error && (output.output?.length ?? 0) > 0
  }
}

/**
 * Evaluate custom success criteria from registry
 *
 * Implements Doc 22 §Part 2 (lines 530-543)
 */
function evaluateCustomCriteria(
  criteria: SuccessCriteria,
  output: ToolResult
): boolean {
  const fieldValue = output[criteria.field]

  switch (criteria.operator) {
    case "exists":
      return fieldValue !== undefined
    case "not_empty":
      return fieldValue !== undefined && fieldValue !== null && fieldValue !== ""
    case "length_gt":
      return Array.isArray(fieldValue) && fieldValue.length > (criteria.value as number)
    case "equals":
      return fieldValue === criteria.value
    case "contains":
      return String(fieldValue).includes(String(criteria.value))
    default:
      return !output.error
  }
}

// =============================================================================
// Failure Detection
// =============================================================================

/**
 * Detect and categorize failure reason
 *
 * Implements Doc 22 §Part 2 (lines 545-559)
 *
 * Categories follow MAST framework patterns for security tool failures.
 */
export function detectFailureReason(tool: string, output: ToolResult): string {
  // Check error message patterns
  const error = output.error?.toLowerCase() || ""

  if (error.includes("timeout") || error.includes("timed out")) return "timeout"
  if (error.includes("connection refused")) return "connection_refused"
  if (error.includes("not found") || error.includes("404")) return "not_found"
  if (error.includes("permission") || error.includes("403")) return "permission_denied"
  if (error.includes("authentication") || error.includes("401")) return "auth_required"
  if (error.includes("rate limit") || error.includes("429")) return "rate_limited"
  if (error.includes("dns") || error.includes("resolve")) return "dns_error"
  if (error.includes("ssl") || error.includes("certificate")) return "ssl_error"

  // Tool-specific failure reasons
  switch (tool) {
    case "curl":
      if ((output.body_length ?? 0) < 100) return "empty_response"
      break
    case "nmap":
      if ((output.ports?.length ?? 0) === 0) return "no_open_ports"
      break
    case "searchsploit":
      if ((output.results?.length ?? 0) === 0) return "no_exploits_found"
      break
    case "ffuf":
      if ((output.results?.length ?? 0) === 0) return "no_paths_found"
      break
    case "hydra":
      if (!output.found_credentials) return "no_credentials_found"
      break
    case "sqlmap":
      if (!output.vulnerable) return "not_vulnerable"
      break
  }

  // Generic fallback
  if (output.error) return "tool_error"
  return "unknown"
}

// =============================================================================
// Result Summarization
// =============================================================================

/**
 * Summarize tool result for storage
 *
 * Implements Doc 22 §Part 2 (lines 436-440)
 *
 * Creates a brief description suitable for logging and embedding.
 */
export function summarizeResult(output: ToolResult): string {
  // Error case
  if (output.error) {
    return `Error: ${output.error.slice(0, 100)}`
  }

  // Structured results
  if (output.ports && Array.isArray(output.ports) && output.ports.length > 0) {
    const portList = output.ports
      .slice(0, 5)
      .map((p) => `${p.port}/${p.service || "unknown"}`)
      .join(", ")
    return `Found ${output.ports.length} ports: ${portList}${output.ports.length > 5 ? "..." : ""}`
  }

  if (output.results && Array.isArray(output.results)) {
    return `Found ${output.results.length} result(s)`
  }

  if (output.databases && Array.isArray(output.databases)) {
    return `Found ${output.databases.length} database(s): ${output.databases.slice(0, 3).join(", ")}`
  }

  if (output.found_credentials) {
    return "Found valid credentials"
  }

  if (output.vulnerable) {
    return "Target is vulnerable"
  }

  // Text output
  if (output.output && typeof output.output === "string") {
    return output.output.slice(0, 200)
  }

  // Fallback to JSON
  return JSON.stringify(output).slice(0, 200)
}

// =============================================================================
// Embedding Format
// =============================================================================

/**
 * Format experience for embedding generation
 *
 * Implements Doc 22 §Part 2 (lines 452-481)
 *
 * Creates a text representation that captures the full context,
 * following LangMem's episodic memory pattern.
 */
export function formatExperienceForEmbedding(exp: Experience): string {
  const parts: string[] = []

  // Core action
  if (exp.action.query) {
    parts.push(`Query: ${exp.action.query}`)
  }
  parts.push(`Tool: ${exp.action.tool_selected}`)
  parts.push(`Result: ${exp.outcome.success ? "success" : "failure"}`)

  // Failure details
  if (exp.outcome.failure_reason) {
    parts.push(`Failure: ${exp.outcome.failure_reason}`)
  }

  // Recovery info
  if (exp.outcome.recovery && exp.outcome.recovery.tool) {
    parts.push(`Recovery: switched to ${exp.outcome.recovery.tool}`)
    parts.push(`Recovery worked: ${exp.outcome.recovery.worked}`)
  }

  // Context
  if (exp.context.phase && exp.context.phase !== "unknown") {
    parts.push(`Phase: ${exp.context.phase}`)
  }

  if (exp.context.target_characteristics && exp.context.target_characteristics.length > 0) {
    parts.push(`Context: ${exp.context.target_characteristics.join(", ")}`)
  }

  return parts.join(". ")
}

// =============================================================================
// Characteristic Inference
// =============================================================================

/**
 * Infer target characteristics from context
 *
 * Implements Doc 22 §Part 2 (lines 442-450)
 *
 * Builds up a list of characteristics based on observed behavior.
 */
export function inferCharacteristics(context: ToolContext): string[] {
  const chars: string[] = []

  // Infer from previous tool failures
  const previousFailure = context.previousFailure
  if (previousFailure) {
    switch (previousFailure.reason) {
      case "empty_response":
        chars.push("possible_javascript_page")
        break
      case "timeout":
        chars.push("slow_target")
        break
      case "rate_limited":
        chars.push("rate_limiting_enabled")
        break
      case "auth_required":
        chars.push("requires_authentication")
        break
      case "ssl_error":
        chars.push("ssl_issues")
        break
    }
  }

  // Could extend to infer from successful tool results:
  // - Web fingerprinting results
  // - Technology detection
  // - Port scan results

  return chars
}

// =============================================================================
// Deduplication
// =============================================================================

/**
 * Check if an experience is a semantic duplicate
 *
 * Implements Doc 22 REQ-MEM-010 (deduplication threshold: 0.92)
 *
 * Uses cosine similarity via LanceDB vector search.
 */
async function checkForDuplicate(
  experience: Record<string, unknown>,
  vector: number[] | null
): Promise<boolean> {
  if (!vector) {
    // No embedding available, can't check for duplicates
    return false
  }

  try {
    const table = await getExperiencesTable()

    // Search for similar experiences
    const similar = await table
      .search(vector)
      .limit(1)
      .toArray()

    if (similar.length === 0) {
      return false
    }

    // LanceDB returns _distance (L2) not _score (cosine similarity)
    // For normalized vectors, we can convert: similarity ≈ 1 - (distance² / 2)
    // But LanceDB also supports metric="cosine" which returns 1 - similarity
    // So we need to check if the distance is below threshold
    const mostSimilar = similar[0] as { _distance?: number }

    // With cosine distance, lower is more similar
    // _distance of 0 = identical, _distance of 2 = opposite
    // We want similarity > 0.92, so distance < 2 * (1 - 0.92) = 0.16
    const distanceThreshold = 2 * (1 - EXPERIENCE_DEDUP_THRESHOLD)
    const isDuplicate = (mostSimilar._distance ?? Infinity) < distanceThreshold

    return isDuplicate
  } catch (error) {
    log.warn("deduplication check failed", { error: String(error) })
    return false
  }
}

// =============================================================================
// Recovery Linking
// =============================================================================

/**
 * Link a successful experience to a previous failure (FUTURE IMPLEMENTATION)
 *
 * Implements Doc 22 §Part 2 (lines 215-264) - ToolContext flow
 *
 * Currently, recovery linking is handled within recordExperience():
 * - When a success follows a failure, the recovery info is stored in the
 *   successful experience's outcome.recovery field
 * - The previousExperienceId links back to the failed experience
 *
 * This function is a placeholder for future enhancement where we would
 * also update the failed experience record to point to its recovery.
 * LanceDB updates require read-modify-reinsert, which is complex.
 *
 * @internal Not exported - use recordExperience() for recovery linking
 */
async function linkRecoveryToFailure(
  failedExperienceId: string,
  recoveryTool: string,
  recoveryMethod: string
): Promise<void> {
  // Future: Update the failed experience to point to its recovery
  // For now, correlation is done via the recovery experience's linkedRecovery field
  log.info("recovery pattern detected", {
    failedExperienceId: failedExperienceId.slice(-8),
    recoveryTool,
    recoveryMethod,
  })
}

// =============================================================================
// Query Functions
// =============================================================================

/**
 * Sanitize tool name to prevent SQL injection
 *
 * Tool names should only contain alphanumeric characters, underscores, and hyphens.
 */
function sanitizeToolName(tool: string): string {
  if (!/^[a-zA-Z0-9_-]+$/.test(tool)) {
    throw new Error(`Invalid tool name: ${tool.slice(0, 50)}`)
  }
  return tool
}

/**
 * Get experiences by tool name
 *
 * Useful for analyzing tool-specific patterns.
 */
export async function getExperiencesByTool(
  tool: string,
  limit: number = 100
): Promise<Experience[]> {
  const safeTool = sanitizeToolName(tool)
  const table = await getExperiencesTable()
  const results = await table
    .query()
    .where(`action.tool_selected = '${safeTool}'`)
    .limit(limit)
    .toArray()

  return results as unknown as Experience[]
}

/**
 * Get recent experiences
 */
export async function getRecentExperiences(limit: number = 50): Promise<Experience[]> {
  const table = await getExperiencesTable()
  // Note: LanceDB doesn't have direct ORDER BY, but newest are typically at end
  const results = await table.query().limit(limit).toArray()
  return results as unknown as Experience[]
}

/**
 * Search experiences by semantic similarity
 */
export async function searchExperiences(
  query: string,
  limit: number = 10
): Promise<Array<Experience & { _distance: number }>> {
  const embeddingService = getEmbeddingService()
  const embedding = await embeddingService.embed(query)

  if (!embedding) {
    log.warn("embedding unavailable for experience search")
    return []
  }

  const table = await getExperiencesTable()
  const results = await table
    .search(embedding.dense)
    .limit(limit)
    .toArray()

  return results as unknown as Array<Experience & { _distance: number }>
}

/**
 * Get experiences with recovery patterns
 *
 * Used for insight extraction (Phase 6)
 */
export async function getRecoveryPatterns(): Promise<Experience[]> {
  const table = await getExperiencesTable()
  // Filter for experiences that have recovery info
  const results = await table
    .query()
    .where("outcome.recovery.tool != ''")
    .toArray()

  return results as unknown as Experience[]
}
