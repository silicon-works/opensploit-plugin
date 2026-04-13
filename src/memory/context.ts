/**
 * Tool Context
 *
 * Implements Doc 22 §Agent Loop Integration (lines 185-267)
 *
 * Provides shared state across tool calls within a session for:
 * - Tracking what tools have been tried
 * - Linking failures to subsequent recoveries
 * - Recording the last search query for experience attribution
 * - Tracking successful tools for recency bonuses
 *
 * The context is session-scoped and persists in memory during the session.
 */

import { createLog } from "../util/log"

const log = createLog("memory.context")

// =============================================================================
// Constants
// =============================================================================

/** Maximum number of tools to track in toolsTried and recentSuccesses */
const MAX_TOOLS_TRACKED = 100

/** Session timeout in milliseconds (30 minutes) */
const SESSION_TIMEOUT_MS = 30 * 60 * 1000

/** Cleanup interval in milliseconds (5 minutes) */
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000

/** Previous failure information for recovery linking */
export interface PreviousFailure {
  /** The experience ID of the failed attempt */
  experienceId: string
  /** The tool that failed */
  tool: string
  /** The reason for failure */
  reason: string
}

/** Tool search result (subset of full registry tool) */
export interface SearchResult {
  tool: string
  method?: string
  score: number
  description?: string
}

/**
 * Tool Context - shared state for experience collection
 *
 * Following the pattern from OpenAI Agents SDK (context as dependency injection)
 * and Google ADK (state tracking in callbacks).
 */
export interface ToolContext {
  /** The last query sent to tool_registry_search */
  lastSearchQuery: string | null

  /** Results from the last tool search */
  lastSearchResults: SearchResult[]

  /** Current pentest phase (recon, enum, exploit, post) */
  currentPhase: string | null

  /** Tools that have been invoked in this session (bounded to MAX_TOOLS_TRACKED) */
  toolsTried: string[]

  /** Tools that succeeded recently (for recency bonus, bounded to MAX_TOOLS_TRACKED) */
  recentSuccesses: string[]

  /** Information about the most recent failure (for recovery linking) */
  previousFailure: PreviousFailure | null

  /** Last time this context was accessed (for cleanup) */
  lastAccessTime: number
}

/** Create a fresh ToolContext */
export function createToolContext(): ToolContext {
  return {
    lastSearchQuery: null,
    lastSearchResults: [],
    currentPhase: null,
    toolsTried: [],
    recentSuccesses: [],
    previousFailure: null,
    lastAccessTime: Date.now(),
  }
}

// Session-scoped context storage (in-memory)
const sessionContexts = new Map<string, ToolContext>()

// Cleanup interval handle
let cleanupInterval: ReturnType<typeof setInterval> | null = null

/**
 * Start the cleanup interval for stale sessions.
 * Called automatically on first context access.
 */
function ensureCleanupStarted(): void {
  if (cleanupInterval !== null) return

  cleanupInterval = setInterval(() => {
    const now = Date.now()
    let cleanedCount = 0

    for (const [sessionId, context] of sessionContexts.entries()) {
      if (now - context.lastAccessTime > SESSION_TIMEOUT_MS) {
        sessionContexts.delete(sessionId)
        cleanedCount++
      }
    }

    if (cleanedCount > 0) {
      log.info("cleaned up stale session contexts", { count: cleanedCount })
    }
  }, CLEANUP_INTERVAL_MS)

  // Don't prevent process exit
  if (cleanupInterval.unref) {
    cleanupInterval.unref()
  }
}

/**
 * Stop the cleanup interval (for testing or shutdown).
 */
export function stopCleanupInterval(): void {
  if (cleanupInterval !== null) {
    clearInterval(cleanupInterval)
    cleanupInterval = null
  }
}

/**
 * Get the ToolContext for a session.
 * Creates a new context if one doesn't exist.
 */
export function getToolContext(sessionId: string): ToolContext {
  // Start cleanup if not already running
  ensureCleanupStarted()

  let context = sessionContexts.get(sessionId)
  if (!context) {
    context = createToolContext()
    sessionContexts.set(sessionId, context)
    log.info("created new tool context", { sessionId: sessionId.slice(-8) })
  }

  // Update last access time
  context.lastAccessTime = Date.now()
  return context
}

/**
 * Update the ToolContext after a tool search.
 */
export function updateSearchContext(
  sessionId: string,
  query: string,
  results: SearchResult[]
): void {
  const context = getToolContext(sessionId)
  context.lastSearchQuery = query
  context.lastSearchResults = results
  log.info("updated search context", {
    sessionId: sessionId.slice(-8),
    query: query.slice(0, 50),
    resultCount: results.length,
  })
}

/**
 * Record that a tool was tried.
 * Maintains a bounded list (evicts oldest when full).
 */
export function recordToolTried(sessionId: string, tool: string): void {
  const context = getToolContext(sessionId)
  if (!context.toolsTried.includes(tool)) {
    // Evict oldest if at capacity
    if (context.toolsTried.length >= MAX_TOOLS_TRACKED) {
      context.toolsTried.shift()
    }
    context.toolsTried.push(tool)
  }
}

/**
 * Record a tool success.
 * Maintains a bounded list (evicts oldest when full).
 */
export function recordToolSuccess(sessionId: string, tool: string): void {
  const context = getToolContext(sessionId)
  if (!context.recentSuccesses.includes(tool)) {
    // Evict oldest if at capacity
    if (context.recentSuccesses.length >= MAX_TOOLS_TRACKED) {
      context.recentSuccesses.shift()
    }
    context.recentSuccesses.push(tool)
  }
}

/**
 * Record a tool failure for potential recovery linking.
 */
export function recordToolFailure(
  sessionId: string,
  experienceId: string,
  tool: string,
  reason: string
): void {
  const context = getToolContext(sessionId)
  context.previousFailure = { experienceId, tool, reason }
  log.info("recorded tool failure", {
    sessionId: sessionId.slice(-8),
    tool,
    reason,
    experienceId: experienceId.slice(-8),
  })
}

/**
 * Clear the previous failure (called after successful recovery linking).
 */
export function clearPreviousFailure(sessionId: string): void {
  const context = getToolContext(sessionId)
  context.previousFailure = null
}

/**
 * Get the previous failure for recovery linking.
 */
export function getPreviousFailure(sessionId: string): PreviousFailure | null {
  return getToolContext(sessionId).previousFailure
}

/**
 * Set the current pentest phase.
 */
export function setCurrentPhase(sessionId: string, phase: string): void {
  const context = getToolContext(sessionId)
  context.currentPhase = phase
  log.info("set current phase", { sessionId: sessionId.slice(-8), phase })
}

/**
 * Clean up context when session ends.
 */
export function clearToolContext(sessionId: string): void {
  sessionContexts.delete(sessionId)
  log.info("cleared tool context", { sessionId: sessionId.slice(-8) })
}

/**
 * Get context summary for logging/debugging.
 */
export function getContextSummary(sessionId: string): Record<string, unknown> {
  const context = getToolContext(sessionId)
  return {
    hasLastSearch: context.lastSearchQuery !== null,
    lastSearchResultCount: context.lastSearchResults.length,
    currentPhase: context.currentPhase,
    toolsTriedCount: context.toolsTried.length,
    recentSuccessCount: context.recentSuccesses.length,
    hasPreviousFailure: context.previousFailure !== null,
  }
}
