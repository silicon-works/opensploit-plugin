/**
 * Pattern Capture Module
 *
 * Implements Doc 13 §Pattern Capture (lines 700-820)
 *
 * Captures attack patterns when engagement achieves access.
 * Patterns are stored in LanceDB for later similarity search.
 *
 * Trigger conditions:
 * 1. Session achieves user or root access (automatic)
 * 2. User explicitly saves via /save-pattern command
 * 3. Session marked as successful by user
 */

import { createLog } from "../util/log"
import type { EngagementState, StateSnapshot } from "../tools/engagement-state"
import { loadEngagementState, getStateSnapshots } from "../tools/engagement-state"
import { Trajectory } from "../session/trajectory"
import {
  getPatternsTable,
  getEmbeddingService,
  createPattern,
  generatePatternId,
  PATTERN_DEDUP_THRESHOLD,
  type AttackPattern,
} from "../memory"
import { formatPatternForEmbedding } from "./search"
import {
  detectOS,
  extractTechnologies,
  inferCharacteristics,
  extractPrimaryVulnerability,
  detectPivotalSteps,
  generateMethodologySummary,
  extractPhases,
  extractToolSequence,
  extractInsights,
  calculateDuration,
} from "./extract"
import { anonymizePattern } from "./anonymize"

const log = createLog("pattern.capture")

// =============================================================================
// Types
// =============================================================================

export interface CaptureOptions {
  /** Whether capture was triggered by user command (vs automatic) */
  userTriggered?: boolean
  /** Model used for the engagement */
  model?: string
  /** Engagement type (htb, vulnhub, real) */
  engagementType?: string
}

export interface CaptureResult {
  success: boolean
  pattern?: AttackPattern
  message: string
  /** If duplicate, the ID of the existing similar pattern */
  duplicateOf?: string
}

// =============================================================================
// Main Capture Function
// =============================================================================

/**
 * Capture an attack pattern from a session
 * Doc 13 §capturePattern (lines 712-769)
 *
 * @param sessionID - Session to capture pattern from
 * @param options - Capture options
 * @returns CaptureResult with success status and pattern or error message
 */
export async function capturePattern(sessionID: string, options: CaptureOptions = {}): Promise<CaptureResult> {
  log.info("capturing pattern", { sessionID, userTriggered: options.userTriggered })

  try {
    // Load engagement state
    const state = await loadEngagementState(sessionID)
    if (!state) {
      return {
        success: false,
        message: "No engagement state found for session",
      }
    }

    // Only capture successful sessions (user or root access)
    const accessLevel = state.accessLevel ?? "none"
    if (accessLevel === "none") {
      if (options.userTriggered) {
        return {
          success: false,
          message: "Cannot save pattern: no access achieved yet. Achieve user or root access first.",
        }
      }
      return {
        success: false,
        message: "Session has not achieved access",
      }
    }

    // Get trajectory from full session tree (includes sub-agent data)
    const trajectory = await Trajectory.fromSessionTree(sessionID)
    if (!trajectory) {
      return {
        success: false,
        message: "No trajectory data found for session",
      }
    }

    // Get state snapshots for pivotal step detection
    const stateSnapshots = await getStateSnapshots(sessionID)

    // Extract pattern
    const pattern = await extractPattern(sessionID, state, trajectory, stateSnapshots, options)

    // Generate embedding
    const embeddingService = getEmbeddingService()
    const embeddingText = formatPatternForEmbedding(pattern)
    const embedding = await embeddingService.embed(embeddingText)

    if (!embedding) {
      log.warn("could not generate embedding for pattern")
      return {
        success: false,
        message: "Could not generate embedding for pattern. Embedding service may be unavailable.",
      }
    }

    pattern.vector = embedding.dense

    // Check for duplicates
    const table = await getPatternsTable()
    const similar = await table
      .search(embedding.dense)
      .where("outcome.success = true")
      .limit(1)
      .toArray()

    if (similar.length > 0) {
      const record = similar[0] as Record<string, unknown>
      const distance = record._distance as number | undefined
      // Convert distance to similarity (lower distance = higher similarity)
      const similarity = distance !== undefined ? Math.max(0, 1 - distance / 2) : 0

      if (similarity > PATTERN_DEDUP_THRESHOLD) {
        const existingId = record.id as string
        log.info("similar pattern already exists", { similarity: similarity.toFixed(3), existingId })
        return {
          success: false,
          message: `Similar pattern already exists (similarity: ${(similarity * 100).toFixed(1)}%)`,
          duplicateOf: existingId,
        }
      }
    }

    // Anonymize pattern before storage (Doc 13 §Anonymization lines 825-900)
    const anonymized = anonymizePattern(pattern)
    anonymized.vector = pattern.vector // Preserve the embedding vector

    // Store anonymized pattern
    const patternRecord = createPattern(anonymized)
    await table.add([patternRecord])

    log.info("pattern captured successfully", { patternId: anonymized.id, accessLevel, anonymized: true })

    return {
      success: true,
      pattern: anonymized,
      message: `Pattern captured: ${anonymized.methodology.summary}`,
    }
  } catch (error) {
    log.error("pattern capture failed", { error: String(error) })
    return {
      success: false,
      message: `Failed to capture pattern: ${error}`,
    }
  }
}

// =============================================================================
// Pattern Extraction
// =============================================================================

/**
 * Extract pattern data from session, state, and trajectory
 * Doc 13 §extractPattern (lines 771-820)
 */
async function extractPattern(
  sessionID: string,
  state: EngagementState,
  trajectory: Trajectory.Data,
  stateSnapshots: StateSnapshot[],
  options: CaptureOptions
): Promise<AttackPattern> {
  // Detect pivotal steps via state changes
  const pivotalStepIndices = detectPivotalSteps(trajectory, stateSnapshots)

  log.debug("detected pivotal steps", { count: pivotalStepIndices.size, indices: Array.from(pivotalStepIndices) })

  // Extract target profile from state
  const ports = state.ports ?? []
  const target_profile: AttackPattern["target_profile"] = {
    os: detectOS(state),
    services: ports.map((p) => p.service).filter((s): s is string => !!s),
    ports: ports.map((p) => p.port).filter((p): p is number => typeof p === "number"),
    technologies: extractTechnologies(state),
    characteristics: inferCharacteristics(trajectory),
  }

  // Find the primary vulnerability exploited
  const vulnerability = extractPrimaryVulnerability(state, trajectory)

  // Build methodology from trajectory using pivotal step detection
  const methodology: AttackPattern["methodology"] = {
    summary: generateMethodologySummary(trajectory, state, pivotalStepIndices),
    phases: extractPhases(trajectory, pivotalStepIndices),
    tools_sequence: extractToolSequence(trajectory),
    key_insights: extractInsights(trajectory, pivotalStepIndices),
  }

  // Build outcome
  const outcome: AttackPattern["outcome"] = {
    success: true,
    access_achieved: (state.accessLevel ?? "none") as "none" | "user" | "root",
    time_to_access_minutes: calculateDuration(trajectory),
    flags_captured: state.flags?.length ?? 0,
  }

  // Build metadata
  const metadata: AttackPattern["metadata"] = {
    source: "local",
    created_at: new Date().toISOString(),
    session_id: sessionID,
    model_used: options.model ?? trajectory.model,
    engagement_type: options.engagementType,
    anonymized: false, // Will be anonymized in Phase 4
    confidence: 1.0, // Start at full confidence (P2 field)
    access_count: 0,
  }

  return {
    id: generatePatternId(),
    target_profile,
    vulnerability,
    methodology,
    outcome,
    metadata,
    vector: [], // Set after embedding generation
  }
}

// =============================================================================
// Auto-Capture Hook
// =============================================================================

/**
 * Check if pattern should be auto-captured based on state change
 * Called when engagement state is updated.
 *
 * @param sessionID - Session to check
 * @param previousAccessLevel - Previous access level
 * @param newAccessLevel - New access level
 * @returns true if pattern was captured
 */
export async function checkAutoCapturePattern(
  sessionID: string,
  previousAccessLevel: "none" | "user" | "root" | undefined,
  newAccessLevel: "none" | "user" | "root" | undefined
): Promise<boolean> {
  const prev = previousAccessLevel ?? "none"
  const curr = newAccessLevel ?? "none"

  // Only auto-capture on access level increase
  const accessOrder: Record<string, number> = { none: 0, user: 1, root: 2 }
  if (accessOrder[curr] <= accessOrder[prev]) {
    return false
  }

  log.info("auto-capture triggered", { sessionID, from: prev, to: curr })

  const result = await capturePattern(sessionID, { userTriggered: false })

  if (result.success) {
    log.info("auto-captured pattern", { patternId: result.pattern?.id })
  } else if (result.duplicateOf) {
    log.debug("pattern already exists", { duplicateOf: result.duplicateOf })
  }

  return result.success
}
