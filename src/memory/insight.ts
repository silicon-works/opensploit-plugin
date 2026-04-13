/**
 * Insight Extraction and Management
 *
 * Implements Doc 22 §Part 3 (lines 564-818)
 *
 * Phase 6 provides:
 * - Export recovery patterns to YAML for Claude Code analysis
 * - Import approved insights from YAML to LanceDB
 * - Automated confidence updates (reinforce/contradict)
 * - Temporal decay (2% per day if not reinforced)
 *
 * Workflow:
 * 1. Experiences accumulate during engagements
 * 2. At engagement end, exportForAnalysis() exports recovery patterns
 * 3. User runs Claude Code to analyze patterns and suggest insights
 * 4. User approves → importInsights() imports to LanceDB
 * 5. updateInsightConfidences() runs automatically to adjust confidence
 * 6. applyConfidenceDecay() runs periodically for temporal decay
 */

import * as fs from "fs/promises"
import * as path from "path"
import * as os from "os"
import yaml from "js-yaml"
import { createLog } from "../util/log"
import { getExperiencesTable, getInsightsTable, initializeMemorySystem } from "./database"
import { getEmbeddingService } from "./embedding"
import { createInsight, type Experience, type Insight, VECTOR_DIMENSIONS } from "./schema"
import { serializeSparse } from "./sparse"

const log = createLog("memory.insight")

// =============================================================================
// Constants
// =============================================================================

/** Directory for pending analysis files */
export const PENDING_ANALYSIS_DIR = path.join(os.homedir(), ".opensploit", "pending_analysis")

/** Minimum occurrences before a pattern is exported (prevents one-off flukes) */
export const MIN_PATTERN_OCCURRENCES = 2

/** Confidence lifecycle constants (from Doc 22 §Part 3 lines 590-595) */
export const CONFIDENCE_INITIAL = 0.5
export const CONFIDENCE_REINFORCE_DELTA = 0.1
export const CONFIDENCE_CONTRADICT_DELTA = 0.15
export const CONFIDENCE_MIN = 0.1
export const CONFIDENCE_MAX = 1.0
export const CONFIDENCE_DELETE_THRESHOLD = 0.15
export const CONTRADICTIONS_DELETE_THRESHOLD = 2

/** Temporal decay constants */
export const DECAY_FACTOR = 0.98 // γ per day (2% decay)
export const DECAY_INTERVAL_MS = 24 * 60 * 60 * 1000 // 24 hours

// =============================================================================
// Types
// =============================================================================

/** Recovery pattern extracted from experience */
export interface RecoveryPattern {
  query: string
  failed_tool: string
  failure_reason: string | null
  recovery_tool: string
  recovery_method: string
  context: {
    phase: string
    target_characteristics?: string[]
  }
  experience_ids: string[]
  occurrences: number
}

/** Exported batch for Claude Code analysis */
export interface ExportedBatch {
  exported_at: string
  min_occurrences: number
  total_patterns: number
  patterns: Array<{
    query: string
    failed_tool: string
    failure_reason: string | null
    recovery_tool: string
    context: {
      phase: string
      target_characteristics?: string[]
    }
    occurrences: number
  }>
}

/** Insight suggestion from YAML */
export interface InsightSuggestion {
  rule: string
  suggestion: {
    prefer: string
    over?: string
    when: string
  }
}

/** Imported insights YAML format */
export interface ImportedInsights {
  insights: InsightSuggestion[]
}

/** Result of confidence update */
export interface ConfidenceUpdateResult {
  reinforced: number
  contradicted: number
  deleted: number
  unchanged: number
}

/** Result of decay application */
export interface DecayResult {
  decayed: number
  deleted: number
  unchanged: number
}

// =============================================================================
// Export for Analysis
// =============================================================================

/**
 * Ensure pending analysis directory exists
 */
async function ensurePendingAnalysisDir(): Promise<void> {
  try {
    await fs.mkdir(PENDING_ANALYSIS_DIR, { recursive: true })
  } catch {
    // Directory may already exist
  }
}

/**
 * Validate insight ID format to prevent SQL injection
 * Valid IDs match: ins_{timestamp}_{random} pattern
 */
function validateInsightId(id: string): boolean {
  // IDs should only contain alphanumeric chars and underscores
  return /^ins_[a-zA-Z0-9_]+$/.test(id)
}

/**
 * Safely delete an insight by ID with validation
 * @throws Error if ID format is invalid
 */
async function safeDeleteInsight(insTable: Awaited<ReturnType<typeof getInsightsTable>>, id: string): Promise<void> {
  if (!validateInsightId(id)) {
    throw new Error(`Invalid insight ID format: ${id.slice(0, 50)}`)
  }
  await insTable.delete(`id = '${id}'`)
}

/**
 * Safely update an insight (delete + re-add with rollback on failure)
 * Uses delete+add since LanceDB doesn't support in-place updates
 */
async function safeUpdateInsight(
  insTable: Awaited<ReturnType<typeof getInsightsTable>>,
  oldId: string,
  newInsight: Record<string, unknown>
): Promise<void> {
  if (!validateInsightId(oldId)) {
    throw new Error(`Invalid insight ID format: ${oldId.slice(0, 50)}`)
  }

  // Delete first
  await insTable.delete(`id = '${oldId}'`)

  try {
    // Then add the updated insight
    await insTable.add([newInsight])
  } catch (error) {
    // Rollback: try to restore the old insight if add fails
    // This is best-effort - if it also fails, we log and rethrow
    log.error("failed to add updated insight, data may be lost", {
      id: oldId,
      error: String(error),
    })
    throw error
  }
}

/**
 * Convert Arrow vector types to plain JavaScript arrays
 * LanceDB returns Apache Arrow types that need conversion for YAML serialization
 */
function toPlainArray(arr: unknown): string[] | undefined {
  if (!arr) return undefined
  if (Array.isArray(arr)) return arr.map(String)
  // Handle Arrow vector types (they have toArray method)
  if (typeof arr === "object" && "toArray" in arr && typeof (arr as { toArray: unknown }).toArray === "function") {
    return (arr as { toArray: () => unknown[] }).toArray().map(String)
  }
  // Handle iterable objects
  if (typeof arr === "object" && Symbol.iterator in arr) {
    return Array.from(arr as Iterable<unknown>).map(String)
  }
  return undefined
}

/**
 * Export experiences with recovery patterns for Claude Code analysis
 *
 * Implements Doc 22 §Part 3 (lines 610-652)
 *
 * Only exports patterns that occurred 2+ times to prevent one-off flukes
 * from becoming insights.
 *
 * @returns Path to exported YAML file
 */
export async function exportForAnalysis(): Promise<string> {
  await ensurePendingAnalysisDir()
  await initializeMemorySystem()

  const expTable = await getExperiencesTable()

  // Get all experiences with successful recovery patterns
  const allExperiences = await expTable.query().toArray()

  // Filter to experiences with working recovery patterns
  const recoveryPatterns = allExperiences.filter((exp) => {
    const e = exp as unknown as Experience
    return (
      e.outcome.recovery &&
      e.outcome.recovery.tool &&
      e.outcome.recovery.worked === true
    )
  }) as unknown as Experience[]

  log.info("found recovery patterns", { count: recoveryPatterns.length })

  // Group by pattern key (failed_tool → recovery_tool)
  const patternGroups = new Map<string, Experience[]>()
  for (const exp of recoveryPatterns) {
    const key = `${exp.action.tool_selected}→${exp.outcome.recovery!.tool}`
    if (!patternGroups.has(key)) {
      patternGroups.set(key, [])
    }
    patternGroups.get(key)!.push(exp)
  }

  // Only include patterns seen MIN_PATTERN_OCCURRENCES+ times
  const qualifyingPatterns: RecoveryPattern[] = []
  for (const [key, experiences] of patternGroups) {
    if (experiences.length >= MIN_PATTERN_OCCURRENCES) {
      // Use first experience as representative
      const rep = experiences[0]
      qualifyingPatterns.push({
        query: String(rep.action.query),
        failed_tool: String(rep.action.tool_selected),
        failure_reason: rep.outcome.failure_reason ? String(rep.outcome.failure_reason) : null,
        recovery_tool: String(rep.outcome.recovery!.tool),
        recovery_method: String(rep.outcome.recovery!.method),
        context: {
          phase: String(rep.context.phase),
          target_characteristics: toPlainArray(rep.context.target_characteristics),
        },
        experience_ids: experiences.map((e) => String(e.id)),
        occurrences: experiences.length,
      })
    }
  }

  log.info("qualifying patterns for export", {
    total: patternGroups.size,
    qualifying: qualifyingPatterns.length,
    minOccurrences: MIN_PATTERN_OCCURRENCES,
  })

  // Build export data
  const exportData: ExportedBatch = {
    exported_at: new Date().toISOString(),
    min_occurrences: MIN_PATTERN_OCCURRENCES,
    total_patterns: qualifyingPatterns.length,
    patterns: qualifyingPatterns.map((p) => ({
      query: p.query,
      failed_tool: p.failed_tool,
      failure_reason: p.failure_reason,
      recovery_tool: p.recovery_tool,
      context: p.context,
      occurrences: p.occurrences,
    })),
  }

  // Write to file
  const dateStr = new Date().toISOString().split("T")[0]
  const filename = `batch_${dateStr}.yaml`
  const filepath = path.join(PENDING_ANALYSIS_DIR, filename)

  await fs.writeFile(filepath, yaml.dump(exportData, { lineWidth: 120 }), "utf-8")

  log.info("exported patterns for analysis", { filepath, patterns: qualifyingPatterns.length })

  return filepath
}

/**
 * Get Claude Code analysis prompt for the exported patterns
 *
 * @param filepath Path to exported YAML file
 * @returns Prompt text for Claude Code
 */
export function getAnalysisPrompt(filepath: string): string {
  return `Analyze the recovery patterns in ${filepath}

For each pattern, suggest an insight in this YAML format:

insights:
  - rule: "Brief, actionable insight (1-2 sentences)"
    suggestion:
      prefer: "tool_to_use"
      over: "tool_to_avoid"  # optional, only if pattern shows clear alternative
      when: "context description"

Guidelines:
- Focus on generalizable patterns, not one-off cases
- The "when" clause should describe the context where this preference applies
- Only include "over" if the pattern clearly shows one tool failing and another succeeding
- Rules should be actionable and specific

Save your output to ${filepath.replace(".yaml", "_insights.yaml")}`
}

// =============================================================================
// Import Insights
// =============================================================================

/**
 * Import approved insights from YAML to LanceDB
 *
 * Implements Doc 22 §Part 3 (lines 672-694)
 *
 * @param filepath Path to YAML file with insights
 * @returns Number of insights imported
 */
export async function importInsights(filepath: string): Promise<number> {
  await initializeMemorySystem()

  // Read and parse YAML
  const content = await fs.readFile(filepath, "utf-8")
  const data = yaml.load(content) as ImportedInsights

  if (!data.insights || !Array.isArray(data.insights)) {
    throw new Error("Invalid insights file: missing 'insights' array")
  }

  const embeddingService = getEmbeddingService()
  const insTable = await getInsightsTable()

  let imported = 0
  for (const suggestion of data.insights) {
    // Validate required fields
    if (!suggestion.rule || !suggestion.suggestion?.prefer || !suggestion.suggestion?.when) {
      log.warn("skipping invalid insight", { suggestion })
      continue
    }

    // Generate embedding for the rule
    const embedding = await embeddingService.embed(suggestion.rule)
    const vector = embedding?.dense ?? Array(VECTOR_DIMENSIONS).fill(0)

    // Create insight record
    const insight = createInsight({
      rule: suggestion.rule,
      confidence: CONFIDENCE_INITIAL,
      contradictions: 0,
      suggestion: {
        prefer: suggestion.suggestion.prefer,
        over: suggestion.suggestion.over,
        when: suggestion.suggestion.when,
      },
      created_from: [],
      vector,
      sparse_json: serializeSparse(embedding?.sparse ?? null),
    })

    await insTable.add([insight])
    imported++

    log.info("imported insight", {
      id: insight.id,
      prefer: suggestion.suggestion.prefer,
      hasEmbedding: embedding?.dense !== undefined,
    })
  }

  log.info("import complete", { filepath, imported, total: data.insights.length })

  return imported
}

// =============================================================================
// Confidence Management
// =============================================================================

/**
 * Check if a pattern reinforces an insight
 *
 * Implements Doc 22 §Part 3 (lines 750-758)
 *
 * Pattern reinforces if:
 * - Recovery tool matches suggestion.prefer
 * - Failed tool matches suggestion.over (if specified)
 * - Recovery actually worked
 */
export function patternReinforcesInsight(insight: Insight, experience: Experience): boolean {
  if (!experience.outcome.recovery?.worked) {
    return false
  }

  const recoveryMatches = experience.outcome.recovery.tool === insight.suggestion.prefer

  // If insight specifies "over", the failed tool must match
  const failedMatches =
    !insight.suggestion.over || experience.action.tool_selected === insight.suggestion.over

  return recoveryMatches && failedMatches
}

/**
 * Helper function to get date N days ago
 */
function daysAgo(n: number): Date {
  return new Date(Date.now() - n * DECAY_INTERVAL_MS)
}

/**
 * Update insight confidences based on recent experiences
 *
 * Implements Doc 22 §Part 3 (lines 706-748)
 *
 * Run at end of engagement or nightly.
 *
 * @param lookbackDays Number of days to look back for recent patterns (default: 7)
 * @returns Summary of updates made
 */
export async function updateInsightConfidences(lookbackDays: number = 7): Promise<ConfidenceUpdateResult> {
  await initializeMemorySystem()

  const expTable = await getExperiencesTable()
  const insTable = await getInsightsTable()

  const result: ConfidenceUpdateResult = {
    reinforced: 0,
    contradicted: 0,
    deleted: 0,
    unchanged: 0,
  }

  // Get recent experiences with recovery patterns
  const allExperiences = await expTable.query().toArray()
  const cutoffDate = daysAgo(lookbackDays)

  const recentPatterns = (allExperiences as unknown as Experience[]).filter((exp) => {
    const expDate = new Date(exp.timestamp)
    return (
      exp.outcome.recovery &&
      exp.outcome.recovery.worked &&
      expDate > cutoffDate
    )
  })

  if (recentPatterns.length === 0) {
    log.info("no recent recovery patterns found", { lookbackDays })
    return result
  }

  // Get all insights
  const allInsights = await insTable.query().toArray() as unknown as Insight[]

  // Track which insights have been processed (to handle once per update cycle)
  const processedInsights = new Set<string>()

  for (const pattern of recentPatterns) {
    // Find insights that match this pattern's recovery tool
    const matchingInsights = allInsights.filter(
      (ins) => ins.suggestion.prefer === pattern.outcome.recovery!.tool
    )

    for (const insight of matchingInsights) {
      // Only process each insight once per update cycle
      if (processedInsights.has(insight.id)) {
        continue
      }
      processedInsights.add(insight.id)

      const reinforces = patternReinforcesInsight(insight, pattern)

      let newConfidence: number
      let newContradictions: number = insight.contradictions

      if (reinforces) {
        newConfidence = Math.min(CONFIDENCE_MAX, insight.confidence + CONFIDENCE_REINFORCE_DELTA)
        result.reinforced++
        log.debug("reinforcing insight", {
          id: insight.id,
          oldConfidence: insight.confidence,
          newConfidence,
        })
      } else {
        newConfidence = Math.max(CONFIDENCE_MIN, insight.confidence - CONFIDENCE_CONTRADICT_DELTA)
        newContradictions = insight.contradictions + 1
        result.contradicted++
        log.debug("contradicting insight", {
          id: insight.id,
          oldConfidence: insight.confidence,
          newConfidence,
          contradictions: newContradictions,
        })
      }

      // Check if insight should be deleted
      if (newConfidence < CONFIDENCE_DELETE_THRESHOLD && newContradictions > CONTRADICTIONS_DELETE_THRESHOLD) {
        // Delete low-confidence insight with multiple contradictions
        try {
          await safeDeleteInsight(insTable, insight.id)
          result.deleted++
          log.info("deleted low-confidence insight", {
            id: insight.id,
            confidence: newConfidence,
            contradictions: newContradictions,
          })
        } catch (error) {
          log.error("failed to delete insight", { id: insight.id, error: String(error) })
        }
      } else {
        // Update insight via delete + re-add (LanceDB doesn't have in-place update)
        const updatedInsight = createInsight({
          id: insight.id,
          created_at: insight.created_at,
          created_from: insight.created_from,
          confidence: newConfidence,
          contradictions: newContradictions,
          last_reinforced: reinforces ? new Date().toISOString() : insight.last_reinforced,
          rule: insight.rule,
          suggestion: insight.suggestion,
          vector: insight.vector,
          sparse_json: (insight as any).sparse_json ?? "",
        })

        try {
          await safeUpdateInsight(insTable, insight.id, updatedInsight)
        } catch (error) {
          log.error("failed to update insight", { id: insight.id, error: String(error) })
        }
      }
    }
  }

  // Count unchanged
  result.unchanged = allInsights.length - result.reinforced - result.contradicted - result.deleted

  log.info("confidence update complete", result)

  return result
}

// =============================================================================
// Temporal Decay
// =============================================================================

/**
 * Apply temporal decay to insights
 *
 * Implements Doc 22 §Part 3 (lines 760-795)
 *
 * Following Google Titans' weight decay and Ebbinghaus forgetting curve.
 * Decay factor γ = 0.98 per day (2% decay).
 *
 * @returns Summary of decay application
 */
export async function applyConfidenceDecay(): Promise<DecayResult> {
  await initializeMemorySystem()

  const insTable = await getInsightsTable()
  const allInsights = await insTable.query().toArray() as unknown as Insight[]

  const result: DecayResult = {
    decayed: 0,
    deleted: 0,
    unchanged: 0,
  }

  const now = Date.now()

  for (const insight of allInsights) {
    // Skip canonical insights (from registry pre-seeding) — they don't decay
    const createdFrom = toPlainArray(insight.created_from) ?? []
    if (createdFrom.includes("canonical:registry")) {
      result.unchanged++
      continue
    }

    // Get last update time
    const lastUpdate = insight.last_reinforced
      ? new Date(insight.last_reinforced).getTime()
      : new Date(insight.created_at).getTime()

    const daysSinceUpdate = (now - lastUpdate) / DECAY_INTERVAL_MS

    if (daysSinceUpdate <= 1) {
      // No decay needed yet
      result.unchanged++
      continue
    }

    // Apply decay: confidence *= γ^days
    const decayedConfidence = insight.confidence * Math.pow(DECAY_FACTOR, daysSinceUpdate)
    const newConfidence = Math.max(CONFIDENCE_MIN, decayedConfidence)

    // Check if insight should be deleted
    if (newConfidence < CONFIDENCE_DELETE_THRESHOLD && insight.contradictions > CONTRADICTIONS_DELETE_THRESHOLD) {
      try {
        await safeDeleteInsight(insTable, insight.id)
        result.deleted++
        log.info("deleted decayed insight", {
          id: insight.id,
          confidence: newConfidence,
          contradictions: insight.contradictions,
          daysSinceUpdate: Math.round(daysSinceUpdate),
        })
      } catch (error) {
        log.error("failed to delete decayed insight", { id: insight.id, error: String(error) })
      }
    } else {
      // Update insight with decayed confidence
      const updatedInsight = createInsight({
        id: insight.id,
        created_at: insight.created_at,
        created_from: insight.created_from,
        confidence: newConfidence,
        contradictions: insight.contradictions,
        last_reinforced: insight.last_reinforced,
        rule: insight.rule,
        suggestion: insight.suggestion,
        vector: insight.vector,
        sparse_json: (insight as any).sparse_json ?? "",
      })

      try {
        await safeUpdateInsight(insTable, insight.id, updatedInsight)
        result.decayed++

        log.debug("applied decay to insight", {
          id: insight.id,
          oldConfidence: insight.confidence,
          newConfidence,
          daysSinceUpdate: Math.round(daysSinceUpdate),
        })
      } catch (error) {
        log.error("failed to update decayed insight", { id: insight.id, error: String(error) })
      }
    }
  }

  log.info("decay application complete", result)

  return result
}

// =============================================================================
// Query Functions
// =============================================================================

/**
 * Get all insights ordered by confidence
 *
 * @param minConfidence Minimum confidence threshold (default: 0)
 * @returns Array of insights
 */
export async function getAllInsights(minConfidence: number = 0): Promise<Insight[]> {
  await initializeMemorySystem()

  const insTable = await getInsightsTable()

  let query = insTable.query()
  if (minConfidence > 0) {
    query = query.where(`confidence >= ${minConfidence}`)
  }

  const results = await query.toArray()

  // Sort by confidence descending
  return (results as unknown as Insight[]).sort((a, b) => b.confidence - a.confidence)
}

/**
 * Get insights for a specific tool
 *
 * @param tool Tool name to search for
 * @returns Array of insights that prefer or are about this tool
 */
export async function getInsightsForTool(tool: string): Promise<Insight[]> {
  await initializeMemorySystem()

  const insTable = await getInsightsTable()
  const allInsights = await insTable.query().toArray() as unknown as Insight[]

  return allInsights.filter(
    (ins) => ins.suggestion.prefer === tool || ins.suggestion.over === tool
  )
}

/**
 * Get pending analysis files
 *
 * @returns Array of file paths in pending_analysis directory
 */
export async function getPendingAnalysisFiles(): Promise<string[]> {
  try {
    await ensurePendingAnalysisDir()
    const files = await fs.readdir(PENDING_ANALYSIS_DIR)
    return files
      .filter((f) => f.endsWith(".yaml"))
      .map((f) => path.join(PENDING_ANALYSIS_DIR, f))
      .sort()
  } catch {
    return []
  }
}

/**
 * Delete a pending analysis file after processing
 *
 * @param filepath Path to file to delete
 */
export async function deletePendingAnalysisFile(filepath: string): Promise<void> {
  await fs.unlink(filepath)
  log.info("deleted pending analysis file", { filepath })
}

// =============================================================================
// Automated Insight Generation (F4 + F5)
// =============================================================================

/**
 * Auto-convert recovery patterns to insights.
 *
 * Queries experiences table for all recovery patterns where worked === true,
 * groups by {failed_tool}→{recovery_tool}, filters to 2+ occurrences,
 * and creates insights without needing an LLM.
 *
 * @returns Number of new insights created
 */
export async function autoConvertRecoveryToInsights(): Promise<number> {
  await initializeMemorySystem()

  const expTable = await getExperiencesTable()
  const insTable = await getInsightsTable()

  // Get all experiences with working recovery
  const allExperiences = await expTable.query().toArray()
  const recoveryExperiences = (allExperiences as unknown as Experience[]).filter(
    (exp) => exp.outcome.recovery?.tool && exp.outcome.recovery?.worked === true
  )

  if (recoveryExperiences.length === 0) {
    log.info("no recovery patterns to convert")
    return 0
  }

  // Group by pattern key: {failed_tool}→{recovery_tool}
  const patternGroups = new Map<string, { failedTool: string; recoveryTool: string; failureReasons: string[]; phases: string[]; count: number }>()

  for (const exp of recoveryExperiences) {
    const failedTool = String(exp.action.tool_selected)
    const recoveryTool = String(exp.outcome.recovery!.tool)
    const key = `${failedTool}→${recoveryTool}`

    if (!patternGroups.has(key)) {
      patternGroups.set(key, { failedTool, recoveryTool, failureReasons: [], phases: [], count: 0 })
    }
    const group = patternGroups.get(key)!
    group.count++
    if (exp.outcome.failure_reason) group.failureReasons.push(String(exp.outcome.failure_reason))
    if (exp.context.phase) group.phases.push(String(exp.context.phase))
  }

  // Filter to 2+ occurrences
  const qualifyingPatterns = Array.from(patternGroups.values()).filter(
    (p) => p.count >= MIN_PATTERN_OCCURRENCES
  )

  // Check existing insights to avoid duplicates
  const existingInsights = await insTable.query().toArray() as unknown as Insight[]
  const existingKeys = new Set(existingInsights.map(
    (ins) => `${ins.suggestion.over ?? ""}→${ins.suggestion.prefer}`
  ))

  const embeddingService = getEmbeddingService()
  let created = 0

  for (const pattern of qualifyingPatterns) {
    const key = `${pattern.failedTool}→${pattern.recoveryTool}`
    if (existingKeys.has(key)) continue

    // Build insight rule
    const failureReason = pattern.failureReasons[0] ?? "failure"
    const phase = pattern.phases[0] ?? "any phase"
    const rule = `When ${pattern.failedTool} fails with ${failureReason} during ${phase}, use ${pattern.recoveryTool} instead.`

    // Embed the rule
    const embedding = await embeddingService.embed(rule)

    const insight = createInsight({
      rule,
      confidence: CONFIDENCE_INITIAL,
      contradictions: 0,
      suggestion: {
        prefer: pattern.recoveryTool,
        over: pattern.failedTool,
        when: failureReason,
      },
      created_from: [`auto:recovery:${key}`],
      vector: embedding?.dense ?? Array(VECTOR_DIMENSIONS).fill(0),
      sparse_json: serializeSparse(embedding?.sparse ?? null),
    })

    await insTable.add([insight])
    created++

    log.info("auto-created insight from recovery", {
      failedTool: pattern.failedTool,
      recoveryTool: pattern.recoveryTool,
      occurrences: pattern.count,
    })
  }

  log.info("auto-convert recovery complete", { created, qualifying: qualifyingPatterns.length })
  return created
}

/**
 * Pre-seed insights from registry routing metadata.
 *
 * Called during initialization when insights table is empty.
 * Creates insights from:
 * - prefer_over entries (most reliable — both tool IDs explicit)
 * - never_use_for entries (negative signals)
 *
 * Set confidence: 0.7 (expert knowledge).
 * Marked with created_from: ["canonical:registry"] for decay exemption.
 *
 * @param registryTools - Record<toolId, toolData> from registry
 * @returns Number of insights created
 */
export async function preSeedInsightsFromRegistry(
  registryTools: Record<string, any>
): Promise<number> {
  await initializeMemorySystem()

  const insTable = await getInsightsTable()
  const embeddingService = getEmbeddingService()
  let created = 0

  for (const [toolId, tool] of Object.entries(registryTools)) {
    const routing = tool.routing ?? {}

    // prefer_over entries → "Prefer X over Y for Z"
    for (const overTool of routing.prefer_over ?? []) {
      const toolName = tool.name ?? toolId
      const overToolName = registryTools[overTool]?.name ?? overTool
      const capabilities = (tool.capabilities ?? []).join(", ") || tool.description?.slice(0, 50)

      const rule = `Prefer ${toolName} over ${overToolName} for ${capabilities}`
      const embedding = await embeddingService.embed(rule)

      const insight = createInsight({
        rule,
        confidence: 0.7,
        contradictions: 0,
        suggestion: {
          prefer: toolId,
          over: overTool,
          when: capabilities,
        },
        created_from: ["canonical:registry"],
        vector: embedding?.dense ?? Array(VECTOR_DIMENSIONS).fill(0),
        sparse_json: serializeSparse(embedding?.sparse ?? null),
      })

      await insTable.add([insight])
      created++
    }

    // never_use_for entries → "Do not use X for Y"
    for (const entry of routing.never_use_for ?? []) {
      const task = typeof entry === "string" ? entry : entry.task
      if (!task) continue

      const toolName = tool.name ?? toolId
      const rule = `Do not use ${toolName} for ${task}`

      // Try to find the preferred alternative from use_instead or cross-reference
      let preferTool: string | undefined
      if (typeof entry !== "string" && entry.use_instead) {
        const useInstead = Array.isArray(entry.use_instead) ? entry.use_instead[0] : entry.use_instead
        if (useInstead) preferTool = useInstead
      }

      const embedding = await embeddingService.embed(rule)

      const insight = createInsight({
        rule,
        confidence: 0.7,
        contradictions: 0,
        suggestion: {
          prefer: preferTool ?? "",
          over: toolId,
          when: task,
        },
        created_from: ["canonical:registry"],
        vector: embedding?.dense ?? Array(VECTOR_DIMENSIONS).fill(0),
        sparse_json: serializeSparse(embedding?.sparse ?? null),
      })

      await insTable.add([insight])
      created++
    }
  }

  log.info("pre-seeded insights from registry", { created })
  return created
}
