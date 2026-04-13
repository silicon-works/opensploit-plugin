/**
 * Unified Search — Annotation Model
 *
 * Implements Doc 22 §Part 4 with cross-table architecture:
 *
 * Tools are primary results. Experiences and insights annotate and
 * adjust tool scores instead of competing as peer results via RRF.
 *
 * Flow:
 * 1. Tool results come pre-scored from tool-registry-search.ts (method-level)
 * 2. Experiences and insights are searched in parallel
 * 3. For each tool, matching insights boost/penalize the score
 * 4. Matching experiences provide evidence annotations
 * 5. Tools re-sorted by adjusted score
 * 6. Each tool result includes evidence annotations for the agent
 */

import { createLog } from "../util/log"
import { getExperiencesTable, getInsightsTable, initializeMemorySystem } from "./database"
import { getEmbeddingService } from "./embedding"
import type { Experience, Insight } from "./schema"
import type { ToolContext } from "./context"

const log = createLog("memory.search")

// =============================================================================
// Types
// =============================================================================

/** Base interface for scored items */
interface ScoredItem {
  id: string
  score: number
  [key: string]: unknown
}

/** Scored tool result (from method-level search) */
export interface ScoredTool extends ScoredItem {
  name: string
  description: string
  phases?: string[]
  capabilities?: string[]
  routing?: {
    use_for?: string[]
    triggers?: string[]
    never_use_for?: unknown[]
  }
  suggestedMethod?: string
}

/** Scored experience result (from LanceDB) */
export interface ScoredExperience extends ScoredItem {
  action: {
    query: string
    tool_selected: string
    tool_input: string
  }
  outcome: {
    success: boolean
    result_summary: string
    failure_reason?: string
    recovery?: {
      tool: string
      method: string
      worked: boolean
    }
  }
  context: {
    phase: string
    target_characteristics?: string[]
  }
}

/** Scored insight result (from LanceDB) */
export interface ScoredInsight extends ScoredItem {
  rule: string
  confidence: number
  suggestion: {
    prefer: string
    over?: string
    when: string
  }
  created_from: string[]
}

/** Type of result item */
export type ResultType = "tool" | "experience" | "insight"

/** Ranked item after RRF fusion (kept for backwards compatibility) */
export interface RankedItem {
  id: string
  score: number
  type: ResultType
  data: ScoredTool | ScoredExperience | ScoredInsight
}

/** Context for search (from ToolContext) */
export interface SearchContext {
  phase?: string
  toolsTried?: string[]
  recentSuccesses?: string[]
}

// =============================================================================
// Annotation Types (Cross-Table Architecture)
// =============================================================================

/** Experience annotation on a tool result */
export interface ExperienceAnnotation {
  success: boolean
  summary: string
  recovery?: { tool: string; method: string }
}

/** Insight annotation on a tool result */
export interface InsightAnnotation {
  rule: string
  confidence: number
  effect: "boost" | "penalize"
}

/** Tool result with annotations from experiences and insights */
export interface AnnotatedToolResult {
  tool: string
  name: string
  baseScore: number
  adjustedScore: number
  suggestedMethod?: string
  experiences: ExperienceAnnotation[]
  insights: InsightAnnotation[]
}

/** Result of unified search */
export interface UnifiedSearchResult {
  query: string
  /** Combined and ranked results (kept for backwards compat) */
  results: RankedItem[]
  /** Annotated tool results (new cross-table architecture) */
  annotatedTools: AnnotatedToolResult[]
  /** Tool results */
  tools: ScoredTool[]
  /** Experience results */
  experiences: ScoredExperience[]
  /** Insight results */
  insights: ScoredInsight[]
  /** Whether embedding was available */
  embeddingAvailable: boolean
  /** Optional explanation (when explain=true) */
  explanation?: string
}

// =============================================================================
// Experience Search
// =============================================================================

/**
 * Search experiences using LanceDB vector similarity
 */
export async function searchExperiencesLance(
  query: string,
  queryEmbedding: number[] | null,
  limit: number = 10
): Promise<ScoredExperience[]> {
  if (!queryEmbedding) {
    log.warn("skipping experience search — no embedding available")
    return []
  }

  try {
    await initializeMemorySystem()

    const table = await getExperiencesTable()
    const results = await table
      .search(queryEmbedding)
      .limit(limit)
      .toArray()

    return results.map((exp) => {
      const experience = exp as unknown as Experience & { _distance?: number }
      const score = 1 / (1 + (experience._distance ?? 1))

      return {
        id: experience.id,
        score,
        action: experience.action,
        outcome: experience.outcome,
        context: experience.context,
      } as ScoredExperience
    })
  } catch (error) {
    log.warn("experience search failed", { error: String(error) })
    return []
  }
}

// =============================================================================
// Insight Search
// =============================================================================

/**
 * Search insights using LanceDB vector similarity
 */
export async function searchInsightsLance(
  query: string,
  queryEmbedding: number[] | null,
  minConfidence: number = 0.3,
  limit: number = 5
): Promise<ScoredInsight[]> {
  if (!queryEmbedding) {
    log.warn("skipping insight search — no embedding available")
    return []
  }

  try {
    await initializeMemorySystem()

    const table = await getInsightsTable()

    const results = await table
      .search(queryEmbedding)
      .where(`confidence > ${minConfidence}`)
      .limit(limit)
      .toArray()

    return results.map((ins) => {
      const insight = ins as unknown as Insight & { _distance?: number }
      const baseSimilarity = 1 / (1 + (insight._distance ?? 1))
      const score = baseSimilarity * insight.confidence

      return {
        id: insight.id,
        score,
        rule: insight.rule,
        confidence: insight.confidence,
        suggestion: insight.suggestion,
        created_from: insight.created_from,
      } as ScoredInsight
    })
  } catch (error) {
    log.warn("insight search failed", { error: String(error) })
    return []
  }
}

// =============================================================================
// Reciprocal Rank Fusion (kept for potential future use)
// =============================================================================

interface RRFInput {
  results: ScoredItem[]
  weight: number
  type: ResultType
}

/**
 * Reciprocal Rank Fusion - combines ranked lists from different sources.
 *
 * Kept for backwards compatibility but no longer used in the main
 * unifiedSearch() path. Tools are now the primary ranked list with
 * experiences and insights as annotations.
 */
export function reciprocalRankFusion(
  resultSets: RRFInput[],
  k: number = 60
): RankedItem[] {
  const scores = new Map<string, RankedItem>()

  for (const { results, weight, type } of resultSets) {
    for (let rank = 0; rank < results.length; rank++) {
      const item = results[rank]
      const prefixedId = `${type}:${item.id}`

      const rrf = weight * (1 / (k + rank + 1))

      const existing = scores.get(prefixedId)
      if (existing) {
        existing.score += rrf
      } else {
        scores.set(prefixedId, {
          id: prefixedId,
          score: rrf,
          type,
          data: item as ScoredTool | ScoredExperience | ScoredInsight,
        })
      }
    }
  }

  return Array.from(scores.values()).sort((a, b) => b.score - a.score)
}

// =============================================================================
// Annotation Builder (Cross-Table Architecture)
// =============================================================================

/** Weight for insight score adjustments */
const INSIGHT_BOOST_WEIGHT = 0.15
const INSIGHT_PENALIZE_WEIGHT = 0.10
const EXPERIENCE_SUCCESS_BOOST = 0.05
const EXPERIENCE_FAILURE_PENALTY = 0.03

/**
 * Build annotations for tool results from experiences and insights.
 *
 * For each tool:
 * - Matching insights (prefer/over) → boost or penalize
 * - Matching experiences (tool_selected) → evidence annotations
 */
function buildAnnotatedTools(
  toolResults: ScoredTool[],
  experiences: ScoredExperience[],
  insights: ScoredInsight[]
): AnnotatedToolResult[] {
  return toolResults.map((tool) => {
    const annotations: AnnotatedToolResult = {
      tool: tool.id,
      name: tool.name,
      baseScore: tool.score,
      adjustedScore: tool.score,
      suggestedMethod: tool.suggestedMethod,
      experiences: [],
      insights: [],
    }

    // Insight adjustments
    for (const insight of insights) {
      if (insight.suggestion.prefer === tool.id) {
        // This tool is preferred by the insight → boost
        const boost = insight.confidence * INSIGHT_BOOST_WEIGHT
        annotations.adjustedScore += boost
        annotations.insights.push({
          rule: insight.rule,
          confidence: insight.confidence,
          effect: "boost",
        })
      } else if (insight.suggestion.over === tool.id) {
        // This tool is the one to avoid → penalize
        const penalty = insight.confidence * INSIGHT_PENALIZE_WEIGHT
        annotations.adjustedScore -= penalty
        annotations.insights.push({
          rule: insight.rule,
          confidence: insight.confidence,
          effect: "penalize",
        })
      }
    }

    // Experience annotations
    for (const exp of experiences) {
      if (exp.action.tool_selected === tool.id) {
        if (exp.outcome.success) {
          annotations.adjustedScore += EXPERIENCE_SUCCESS_BOOST
          annotations.experiences.push({
            success: true,
            summary: exp.outcome.result_summary.slice(0, 100),
          })
        } else {
          annotations.adjustedScore -= EXPERIENCE_FAILURE_PENALTY
          const annotation: ExperienceAnnotation = {
            success: false,
            summary: exp.outcome.failure_reason ?? exp.outcome.result_summary.slice(0, 100),
          }
          if (exp.outcome.recovery?.worked) {
            annotation.recovery = {
              tool: exp.outcome.recovery.tool,
              method: exp.outcome.recovery.method,
            }
          }
          annotations.experiences.push(annotation)
        }
      }
    }

    return annotations
  })
}

// =============================================================================
// Explanation Formatting
// =============================================================================

/**
 * Format detailed score explanation for --explain flag
 */
export function formatExplanation(
  query: string,
  toolResults: ScoredTool[],
  context: SearchContext,
  experienceResults: ScoredExperience[],
  insightResults: ScoredInsight[]
): string {
  const lines: string[] = [`\n## Score Breakdown for: "${query}"\n`]

  if (toolResults.length > 0) {
    lines.push("### Tool Scores\n")
    for (const tool of toolResults.slice(0, 5)) {
      const parts: string[] = []

      parts.push(`- Base score: ${tool.score.toFixed(3)}`)

      if (tool.suggestedMethod) {
        parts.push(`- Suggested method: ${tool.suggestedMethod}`)
      }

      if (context.phase && tool.phases?.includes(context.phase)) {
        parts.push(`- Phase match (${context.phase}): boost applied`)
      }

      if (context.toolsTried?.includes(tool.id)) {
        parts.push(`- Note: Already tried this session`)
      }

      if (context.recentSuccesses?.includes(tool.id)) {
        parts.push(`- Recent success this session: boost applied`)
      }

      lines.push(`**${tool.name}** (score: ${tool.score.toFixed(3)})`)
      lines.push(parts.join("\n"))
      lines.push("")
    }
  }

  if (experienceResults.length > 0) {
    lines.push("### Relevant Experiences\n")
    for (const exp of experienceResults.slice(0, 3)) {
      const status = exp.outcome.success ? "succeeded" : "failed"
      const recovery = exp.outcome.recovery
        ? ` → recovered with ${exp.outcome.recovery.tool}`
        : ""
      lines.push(
        `- **${exp.action.tool_selected}** ${status}${recovery} (similarity: ${exp.score.toFixed(3)})`
      )
      lines.push(`  Query: "${exp.action.query.slice(0, 50)}..."`)
    }
    lines.push("")
  }

  if (insightResults.length > 0) {
    lines.push("### Applicable Insights\n")
    for (const ins of insightResults.slice(0, 3)) {
      lines.push(
        `- **${ins.suggestion.prefer}** over ${ins.suggestion.over || "alternatives"}`
      )
      lines.push(`  When: ${ins.suggestion.when}`)
      lines.push(
        `  Confidence: ${(ins.confidence * 100).toFixed(0)}% (from ${ins.created_from.length} experiences)`
      )
    }
    lines.push("")
  }

  return lines.join("\n")
}

// =============================================================================
// Result Formatting
// =============================================================================

/**
 * Format experience for display in search results
 */
export function formatExperienceForDisplay(exp: ScoredExperience): string {
  const status = exp.outcome.success ? "✓" : "✗"
  const recovery = exp.outcome.recovery
    ? ` → Recovered with ${exp.outcome.recovery.tool}`
    : ""

  let result = `${status} Used **${exp.action.tool_selected}**`

  if (exp.outcome.success) {
    result += `: ${exp.outcome.result_summary.slice(0, 100)}`
  } else {
    result += ` (${exp.outcome.failure_reason || "failed"})${recovery}`
  }

  return result
}

/**
 * Format insight for display in search results
 */
export function formatInsightForDisplay(ins: ScoredInsight): string {
  const confidence = (ins.confidence * 100).toFixed(0)
  let result = `💡 **Insight** (${confidence}% confidence): ${ins.rule}`

  if (ins.suggestion.prefer) {
    result += `\n   → Prefer **${ins.suggestion.prefer}**`
    if (ins.suggestion.over) {
      result += ` over ${ins.suggestion.over}`
    }
    if (ins.suggestion.when) {
      result += ` when ${ins.suggestion.when}`
    }
  }

  return result
}

// =============================================================================
// Main Unified Search
// =============================================================================

/**
 * Unified search — annotation model.
 *
 * Tools are primary results (pre-scored from method-level search).
 * Experiences and insights annotate and adjust tool scores.
 *
 * @param query - Search query
 * @param toolResults - Pre-scored tool results from tool-registry-search.ts
 * @param context - Search context (phase, tools tried, etc.)
 * @param explain - Whether to include detailed explanation
 */
export async function unifiedSearch(
  query: string,
  toolResults: ScoredTool[],
  context: SearchContext,
  explain: boolean = false
): Promise<UnifiedSearchResult> {
  log.info("unified search", { query, explain, toolCount: toolResults.length })

  // 1. Get query embedding
  const embeddingService = getEmbeddingService()
  const embedding = await embeddingService.embed(query)
  const queryEmbedding = embedding?.dense ?? null

  // 2. Search experiences and insights in parallel
  const [experienceResults, insightResults] = await Promise.all([
    searchExperiencesLance(query, queryEmbedding),
    searchInsightsLance(query, queryEmbedding),
  ])

  log.debug("search results", {
    tools: toolResults.length,
    experiences: experienceResults.length,
    insights: insightResults.length,
    embeddingAvailable: queryEmbedding !== null,
  })

  // 3. Build annotations and adjust tool scores
  const annotatedTools = buildAnnotatedTools(toolResults, experienceResults, insightResults)

  // 4. Re-sort by adjusted score
  annotatedTools.sort((a, b) => b.adjustedScore - a.adjustedScore)

  // 5. Build backwards-compatible RankedItem results
  // Tools only — experiences and insights are annotations, not peer results
  const combined: RankedItem[] = annotatedTools.map((at) => ({
    id: `tool:${at.tool}`,
    score: at.adjustedScore,
    type: "tool" as ResultType,
    data: toolResults.find((t) => t.id === at.tool)!,
  }))

  // 6. Build result
  const result: UnifiedSearchResult = {
    query,
    results: combined,
    annotatedTools,
    tools: toolResults,
    experiences: experienceResults,
    insights: insightResults,
    embeddingAvailable: queryEmbedding !== null,
  }

  // 7. Add explanation if requested
  if (explain) {
    result.explanation = formatExplanation(
      query,
      toolResults,
      context,
      experienceResults,
      insightResults
    )
  }

  return result
}

/**
 * Format unified search results for display.
 *
 * Shows tool annotations (insights and experiences) as nested evidence.
 */
export function formatUnifiedResults(result: UnifiedSearchResult): string {
  const lines: string[] = []

  // Show annotated tools with evidence
  const toolsWithEvidence = result.annotatedTools.filter(
    (at) => at.insights.length > 0 || at.experiences.length > 0
  )

  if (toolsWithEvidence.length > 0) {
    lines.push("\n### Evidence from Past Engagements\n")

    for (const at of toolsWithEvidence) {
      // Insight annotations
      for (const ins of at.insights) {
        const confidence = (ins.confidence * 100).toFixed(0)
        const effect = ins.effect === "boost" ? "↑" : "↓"
        lines.push(`> ${effect} **${at.name}** — Insight (${confidence}%): ${ins.rule}`)
      }

      // Experience annotations
      for (const exp of at.experiences) {
        const status = exp.success ? "✓" : "✗"
        const recovery = exp.recovery
          ? ` → recovered with ${exp.recovery.tool}:${exp.recovery.method}`
          : ""
        lines.push(`> ${status} **${at.name}**: ${exp.summary}${recovery}`)
      }
    }
    lines.push("")
  }

  // Add explanation if present
  if (result.explanation) {
    lines.push(result.explanation)
  }

  // Note if embedding wasn't available
  if (!result.embeddingAvailable && result.experiences.length === 0 && result.insights.length === 0) {
    lines.push("\n*Note: Semantic search unavailable. Results based on keyword matching only.*\n")
  }

  return lines.join("\n")
}
