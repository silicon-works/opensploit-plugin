/**
 * Pattern Search Module
 *
 * Implements Doc 13 §Pattern Search Tool (lines 559-698)
 *
 * Provides strategic attack pattern recommendations based on target profile.
 * Uses LanceDB vector search with BGE-M3 embeddings from Document 22 infrastructure.
 *
 * Key distinction (Doc 13 §lines 38-46):
 * - Document 22 (Tactical): "I need to scan ports" → Tool recommendation
 * - Document 13 (Strategic): "Linux with HTTP+SSH, what worked?" → Attack methodology
 */

import { createLog } from "../util/log"
import {
  getPatternsTable,
  getEmbeddingService,
  parsePattern,
  type AttackPattern,
  type AttackPhase,
} from "../memory"

const log = createLog("pattern.search")

// =============================================================================
// Types
// =============================================================================

/**
 * Pattern query interface
 * Doc 13 §PatternQuery (lines 677-686)
 */
export interface PatternQuery {
  target_profile: {
    /** Target OS: linux, windows, or unknown */
    os?: string
    /** Discovered services: http, ssh, smb, etc. */
    services: string[]
    /** Technologies found: apache, wordpress, php, etc. */
    technologies?: string[]
    /** Characteristics: login_form, file_upload, api_endpoint, etc. */
    characteristics?: string[]
  }
  /** What you're trying to achieve: initial_access, privilege_escalation, etc. */
  objective: string
  /** Maximum patterns to return (default: 5) */
  limit?: number
}

/**
 * Pattern search result
 * Doc 13 §PatternSearchResult (lines 688-698)
 */
export interface PatternSearchResult {
  /** Vector similarity score (0-1, higher is more similar) */
  similarity: number
  /** Pattern ID for reference */
  pattern_id: string
  /** Methodology summary: "SQL injection in login form → DB creds → SSH" */
  summary: string
  /** Vulnerability type: sqli, rce, lfi, etc. */
  vulnerability_type: string
  /** CVE if known */
  cve?: string
  /** Tool sequence: ["nmap", "ffuf", "sqlmap", "ssh"] */
  tools_sequence: string[]
  /** Access level achieved: none, user, root */
  access_achieved: string
  /** Time to achieve access in minutes */
  time_to_access: number
  /** Key insights/lessons learned */
  key_insights: string[]
  /** Pivotal steps only (key breakthroughs) */
  phases: AttackPhase[]
  /** P2: Confidence score from metadata */
  confidence?: number
  /** P2: How many times this pattern was retrieved */
  access_count?: number
}

/**
 * Cold start result when no patterns exist
 */
const COLD_START_RESULT: PatternSearchResult = {
  similarity: 0,
  pattern_id: "",
  summary: "No similar patterns found yet. This will improve as you complete more engagements.",
  vulnerability_type: "",
  tools_sequence: [],
  access_achieved: "none",
  time_to_access: 0,
  key_insights: [
    "Consider starting with standard methodology for this target profile.",
    "Run reconnaissance to identify services and technologies.",
    "Check for common vulnerabilities based on discovered services.",
  ],
  phases: [],
}

// =============================================================================
// Query Formatting
// =============================================================================

/**
 * Format query for embedding generation
 * Doc 13 §formatQueryForEmbedding (lines 658-675)
 *
 * Creates a natural language representation of the target profile
 * that will be embedded and compared against stored patterns.
 */
export function formatQueryForEmbedding(query: PatternQuery): string {
  const parts: string[] = [
    `Target: ${query.target_profile.os || "unknown"} system`,
    `Services: ${query.target_profile.services.join(", ") || "none identified"}`,
  ]

  if (query.target_profile.technologies?.length) {
    parts.push(`Technologies: ${query.target_profile.technologies.join(", ")}`)
  }

  if (query.target_profile.characteristics?.length) {
    parts.push(`Characteristics: ${query.target_profile.characteristics.join(", ")}`)
  }

  parts.push(`Objective: ${query.objective}`)

  return parts.join(". ")
}

/**
 * Format pattern for embedding generation
 * Doc 13 §Pattern Embedding Text (lines 522-551)
 *
 * Used when storing patterns - creates searchable text representation.
 */
export function formatPatternForEmbedding(pattern: AttackPattern): string {
  const parts: string[] = [
    `Target: ${pattern.target_profile.os} system`,
    `Services: ${pattern.target_profile.services.join(", ")}`,
  ]

  if (pattern.target_profile.technologies.length) {
    parts.push(`Technologies: ${pattern.target_profile.technologies.join(", ")}`)
  }

  if (pattern.target_profile.characteristics.length) {
    parts.push(`Characteristics: ${pattern.target_profile.characteristics.join(", ")}`)
  }

  parts.push(`Vulnerability: ${pattern.vulnerability.type} - ${pattern.vulnerability.description}`)

  if (pattern.vulnerability.cve) {
    parts.push(`CVE: ${pattern.vulnerability.cve}`)
  }

  parts.push(`Methodology: ${pattern.methodology.summary}`)
  parts.push(`Tools: ${pattern.methodology.tools_sequence.join(" → ")}`)
  parts.push(`Outcome: ${pattern.outcome.access_achieved} access in ${pattern.outcome.time_to_access_minutes} minutes`)

  if (pattern.methodology.key_insights.length) {
    parts.push(`Insights: ${pattern.methodology.key_insights.join("; ")}`)
  }

  return parts.join(". ")
}

// =============================================================================
// Search Implementation
// =============================================================================

/**
 * Search for similar attack patterns
 * Doc 13 §searchPatterns (lines 600-656)
 *
 * Uses vector similarity search to find patterns with similar target profiles.
 * Falls back to keyword search if embedding service is unavailable.
 *
 * @param query - Target profile and objective to search for
 * @returns Array of matching patterns sorted by similarity
 */
export async function searchPatterns(query: PatternQuery): Promise<PatternSearchResult[]> {
  log.info("searching patterns", {
    os: query.target_profile.os,
    services: query.target_profile.services,
    objective: query.objective,
    limit: query.limit,
  })

  const limit = query.limit ?? 5

  try {
    // Get patterns table
    const table = await getPatternsTable()

    // Check if table has any patterns
    const countResult = await table.countRows()
    if (countResult === 0) {
      log.info("no patterns in database, returning cold start message")
      return [COLD_START_RESULT]
    }

    // Build query text for embedding
    const queryText = formatQueryForEmbedding(query)
    log.debug("query text for embedding", { queryText })

    // Get embedding from shared service (Doc 22 infrastructure)
    const embeddingService = getEmbeddingService()
    const embedding = await embeddingService.embed(queryText)

    if (!embedding) {
      log.warn("embedding service unavailable, falling back to keyword search")
      return await searchPatternsKeyword(query, limit)
    }

    // Build filter conditions (must combine with AND since chained where() replaces previous)
    const filters: string[] = ["outcome.success = true"]

    // Filter by OS if specified
    if (query.target_profile.os && query.target_profile.os !== "unknown") {
      filters.push(`target_profile.os = '${query.target_profile.os}'`)
    }

    // Vector search with combined filter
    const filterExpr = filters.join(" AND ")
    const search = table.search(embedding.dense).where(filterExpr)

    // Execute search
    const results = await search.limit(limit).toArray()

    // Handle cold start gracefully (RAG best practice)
    if (results.length === 0) {
      log.info("no matching patterns found")
      return [COLD_START_RESULT]
    }

    log.info("found matching patterns", { count: results.length })

    // Format results for agent consumption
    return results.map((record) => {
      const pattern = parsePattern(record as Record<string, unknown>)
      const score = (record as Record<string, unknown>)._distance as number | undefined

      // Convert distance to similarity (LanceDB returns L2 distance by default)
      // Lower distance = more similar, so we convert to similarity score
      const similarity = score !== undefined ? Math.max(0, 1 - score / 2) : 0

      return {
        similarity,
        pattern_id: pattern.id,
        summary: pattern.methodology.summary,
        vulnerability_type: pattern.vulnerability.type,
        cve: pattern.vulnerability.cve,
        tools_sequence: pattern.methodology.tools_sequence,
        access_achieved: pattern.outcome.access_achieved,
        time_to_access: pattern.outcome.time_to_access_minutes,
        key_insights: pattern.methodology.key_insights,
        // Return only pivotal phases (key breakthroughs)
        phases: pattern.methodology.phases.filter((p) => p.pivotal),
        // P2 metadata fields
        confidence: pattern.metadata.confidence,
        access_count: pattern.metadata.access_count,
      }
    })
  } catch (error) {
    log.error("pattern search failed", { error: String(error) })
    // Return cold start message on error
    return [COLD_START_RESULT]
  }
}

/**
 * Fallback keyword-based search when embeddings unavailable
 *
 * Uses simple text matching against pattern metadata.
 */
async function searchPatternsKeyword(query: PatternQuery, limit: number): Promise<PatternSearchResult[]> {
  log.debug("performing keyword search fallback")

  try {
    const table = await getPatternsTable()

    // Build filter conditions
    const filters: string[] = ["outcome.success = true"]

    if (query.target_profile.os && query.target_profile.os !== "unknown") {
      filters.push(`target_profile.os = '${query.target_profile.os}'`)
    }

    // Query with filters (no vector search)
    let queryBuilder = table.query()
    for (const filter of filters) {
      queryBuilder = queryBuilder.where(filter)
    }

    const results = await queryBuilder.limit(limit).toArray()

    if (results.length === 0) {
      return [COLD_START_RESULT]
    }

    // Score based on service overlap
    const queryServices = new Set(query.target_profile.services.map((s) => s.toLowerCase()))

    const scoredResults = results.map((record) => {
      const pattern = parsePattern(record as Record<string, unknown>)

      // Calculate keyword-based score
      let score = 0

      // Service overlap
      for (const service of pattern.target_profile.services) {
        if (queryServices.has(service.toLowerCase())) {
          score += 10
        }
      }

      // Technology overlap
      if (query.target_profile.technologies) {
        const queryTechs = new Set(query.target_profile.technologies.map((t) => t.toLowerCase()))
        for (const tech of pattern.target_profile.technologies) {
          if (queryTechs.has(tech.toLowerCase())) {
            score += 5
          }
        }
      }

      // Characteristic overlap
      if (query.target_profile.characteristics) {
        const queryChars = new Set(query.target_profile.characteristics.map((c) => c.toLowerCase()))
        for (const char of pattern.target_profile.characteristics) {
          if (queryChars.has(char.toLowerCase())) {
            score += 3
          }
        }
      }

      return { pattern, score }
    })

    // Sort by score
    scoredResults.sort((a, b) => b.score - a.score)

    // Convert to results
    return scoredResults.map(({ pattern, score }) => ({
      similarity: Math.min(1, score / 30), // Normalize to 0-1 range
      pattern_id: pattern.id,
      summary: pattern.methodology.summary,
      vulnerability_type: pattern.vulnerability.type,
      cve: pattern.vulnerability.cve,
      tools_sequence: pattern.methodology.tools_sequence,
      access_achieved: pattern.outcome.access_achieved,
      time_to_access: pattern.outcome.time_to_access_minutes,
      key_insights: pattern.methodology.key_insights,
      phases: pattern.methodology.phases.filter((p) => p.pivotal),
      confidence: pattern.metadata.confidence,
      access_count: pattern.metadata.access_count,
    }))
  } catch (error) {
    log.error("keyword search failed", { error: String(error) })
    return [COLD_START_RESULT]
  }
}

// =============================================================================
// Output Formatting
// =============================================================================

/**
 * Format search results for agent display
 */
export function formatPatternResults(results: PatternSearchResult[], query: PatternQuery): string {
  const lines: string[] = []

  lines.push("# Attack Pattern Search Results")
  lines.push("")
  lines.push(`**Target Profile:**`)
  lines.push(`- OS: ${query.target_profile.os || "unknown"}`)
  lines.push(`- Services: ${query.target_profile.services.join(", ") || "none"}`)
  if (query.target_profile.technologies?.length) {
    lines.push(`- Technologies: ${query.target_profile.technologies.join(", ")}`)
  }
  if (query.target_profile.characteristics?.length) {
    lines.push(`- Characteristics: ${query.target_profile.characteristics.join(", ")}`)
  }
  lines.push(`**Objective:** ${query.objective}`)
  lines.push(`**Results:** ${results.length} pattern(s) found`)
  lines.push("")

  // Check for cold start
  if (results.length === 1 && results[0].pattern_id === "") {
    lines.push("---")
    lines.push("")
    lines.push("## No Matching Patterns Yet")
    lines.push("")
    lines.push(results[0].summary)
    lines.push("")
    lines.push("**Suggestions:**")
    for (const insight of results[0].key_insights) {
      lines.push(`- ${insight}`)
    }
    lines.push("")
    lines.push("*Patterns are learned from successful engagements. Complete more targets to build your pattern library.*")
    return lines.join("\n")
  }

  lines.push("---")
  lines.push("")

  for (let i = 0; i < results.length; i++) {
    const result = results[i]
    const rankBadge = i === 0 ? " 🏆" : ""

    lines.push(`## Pattern ${i + 1}${rankBadge}`)
    lines.push("")
    lines.push(`**${result.summary}**`)
    lines.push("")
    lines.push(`- **Similarity:** ${(result.similarity * 100).toFixed(1)}%`)
    if (result.confidence !== undefined) {
      lines.push(`- **Confidence:** ${(result.confidence * 100).toFixed(0)}%`)
    }
    lines.push(`- **Vulnerability:** ${result.vulnerability_type}${result.cve ? ` (${result.cve})` : ""}`)
    lines.push(`- **Access Achieved:** ${result.access_achieved}`)
    lines.push(`- **Time to Access:** ${result.time_to_access} minutes`)
    lines.push("")

    lines.push("### Tool Sequence")
    lines.push("")
    lines.push(`\`${result.tools_sequence.join(" → ")}\``)
    lines.push("")

    if (result.key_insights.length > 0) {
      lines.push("### Key Insights")
      lines.push("")
      for (const insight of result.key_insights) {
        lines.push(`- ${insight}`)
      }
      lines.push("")
    }

    if (result.phases.length > 0) {
      lines.push("### Pivotal Steps")
      lines.push("")
      for (const phase of result.phases) {
        lines.push(`1. **[${phase.phase}]** ${phase.action}`)
        lines.push(`   - Tool: \`${phase.tool}\``)
        lines.push(`   - Result: ${phase.result}`)
      }
      lines.push("")
    }

    lines.push("---")
    lines.push("")
  }

  lines.push("*Use these patterns as guidance, but adapt to the specific target.*")

  return lines.join("\n")
}
