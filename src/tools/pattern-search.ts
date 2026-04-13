/**
 * Pattern Search Tool
 *
 * Implements Doc 13 §pattern_search tool definition (lines 559-595)
 *
 * Searches for similar successful attack patterns based on target profile.
 * This is the strategic layer - recommending attack methodologies rather
 * than individual tools.
 *
 * Usage by agents:
 * - After reconnaissance, query with discovered services/technologies
 * - Use results to guide exploitation strategy
 * - Adapt patterns to specific target characteristics
 */

import { z } from "zod"
import { tool, type ToolContext } from "@opencode-ai/plugin"
import { createLog } from "../util/log"
import {
  searchPatterns,
  formatPatternResults,
  type PatternQuery,
} from "../pattern"

const log = createLog("tool.pattern-search")

// Tool description for agents
const DESCRIPTION = `Search for similar successful attack patterns based on target profile.

This tool provides strategic guidance by finding patterns from previous successful engagements
that match the current target's characteristics. Use this after reconnaissance to understand
what approaches have worked against similar targets.

**When to use:**
- After discovering services and technologies on a target
- When planning an attack strategy
- When stuck and looking for new approaches

**Key difference from tool_registry_search:**
- tool_registry_search: "I need to scan ports" → Returns tool recommendations
- pattern_search: "Linux with HTTP+SSH, what worked?" → Returns attack methodologies

**Example query:**
{
  "target_profile": {
    "os": "linux",
    "services": ["http", "ssh"],
    "technologies": ["apache", "wordpress"],
    "characteristics": ["login_form"]
  },
  "objective": "initial_access"
}

Returns patterns with:
- Methodology summary (e.g., "SQL injection in login form → DB creds → SSH")
- Tool sequence used
- Key insights and lessons learned
- Pivotal steps that led to success`

// Valid objectives for attacks
const VALID_OBJECTIVES = [
  "initial_access",
  "privilege_escalation",
  "lateral_movement",
  "data_exfiltration",
  "persistence",
] as const

export function createPatternSearchTool() {
  return tool({
    description: DESCRIPTION,
    args: {
      target_profile: z
        .object({
          os: z
            .enum(["linux", "windows", "unknown"])
            .optional()
            .describe("Target operating system"),
          services: z
            .array(z.string())
            .describe("Discovered services (e.g., ['http', 'ssh', 'smb'])"),
          technologies: z
            .array(z.string())
            .optional()
            .describe("Detected technologies (e.g., ['apache', 'wordpress', 'php'])"),
          characteristics: z
            .array(z.string())
            .optional()
            .describe("Observed characteristics (e.g., ['login_form', 'file_upload', 'api_endpoint'])"),
        })
        .describe("Target profile to match against"),
      objective: z
        .string()
        .describe("What you're trying to achieve (initial_access, privilege_escalation, etc.)"),
      limit: z
        .number()
        .optional()
        .default(5)
        .describe("Maximum number of patterns to return (default: 5)"),
    },
    async execute(params, ctx): Promise<string> {
      const { target_profile, objective, limit = 5 } = params

      log.info("pattern search requested", {
        sessionID: ctx.sessionID,
        os: target_profile.os,
        services: target_profile.services,
        objective,
        limit,
      })

      // Build query
      const query: PatternQuery = {
        target_profile: {
          os: target_profile.os,
          services: target_profile.services,
          technologies: target_profile.technologies,
          characteristics: target_profile.characteristics,
        },
        objective,
        limit,
      }

      // Search patterns
      const results = await searchPatterns(query)

      // Format output
      const output = formatPatternResults(results, query)

      // Determine if this is a cold start
      const isColdStart = results.length === 1 && results[0].pattern_id === ""

      ctx.metadata({
        title: isColdStart
          ? "Pattern search: no patterns yet"
          : `Pattern search: ${results.length} pattern(s) found`,
        metadata: {
          query: {
            os: target_profile.os,
            services: target_profile.services,
            objective,
          },
          results_count: isColdStart ? 0 : results.length,
          top_similarity: isColdStart ? 0 : results[0]?.similarity,
          cold_start: isColdStart,
        },
      })

      return output
    },
  })
}
