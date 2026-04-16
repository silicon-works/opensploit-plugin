/**
 * Save Pattern Tool
 *
 * Implements Doc 13 §Manual Capture (lines 701-710)
 *
 * Allows users/agents to manually save the current attack pattern.
 * Called via /save-pattern or by the agent when instructed to save.
 */

import { z } from "zod"
import { tool, type ToolContext } from "@opencode-ai/plugin"
import { capturePattern, type CaptureResult } from "../pattern/capture"
import { createLog } from "../util/log"

const log = createLog("tool.save-pattern")

const DESCRIPTION = `Save the current attack pattern for future reference.

This tool captures the successful attack methodology from the current engagement
and stores it in the pattern database for similarity search in future engagements.

**When to use:**
- After achieving user or root access on a target
- When you've found an interesting attack path worth remembering
- At the end of a successful engagement

**Requirements:**
- Access level must be 'user' or 'root' (won't save patterns for unsuccessful attempts)
- Engagement state must have some discoveries recorded

**What gets saved:**
- Target profile (OS, services, ports, technologies)
- Vulnerability exploited
- Attack methodology (phases, tools, key insights)
- Outcome metrics (access level, time to access, flags)

**Note:** Patterns are automatically anonymized before storage to remove PII.`

export function createSavePatternTool() {
  return tool({
    description: DESCRIPTION,
    args: {
      engagement_type: z
        .enum(["htb", "vulnhub", "real", "ctf", "lab"])
        .optional()
        .describe("Type of engagement (htb, vulnhub, real, ctf, lab)"),
    },
    async execute(params, ctx): Promise<string> {
      const sessionID = ctx.sessionID

      log.info("save_pattern called", { sessionID, engagementType: params.engagement_type })

      let result: CaptureResult
      try {
        result = await capturePattern(sessionID, {
          userTriggered: true,
          engagementType: params.engagement_type,
        })
      } catch (error) {
        log.error("save_pattern failed", { error })
        return `Pattern save error: ${error instanceof Error ? error.message : String(error)}`
      }

      // Build output based on result
      let output: string
      let title: string

      if (result.success && result.pattern) {
        const pattern = result.pattern
        const insights = Array.isArray(pattern.methodology.key_insights) ? pattern.methodology.key_insights : []
        output = [
          "**Pattern Saved Successfully**",
          "",
          `**ID:** ${pattern.id}`,
          `**Summary:** ${pattern.methodology.summary}`,
          "",
          "**Target Profile:**",
          `- OS: ${pattern.target_profile.os}`,
          `- Services: ${pattern.target_profile.services.join(", ") || "none"}`,
          `- Technologies: ${pattern.target_profile.technologies.join(", ") || "none"}`,
          "",
          "**Vulnerability:**",
          `- Type: ${pattern.vulnerability.type}`,
          `- Description: ${pattern.vulnerability.description}`,
          "",
          "**Outcome:**",
          `- Access Achieved: ${pattern.outcome.access_achieved}`,
          `- Time to Access: ${pattern.outcome.time_to_access_minutes} minutes`,
          pattern.outcome.flags_captured ? `- Flags Captured: ${pattern.outcome.flags_captured}` : null,
          "",
          "**Key Insights:**",
          ...(insights.length > 0 ? insights.map((i: string) => `- ${i}`) : ["- None recorded"]),
          "",
          "_Pattern has been anonymized and stored for future similarity search._",
        ]
          .filter((line) => line !== null)
          .join("\n")
        title = "Pattern saved"
      } else if (result.duplicateOf) {
        output = [
          "**Pattern Not Saved - Duplicate Detected**",
          "",
          result.message,
          "",
          `A similar pattern already exists: ${result.duplicateOf}`,
          "",
          "_The existing pattern covers this attack methodology._",
        ].join("\n")
        title = "Pattern duplicate"
      } else {
        output = [
          "**Pattern Not Saved**",
          "",
          result.message,
          "",
          "**Common reasons:**",
          "- No access achieved yet (need user or root access)",
          "- No engagement state recorded",
          "- Embedding service unavailable",
        ].join("\n")
        title = "Pattern save failed"
      }

      ctx.metadata({
        title,
        metadata: {
          success: result.success,
          patternId: result.pattern?.id ?? result.duplicateOf,
          message: result.message,
        },
      })

      return output
    },
  })
}
