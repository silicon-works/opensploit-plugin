/**
 * experimental.chat.system.transform hook
 *
 * Injects engagement state into every agent's system prompt. This replaces
 * the fat fork's task.ts context injection (which only ran at spawn time)
 * with a LIVE injection that fires on every LLM turn.
 *
 * Benefits over spawn-time injection:
 * - Sub-agents always see the LATEST state (ports discovered by siblings, etc.)
 * - Works for ALL agents, not just spawned pentest sub-agents
 * - State updates mid-conversation are immediately visible
 *
 * What gets injected:
 * - Session working directory path
 * - Port accessibility summary (open vs filtered)
 * - Attack plan with progress
 * - Full engagement state YAML
 * - Broken tools warnings
 * - Recent tool search cache
 */

import { getEngagementStateForInjection } from "../tools/engagement-state.js"
import { getRootSession } from "../session/hierarchy.js"
import * as SessionDirectory from "../session/directory.js"
import { createLog } from "../util/log.js"

const log = createLog("hook.system-transform")

export async function systemTransformHook(
  input: { sessionID?: string; model: any },
  output: { system: string[] },
): Promise<void> {
  try {
    if (!input.sessionID) return

    const rootSessionID = getRootSession(input.sessionID)

    // Get engagement state formatted for injection
    const engagementState = await getEngagementStateForInjection(rootSessionID)

    if (!engagementState) return // No state yet — nothing to inject

    // Build the injection block
    const parts: string[] = []

    // Session directory (if it exists)
    if (SessionDirectory.exists(rootSessionID)) {
      const sessionDir = SessionDirectory.get(rootSessionID)
      parts.push(`## Session Working Directory\n${sessionDir}`)
    }

    // Engagement state (ports, creds, vulns, attack plan, failed attempts, etc.)
    parts.push(engagementState)

    if (parts.length > 0) {
      output.system.push(parts.join("\n\n"))
      log.info("injected engagement state", {
        sessionID: input.sessionID.slice(-8),
        rootSessionID: rootSessionID.slice(-8),
      })
    }
  } catch (error) {
    log.error("hook failed, proceeding without modification", {
      error: error instanceof Error ? error.message : String(error),
    })
  }
}
