/**
 * experimental.session.compacting hook
 *
 * Injects engagement state into the compaction context so that critical
 * discoveries (ports, credentials, vulnerabilities, attack plan) survive
 * context window trimming.
 *
 * Without this, a long pen test session that gets compacted would lose
 * earlier phase findings. The compaction summary would miss discovered
 * ports, credentials, and the attack plan.
 *
 * Pattern adopted from beads/agent-skills plugins: inject context that
 * must survive compaction.
 */

import { getEngagementStateForInjection } from "../tools/engagement-state.js"
import { getRootSession } from "../session/hierarchy.js"
import { createLog } from "../util/log.js"

const log = createLog("hook.compaction")

export async function compactionHook(
  input: { sessionID: string },
  output: { context: string[]; prompt?: string },
): Promise<void> {
  try {
    const rootSessionID = getRootSession(input.sessionID)
    const engagementState = await getEngagementStateForInjection(rootSessionID)

    if (!engagementState) return

    output.context.push(
      `CRITICAL — PRESERVE IN SUMMARY:\n` +
      `The following engagement state contains ALL discoveries made during this penetration test. ` +
      `This data MUST be preserved verbatim in the summary — losing it means re-scanning targets ` +
      `and losing credentials, vulnerabilities, and attack progress.\n\n` +
      engagementState
    )

    log.info("injected engagement state into compaction context", {
      sessionID: input.sessionID.slice(-8),
      rootSessionID: rootSessionID.slice(-8),
    })
  } catch (error) {
    log.error("hook failed, proceeding without modification", {
      error: error instanceof Error ? error.message : String(error),
    })
  }
}
