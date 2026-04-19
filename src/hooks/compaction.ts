/**
 * experimental.session.compacting hook
 *
 * Injects engagement state, objective, and todo progress into the compaction
 * context so that critical discoveries and task focus survive context window
 * trimming.
 *
 * Based on research findings:
 * - Goal drift paper (arxiv 2505.02709): Strong goal elicitation is the most
 *   effective prevention against objective drift after compaction.
 * - Factory.ai: Structured sections in summaries force preservation of
 *   critical information.
 * - Anthropic: System prompts survive compaction automatically, but explicit
 *   injection into the compaction prompt ensures the summarizer preserves
 *   the objective in the summary text.
 */

import { loadEngagementState } from "../tools/engagement-state.js"
import { getEngagementStateForInjection } from "../tools/engagement-state.js"
import { getRootSession } from "../session/hierarchy.js"
import { createLog } from "../util/log.js"

const log = createLog("hook.compaction")

/**
 * Fetch todos for a session from the OpenCode server.
 * Returns formatted todo snapshot or null if unavailable.
 */
async function fetchTodos(sessionID: string, serverUrl: URL): Promise<string | null> {
  try {
    const url = new URL(`/${sessionID}/todo`, serverUrl)
    const response = await fetch(url.toString())
    if (!response.ok) return null

    const data = await response.json() as Array<{ content: string; status: string }>
    if (!Array.isArray(data) || data.length === 0) return null

    return data
      .map((t) => `- [${t.status}] ${t.content}`)
      .join("\n")
  } catch {
    // Server might not be available or endpoint might not exist
    return null
  }
}

export async function compactionHook(
  input: { sessionID: string },
  output: { context: string[]; prompt?: string },
  serverUrl?: URL,
): Promise<void> {
  try {
    const rootSessionID = getRootSession(input.sessionID)

    // 1. Load the raw state to extract the objective
    const state = await loadEngagementState(rootSessionID)
    const objective = state?.objective

    // 2. Inject objective with strong anti-drift language
    if (objective) {
      output.context.push(
        `CRITICAL — OBJECTIVE (MUST PRESERVE VERBATIM):\n` +
        `This agent's sole objective is: "${objective}"\n` +
        `The agent MUST NOT deviate from this scope. Include this objective ` +
        `verbatim in the summary. Any tasks, findings, or progress described ` +
        `in the summary must relate to this objective.`
      )
    }

    // 3. Inject current phase if set
    if (state?.currentPhase) {
      output.context.push(
        `CURRENT PHASE: ${state.currentPhase}\n` +
        `Include the current engagement phase in the summary.`
      )
    }

    // 4. Inject todo progress
    if (serverUrl) {
      const todoSnapshot = await fetchTodos(input.sessionID, serverUrl)
      if (todoSnapshot) {
        output.context.push(
          `TASK PROGRESS — PRESERVE IN SUMMARY:\n` +
          `The agent's task list at time of compaction:\n` +
          `${todoSnapshot}\n` +
          `Include this task list with status markers in the summary. ` +
          `Tasks marked [completed] are DONE and must not be repeated. ` +
          `Tasks marked [in_progress] or [pending] are what remain.`
        )
      }
    }

    // 5. Inject full engagement state (ports, credentials, vulnerabilities, etc.)
    const engagementState = await getEngagementStateForInjection(rootSessionID)
    if (engagementState) {
      output.context.push(
        `ENGAGEMENT STATE — PRESERVE ALL DISCOVERIES:\n` +
        `The following contains ALL discoveries made during this penetration test. ` +
        `This data MUST be preserved in the summary — losing it means re-scanning ` +
        `targets and losing credentials, vulnerabilities, and attack progress.\n\n` +
        engagementState
      )
    }

    log.info("injected compaction context", {
      sessionID: input.sessionID.slice(-8),
      rootSessionID: rootSessionID.slice(-8),
      hasObjective: !!objective,
      hasPhase: !!state?.currentPhase,
      hasEngagementState: !!engagementState,
    })
  } catch (error) {
    log.error("hook failed, proceeding without modification", {
      error: error instanceof Error ? error.message : String(error),
    })
  }
}
