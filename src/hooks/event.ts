/**
 * Event hook
 *
 * Listens to bus events for:
 * 1. Post-compaction re-injection — when a session is compacted, the
 *    engagement state context is lost. This hook re-injects it via
 *    the system.transform hook (which fires on the next LLM call).
 *    Pattern adopted from beads/agent-skills plugins.
 *
 * 2. Basic trajectory logging — writes session events to a JSONL file
 *    in the session directory for post-engagement analysis.
 *    (Deferred: full trajectory export with anonymization comes later)
 *
 * Note: The system.transform hook already injects engagement state on
 * every LLM turn. So post-compaction re-injection is automatic — the
 * next LLM call after compaction will pick up the state. This hook
 * is mainly for future trajectory recording.
 */

import { createLog } from "../util/log.js"

const log = createLog("hook.event")

export async function eventHook(input: { event: any }): Promise<void> {
  const { event } = input

  if (!event || !event.type) return

  // Post-compaction: no action needed because system.transform injects
  // engagement state on every LLM turn. After compaction, the next turn
  // automatically gets the latest state.
  //
  // If we needed explicit re-injection (like beads does), we would:
  // if (event.type === "session.compacted") {
  //   // Use client.session.prompt({ body: { noReply: true, parts: [...] } })
  //   // to inject a synthetic message with engagement state
  // }

  // TODO: Trajectory recording
  // When ready, write events to {sessionDir}/trajectory.jsonl:
  // - message.updated (text parts, tool calls)
  // - tool.execute.after (tool results)
  // - session.compacted (mark compaction points)
}
