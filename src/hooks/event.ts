/**
 * Event hook — trajectory recording
 *
 * Listens to bus events and writes trajectory.jsonl entries in real-time.
 * Produces the same JSONL format as the fat fork's batch export.
 *
 * Events handled:
 * - message.updated: Caches message-level info (model, tokens, cost, agent)
 * - message.part.updated: Maps parts to TrajectoryEntry and appends to JSONL
 * - session.created: Writes initial session.json metadata
 *
 * The event hook receives `{ event: Event }` where Event is from the SDK.
 * In the opensploit fork, parts include the custom "tvar" type.
 */

import { createLog } from "../util/log.js"
import { getRootSession } from "../session/hierarchy.js"
import { cleanupSessionHosts } from "../tools/hosts.js"
import {
  appendEntry,
  writeSessionMeta,
  type TrajectoryEntry,
  type SessionMeta,
} from "../training/trajectory.js"

const log = createLog("hook.event")

/**
 * Cached message info from message.updated events.
 * Keyed by messageID. Used to enrich part events with message-level data
 * (tokens, cost, model, provider, agent, parentID).
 */
interface CachedMessageInfo {
  sessionID: string
  role: "user" | "assistant"
  modelID: string
  providerID: string
  agent: string
  parentID?: string
  tokens?: {
    input: number
    output: number
    reasoning: number
    cacheRead: number
    cacheWrite: number
  }
  cost?: number
  timeCreated: number
}

const messageCache = new Map<string, CachedMessageInfo>()

/**
 * Set of partIDs already written to trajectory, to avoid duplicates.
 * Parts can be updated multiple times (e.g., tool: pending -> running -> completed).
 * For tools we only want the final state; for text/tvar the first complete version.
 */
const writtenParts = new Map<string, string>() // partID -> status written (for tools)

/** Maximum entries before evicting oldest from messageCache / writtenParts */
const CACHE_MAX = 1000

/**
 * Evict the oldest entries from a Map when it exceeds CACHE_MAX.
 * Deletes the first (oldest-inserted) entries via the Map iterator.
 */
function evictOldest<K, V>(map: Map<K, V>): void {
  if (map.size <= CACHE_MAX) return
  const excess = map.size - CACHE_MAX
  const iter = map.keys()
  for (let i = 0; i < excess; i++) {
    const { value, done } = iter.next()
    if (done) break
    map.delete(value as K)
  }
}

/**
 * Set of sessions for which we've written session.json.
 */
const initializedSessions = new Set<string>()

export async function eventHook(input: { event: any }): Promise<void> {
  const { event } = input
  if (!event || !event.type) return

  try {
    switch (event.type) {
      case "session.created":
        handleSessionCreated(event)
        break
      case "message.updated":
        handleMessageUpdated(event)
        break
      case "message.part.updated":
        handlePartUpdated(event)
        break
      case "session.deleted":
        await cleanupSessionHosts(event.properties?.id ?? event.id)
        break
    }
  } catch (error) {
    // Never crash the host — trajectory recording is best-effort
    log.error("event hook failed", {
      eventType: event.type,
      error: error instanceof Error ? error.message : String(error),
    })
  }
}

/**
 * Handle session.created — write initial session.json.
 */
function handleSessionCreated(event: any): void {
  const props = event.properties
  if (!props?.info) return

  const session = props.info
  const sessionID: string = session.id
  if (!sessionID) return

  // Only write session.json for root sessions (no parentID)
  if (session.parentID) return

  const rootID = getRootSession(sessionID)

  if (initializedSessions.has(rootID)) return
  initializedSessions.add(rootID)

  const meta: SessionMeta = {
    sessionID: rootID,
    model: "unknown",
    providerID: "unknown",
    startTime: new Date(session.time?.created ?? Date.now()).toISOString(),
    title: session.title,
  }

  writeSessionMeta(rootID, meta)
}

/**
 * Handle message.updated — cache message-level info for joining with parts.
 */
function handleMessageUpdated(event: any): void {
  const props = event.properties
  if (!props?.info) return

  const msg = props.info
  const messageID: string = msg.id
  const sessionID: string = msg.sessionID
  if (!messageID || !sessionID) return

  const role: "user" | "assistant" = msg.role
  let modelID: string
  let providerID: string
  let agent: string
  let parentID: string | undefined
  let tokens: CachedMessageInfo["tokens"]
  let cost: number | undefined

  if (role === "assistant") {
    modelID = msg.modelID ?? "unknown"
    providerID = msg.providerID ?? "unknown"
    agent = msg.agent ?? "master"
    parentID = msg.parentID
    cost = msg.cost
    if (msg.tokens) {
      tokens = {
        input: msg.tokens.input ?? 0,
        output: msg.tokens.output ?? 0,
        reasoning: msg.tokens.reasoning ?? 0,
        cacheRead: msg.tokens.cache?.read ?? 0,
        cacheWrite: msg.tokens.cache?.write ?? 0,
      }
    }
  } else {
    // User message
    modelID = msg.model?.modelID ?? "unknown"
    providerID = msg.model?.providerID ?? "unknown"
    agent = msg.agent ?? "master"
    parentID = undefined
    tokens = undefined
    cost = undefined
  }

  messageCache.set(messageID, {
    sessionID,
    role,
    modelID,
    providerID,
    agent,
    parentID,
    tokens,
    cost,
    timeCreated: msg.time?.created ?? Date.now(),
  })
  evictOldest(messageCache)

  // Update session.json with model info on first assistant message
  const rootID = getRootSession(sessionID)
  if (role === "assistant" && !initializedSessions.has(rootID)) {
    initializedSessions.add(rootID)
    const meta: SessionMeta = {
      sessionID: rootID,
      model: modelID,
      providerID,
      startTime: new Date(msg.time?.created ?? Date.now()).toISOString(),
    }
    writeSessionMeta(rootID, meta)
  }
}

/**
 * Handle message.part.updated — map to TrajectoryEntry and append.
 */
function handlePartUpdated(event: any): void {
  const props = event.properties
  if (!props?.part) return

  const part = props.part
  const partID: string = part.id
  const messageID: string = part.messageID
  const sessionID: string = part.sessionID
  if (!partID || !messageID || !sessionID) return

  const partType: string = part.type

  // Only record text, tvar, and tool parts
  if (partType !== "text" && partType !== "tvar" && partType !== "tool") return

  // For tool parts, only record when completed or error (not pending/running)
  if (partType === "tool") {
    const status: string = part.state?.status
    if (status !== "completed" && status !== "error") return

    // Check if we already wrote this tool part in its final state
    const prevStatus = writtenParts.get(partID)
    if (prevStatus === "completed" || prevStatus === "error") return
    writtenParts.set(partID, status)
    evictOldest(writtenParts)
  } else {
    // For text and tvar parts, only write once (first non-empty version)
    if (writtenParts.has(partID)) return

    // Skip empty text parts
    if (partType === "text" && !part.text) return
    if (partType === "tvar" && !part.thought) return

    // Skip synthetic/ignored text parts
    if (partType === "text" && (part.synthetic || part.ignored)) return

    writtenParts.set(partID, partType)
    evictOldest(writtenParts)
  }

  // Look up cached message info
  const msgInfo = messageCache.get(messageID)

  // Resolve root session for file path
  const rootID = getRootSession(sessionID)

  // Resolve agent name: use message agent, with pentest-style mapping
  const rawAgent = msgInfo?.agent ?? "master"
  const agentName = resolveAgentName(rawAgent)

  // Build base entry fields
  const baseEntry: Pick<
    TrajectoryEntry,
    "sessionID" | "messageID" | "partID" | "agentName" | "role" | "modelID" | "providerID"
  > & {
    parentMessageID?: string
    tokens?: TrajectoryEntry["tokens"]
    cost?: number
  } = {
    sessionID,
    messageID,
    partID,
    agentName,
    role: msgInfo?.role ?? "assistant",
    modelID: msgInfo?.modelID ?? "unknown",
    providerID: msgInfo?.providerID ?? "unknown",
    parentMessageID: msgInfo?.parentID,
    tokens: msgInfo?.tokens,
    cost: msgInfo?.cost,
  }

  // Strip undefined fields from base for cleaner JSON (match fat fork output)
  if (!baseEntry.parentMessageID) delete baseEntry.parentMessageID
  if (!baseEntry.tokens) delete baseEntry.tokens
  if (baseEntry.cost === undefined) delete baseEntry.cost

  let entry: TrajectoryEntry | null = null

  if (partType === "text") {
    entry = {
      ...baseEntry,
      timestamp: resolveTimestamp(part, msgInfo),
      type: "text",
      text: part.text,
    }
  } else if (partType === "tvar") {
    entry = {
      ...baseEntry,
      timestamp: resolveTimestamp(part, msgInfo),
      type: "tvar",
      ...(part.phase ? { phase: part.phase } : {}),
      thought: part.thought,
      verify: part.verify,
      ...(part.action ? { action: part.action } : {}),
      ...(part.result ? { result: part.result } : {}),
      ...(part.toolCallID ? { toolCallID: part.toolCallID } : {}),
    }
  } else if (partType === "tool") {
    entry = buildToolEntry(baseEntry, part, msgInfo)
  }

  if (entry) {
    appendEntry(rootID, entry)
    log.info("recorded", {
      rootID: rootID.slice(-8),
      type: entry.type,
      partID: partID.slice(-8),
      tool: entry.tool,
    })
  }
}

/**
 * Build a TrajectoryEntry for a tool part.
 */
function buildToolEntry(
  baseEntry: any,
  part: any,
  msgInfo: CachedMessageInfo | undefined,
): TrajectoryEntry {
  const state = part.state
  const status: string = state.status

  let toolOutput: string | undefined
  let toolError: string | undefined
  let toolMetadata: Record<string, unknown> | undefined
  let toolDuration: number | undefined
  let startMs: number | undefined

  if (status === "completed") {
    startMs = state.time?.start
    const endMs = state.time?.end
    toolOutput = state.output
    toolMetadata = state.metadata
    if (startMs && endMs) toolDuration = endMs - startMs
  } else if (status === "error") {
    startMs = state.time?.start
    const endMs = state.time?.end
    toolError = state.error
    toolMetadata = state.metadata
    if (startMs && endMs) toolDuration = endMs - startMs
  }

  const timestamp = startMs
    ? new Date(startMs).toISOString()
    : resolveTimestamp(part, msgInfo)

  const entry: TrajectoryEntry = {
    ...baseEntry,
    timestamp,
    type: "tool",
    tool: part.tool,
    callID: part.callID,
    toolInput: state.input,
    toolSuccess: status === "completed",
  }

  // Only include non-undefined optional tool fields
  if (toolOutput !== undefined) entry.toolOutput = toolOutput
  if (toolMetadata !== undefined) entry.toolMetadata = toolMetadata
  if (toolError !== undefined) entry.toolError = toolError
  if (toolDuration !== undefined) entry.toolDuration = toolDuration

  return entry
}

/**
 * Resolve a timestamp from a part or fall back to message creation time.
 * Returns ISO 8601 string to match fat fork format.
 */
function resolveTimestamp(part: any, msgInfo: CachedMessageInfo | undefined): string {
  // Part-level time
  if (part.time?.start) return new Date(part.time.start).toISOString()

  // Message-level time
  if (msgInfo?.timeCreated) return new Date(msgInfo.timeCreated).toISOString()

  // Fallback to now
  return new Date().toISOString()
}

/**
 * Map agent field to display name.
 * "pentest" -> "master", "pentest/recon" stays as-is, etc.
 */
function resolveAgentName(agent: string): string {
  if (agent === "pentest" || agent === "build") return "master"
  return agent
}
