/**
 * Trajectory Recording Module
 *
 * Appends trajectory entries to ~/.opensploit/sessions/{rootSessionID}/trajectory.jsonl
 * in the same format as the fat fork's training-data.ts batch export.
 *
 * Each line is a self-contained JSON object representing one message part:
 * - text: user prompts and assistant text
 * - tvar: structured reasoning (Thought-Verify-Action-Result)
 * - tool: tool invocations with input/output/metadata
 *
 * Uses synchronous file writes for ordering guarantees.
 *
 * Requirements:
 * - REQ-TRN-001: Capture agent trajectories for fine-tuning
 * - REQ-TRN-002: Store trajectories in structured format
 */

import path from "path"
import os from "os"
import { mkdirSync, appendFileSync, writeFileSync, existsSync } from "fs"
import { createLog } from "../util/log.js"

const log = createLog("training.trajectory")

const SESSIONS_DIR = path.join(os.homedir(), ".opensploit", "sessions")

/**
 * Training trajectory entry (one per line in JSONL).
 * Matches the fat fork's TrajectoryEntry format exactly.
 */
export interface TrajectoryEntry {
  // === Identity ===
  sessionID: string
  messageID: string
  partID: string
  agentName: string

  // === Message Context ===
  role: "user" | "assistant"
  modelID: string
  providerID: string
  parentMessageID?: string
  tokens?: {
    input: number
    output: number
    reasoning: number
    cacheRead: number
    cacheWrite: number
  }
  cost?: number

  // === Timing ===
  timestamp: string // ISO 8601

  // === Part Type ===
  type: "text" | "tvar" | "tool"

  // === Text Parts ===
  text?: string

  // === TVAR Parts ===
  phase?: string
  thought?: string
  verify?: string
  action?: string
  result?: string
  toolCallID?: string

  // === Tool Parts ===
  tool?: string
  callID?: string
  toolInput?: Record<string, unknown>
  toolOutput?: string
  toolMetadata?: Record<string, unknown>
  toolSuccess?: boolean
  toolError?: string
  toolDuration?: number
}

/**
 * Session metadata written to session.json.
 */
export interface SessionMeta {
  sessionID: string
  model: string
  providerID: string
  startTime: string
  title?: string
}

/**
 * Ensure the session directory exists. Returns the directory path.
 */
export function ensureSessionDir(sessionID: string): string {
  const dir = path.join(SESSIONS_DIR, sessionID)
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true })
    log.info("created session dir", { sessionID: sessionID.slice(-8) })
  }
  return dir
}

/**
 * Append one trajectory entry to trajectory.jsonl.
 * Uses appendFileSync for ordering guarantees.
 */
export function appendEntry(rootSessionID: string, entry: TrajectoryEntry): void {
  try {
    const dir = ensureSessionDir(rootSessionID)
    const filePath = path.join(dir, "trajectory.jsonl")
    appendFileSync(filePath, JSON.stringify(entry) + "\n", "utf-8")
  } catch (error) {
    log.error("append failed", {
      sessionID: rootSessionID.slice(-8),
      type: entry.type,
      error: error instanceof Error ? error.message : String(error),
    })
  }
}

/**
 * Write or update session.json metadata.
 */
export function writeSessionMeta(rootSessionID: string, meta: SessionMeta): void {
  try {
    const dir = ensureSessionDir(rootSessionID)
    const filePath = path.join(dir, "session.json")
    writeFileSync(filePath, JSON.stringify(meta, null, 2), "utf-8")
    log.info("wrote session.json", { sessionID: rootSessionID.slice(-8) })
  } catch (error) {
    log.error("session.json write failed", {
      sessionID: rootSessionID.slice(-8),
      error: error instanceof Error ? error.message : String(error),
    })
  }
}
