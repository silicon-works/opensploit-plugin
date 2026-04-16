import { z } from "zod"
import { tool, type ToolContext } from "@opencode-ai/plugin"
import path from "path"
import fs from "fs/promises"
import yaml from "js-yaml"
import { createLog } from "../util/log"
import * as SessionDirectory from "../session/directory"
import { getRootSession } from "../session/hierarchy"

// Pattern capture not migrated yet — auto-capture is optional
let checkAutoCapturePattern: ((sessionID: string, prev?: string, next?: string) => Promise<void>) | undefined
try {
  const mod = require("../pattern/capture")
  checkAutoCapturePattern = mod.checkAutoCapturePattern
} catch {
  // pattern/ module not available yet — auto-capture disabled
}


const log = createLog("tool.engagement-state")

// =============================================================================
// Feature 03: Phase Management - Engagement State Tool
// =============================================================================
// Provides state sharing between agents during penetration testing engagements.
//
// Key behaviors:
// - Merges arrays (appends items)
// - Replaces scalar values
// - Persists to /tmp/opensploit-session-{rootSessionID}/state.yaml
// - Available to all agents for sharing discoveries
//
// Updated for Feature 04: Uses SessionDirectory for /tmp/ storage

// Storage paths - directly in session directory per Feature 04 spec
const STATE_FILE = "state.yaml"
const STATE_HISTORY_FILE = "state_history.yaml"
const FINDINGS_DIR = "findings"

// -----------------------------------------------------------------------------
// State Schema (flexible - LLM determines fields)
// -----------------------------------------------------------------------------
// We use a permissive schema since the LLM decides what fields to include.
// Common fields are documented but not strictly enforced.

const PortInfoSchema = z.object({
  port: z.number(),
  protocol: z.enum(["tcp", "udp"]).default("tcp"),
  service: z.string().optional(),
  version: z.string().optional(),
  state: z.enum(["open", "closed", "filtered"]).optional(),
  banner: z.string().optional(),
}).passthrough()

const CredentialInfoSchema = z.object({
  username: z.string(),
  password: z.string().optional(),
  hash: z.string().optional(),
  key: z.string().optional(),
  service: z.string().optional(),
  validated: z.boolean().optional(),
  privileged: z.boolean().optional(),
  source: z.string().optional(),
}).passthrough()

const VulnerabilityInfoSchema = z.object({
  name: z.string(),
  severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
  service: z.string().optional(),
  port: z.number().optional(),
  cve: z.string().optional(),
  exploitable: z.boolean().optional(),
  exploited: z.boolean().optional(),
  accessGained: z.enum(["none", "user", "root"]).optional(),
}).passthrough()

const SessionInfoSchema = z.object({
  id: z.string(),
  type: z.enum(["ssh", "reverse", "webshell", "meterpreter"]).optional(),
  user: z.string().optional(),
  privileged: z.boolean().optional(),
  established: z.string().optional(),
  notes: z.string().optional(),
}).passthrough()

const FileInfoSchema = z.object({
  path: z.string(),
  type: z.enum(["config", "credential", "flag", "suid", "writable", "interesting"]).optional(),
  content: z.string().optional(),
  notes: z.string().optional(),
}).passthrough()

const FailedAttemptSchema = z.object({
  action: z.string(),
  tool: z.string().optional(),
  reason: z.string(),
  timestamp: z.string().optional(),
}).passthrough()

const ToolFailureSchema = z.object({
  tool: z.string(),
  method: z.string().optional(),
  error: z.string(),
  count: z.number().default(1),
  firstSeen: z.string(),
  lastSeen: z.string(),
  argsSummary: z.string().optional(),
}).passthrough()

const AttackStepSchema = z.object({
  step: z.number(),
  description: z.string(),
  source: z.string().optional(),
  status: z.enum(["pending", "in_progress", "completed", "failed", "skipped"]).default("pending"),
  notes: z.string().optional(),
}).passthrough()

const AttackPlanSchema = z.object({
  title: z.string(),
  source: z.string(),
  steps: z.array(AttackStepSchema),
}).passthrough()

const ToolSearchCacheEntrySchema = z.object({
  query: z.string(),
  phase: z.string().optional(),
  results: z.array(z.object({
    tool: z.string(),
    method: z.string().optional(),
  })),
  timestamp: z.string(),
}).passthrough()

const TargetInfoSchema = z.object({
  ip: z.string(),
  hostname: z.string().optional(),
}).passthrough()

// Main state schema - permissive to allow LLM flexibility
const EngagementStateSchema = z.object({
  target: TargetInfoSchema.optional(),
  ports: z.array(PortInfoSchema).optional(),
  credentials: z.array(CredentialInfoSchema).optional(),
  vulnerabilities: z.array(VulnerabilityInfoSchema).optional(),
  sessions: z.array(SessionInfoSchema).optional(),
  files: z.array(FileInfoSchema).optional(),
  failedAttempts: z.array(FailedAttemptSchema).optional(),
  toolFailures: z.array(ToolFailureSchema).optional(),
  attackPlan: AttackPlanSchema.optional(),
  toolSearchCache: z.array(ToolSearchCacheEntrySchema).optional(),
  accessLevel: z.enum(["none", "user", "root"]).optional(),
  flags: z.array(z.string()).optional(),
}).passthrough()

export type EngagementState = z.infer<typeof EngagementStateSchema>

// -----------------------------------------------------------------------------
// State Snapshot Types (Phase 0 - Doc 13 Pattern Learning)
// -----------------------------------------------------------------------------
// Historical state tracking for pivotal step detection.
// Each state change is recorded to enable before/after comparisons.

/**
 * A point-in-time snapshot of engagement state.
 * Used by pattern learning (Doc 13) for pivotal step detection.
 */
export interface StateSnapshot {
  /** Unix timestamp when snapshot was taken */
  timestamp: number
  /** Step index (auto-incremented, correlates to state change sequence) */
  stepIndex: number
  /** The engagement state at this point */
  state: EngagementState
}

// -----------------------------------------------------------------------------
// File System Helpers
// -----------------------------------------------------------------------------
// Uses /tmp/opensploit-session-{sessionID}/ for engagement data storage.
// Session directory is created on first write if it doesn't exist.

function getSessionDir(sessionID: string): string {
  return SessionDirectory.get(sessionID)
}

function getStatePath(sessionID: string): string {
  return SessionDirectory.statePath(sessionID)
}

function getStateHistoryPath(sessionID: string): string {
  return path.join(getSessionDir(sessionID), STATE_HISTORY_FILE)
}

async function ensureSessionDir(sessionID: string): Promise<string> {
  const dir = getSessionDir(sessionID)
  if (!SessionDirectory.exists(sessionID)) {
    SessionDirectory.create(sessionID)
  }
  return dir
}

async function ensureFindingsDir(sessionID: string): Promise<string> {
  await ensureSessionDir(sessionID)
  return SessionDirectory.findingsDir(sessionID)
}

// -----------------------------------------------------------------------------
// State Management
// -----------------------------------------------------------------------------

/**
 * Per-session mutex to prevent lost-update race conditions.
 * When two sub-agents update state concurrently, without this mutex
 * the second write silently overwrites the first (BUG-ES-1).
 */
const sessionLocks = new Map<string, Promise<void>>()

export async function withSessionLock<T>(sessionID: string, fn: () => Promise<T>): Promise<T> {
  // Wait for any existing operation on this session to complete
  const existing = sessionLocks.get(sessionID)
  let resolve: () => void
  const lock = new Promise<void>((r) => { resolve = r })
  sessionLocks.set(sessionID, lock)

  if (existing) await existing

  try {
    return await fn()
  } finally {
    resolve!()
    if (sessionLocks.get(sessionID) === lock) {
      sessionLocks.delete(sessionID)
    }
  }
}

export async function loadEngagementState(sessionID: string): Promise<EngagementState> {
  try {
    const statePath = getStatePath(sessionID)
    const content = await fs.readFile(statePath, "utf-8")
    const parsed = yaml.load(content)
    // BUG-ES-2 fix: validate parsed is a plain object, not string/number/array
    if (parsed === null || parsed === undefined) return {}
    if (typeof parsed !== "object" || Array.isArray(parsed)) {
      log.error("Corrupt state.yaml — expected object, got " + typeof parsed, { sessionID: sessionID.slice(-8) })
      return {}
    }
    return parsed as EngagementState
  } catch (error: any) {
    if (error.code === "ENOENT") {
      return {}
    }
    log.error("Failed to load engagement state", { error: error.message })
    return {}
  }
}

export async function saveEngagementState(sessionID: string, state: EngagementState): Promise<void> {
  // Ensure session directory exists before writing
  await ensureSessionDir(sessionID)

  const statePath = getStatePath(sessionID)
  const content = yaml.dump(state, {
    indent: 2,
    lineWidth: 120,
    noRefs: true,
    sortKeys: false,
  })
  await fs.writeFile(statePath, content, "utf-8")
  log.info("Saved engagement state", { sessionID: sessionID.slice(-8), path: statePath })

  // Append to state history for pattern learning (Doc 13)
  await appendStateHistory(sessionID, state)
}

// -----------------------------------------------------------------------------
// State History Management (Doc 13 - Pattern Learning)
// -----------------------------------------------------------------------------
// Append-only history of state changes for pivotal step detection.

/**
 * Append current state to history file.
 * Called automatically by saveEngagementState().
 */
async function appendStateHistory(sessionID: string, state: EngagementState): Promise<void> {
  const historyPath = getStateHistoryPath(sessionID)

  // Load existing history or start fresh
  let history: StateSnapshot[] = []
  try {
    const content = await fs.readFile(historyPath, "utf-8")
    const parsed = yaml.load(content)
    if (Array.isArray(parsed)) {
      history = parsed as StateSnapshot[]
    }
  } catch (error: any) {
    if (error.code !== "ENOENT") {
      log.error("Failed to load state history", { error: error.message })
    }
    // File doesn't exist yet - start with empty array
  }

  // Create new snapshot
  const snapshot: StateSnapshot = {
    timestamp: Date.now(),
    stepIndex: history.length, // Auto-increment based on history size
    state,
  }

  // Append and save
  history.push(snapshot)
  const content = yaml.dump(history, {
    indent: 2,
    lineWidth: 120,
    noRefs: true,
    sortKeys: false,
  })
  await fs.writeFile(historyPath, content, "utf-8")
  log.debug("Appended state snapshot", { sessionID: sessionID.slice(-8), stepIndex: snapshot.stepIndex })
}

/**
 * Get all state snapshots for a session.
 * Used by pattern learning (Doc 13) for pivotal step detection.
 *
 * @returns Chronological array of state snapshots, or empty array if no history
 */
export async function getStateSnapshots(sessionID: string): Promise<StateSnapshot[]> {
  const historyPath = getStateHistoryPath(sessionID)

  try {
    const content = await fs.readFile(historyPath, "utf-8")
    const parsed = yaml.load(content)
    if (Array.isArray(parsed)) {
      return parsed as StateSnapshot[]
    }
    return []
  } catch (error: any) {
    if (error.code === "ENOENT") {
      return [] // No history yet
    }
    log.error("Failed to load state snapshots", { error: error.message })
    return []
  }
}

/**
 * Get the state snapshot at or before a given step index.
 * Used for before/after comparisons in pivotal step detection.
 *
 * @param snapshots - Array of state snapshots
 * @param stepIndex - The step index to find
 * @returns The snapshot at or before stepIndex, or undefined if none found
 */
export function getStateAtStep(
  snapshots: StateSnapshot[],
  stepIndex: number
): StateSnapshot | undefined {
  // Find snapshot at or before stepIndex
  const candidates = snapshots.filter(s => s.stepIndex <= stepIndex)
  if (candidates.length === 0) return undefined

  // Return the one closest to stepIndex (highest stepIndex <= target)
  return candidates.sort((a, b) => b.stepIndex - a.stepIndex)[0]
}

/**
 * Detect if a significant state change occurred between two snapshots.
 * Used by pattern learning to identify pivotal steps.
 *
 * @returns Object describing detected changes
 */
export function detectStateChanges(
  before: StateSnapshot | undefined,
  after: StateSnapshot
): {
  accessLevelChanged: boolean
  credentialsAdded: number
  vulnerabilitiesAdded: number
  sessionsAdded: number
  flagsAdded: number
  fromAccess?: string
  toAccess?: string
} {
  const beforeState = before?.state ?? {}
  const afterState = after.state

  const beforeCredCount = beforeState.credentials?.length ?? 0
  const afterCredCount = afterState.credentials?.length ?? 0

  const beforeVulnCount = beforeState.vulnerabilities?.length ?? 0
  const afterVulnCount = afterState.vulnerabilities?.length ?? 0

  const beforeSessionCount = beforeState.sessions?.length ?? 0
  const afterSessionCount = afterState.sessions?.length ?? 0

  const beforeFlagCount = beforeState.flags?.length ?? 0
  const afterFlagCount = afterState.flags?.length ?? 0

  // Normalize access levels: treat undefined as "none"
  const beforeAccess = beforeState.accessLevel ?? "none"
  const afterAccess = afterState.accessLevel ?? "none"
  const accessChanged = beforeAccess !== afterAccess

  return {
    accessLevelChanged: accessChanged,
    credentialsAdded: Math.max(0, afterCredCount - beforeCredCount),
    vulnerabilitiesAdded: Math.max(0, afterVulnCount - beforeVulnCount),
    sessionsAdded: Math.max(0, afterSessionCount - beforeSessionCount),
    flagsAdded: Math.max(0, afterFlagCount - beforeFlagCount),
    ...(accessChanged ? {
      fromAccess: beforeAccess,
      toAccess: afterAccess,
    } : {}),
  }
}

/**
 * Merge updates into existing state.
 * - Arrays are appended (with deduplication for some fields)
 * - Scalars are replaced
 * - Objects are merged recursively
 *
 * Exported for testing.
 */
export function mergeState(existing: EngagementState, updates: Partial<EngagementState>): EngagementState {
  const result = { ...existing }

  for (const [key, value] of Object.entries(updates)) {
    if (value === undefined || value === null) continue

    const existingValue = (result as any)[key]

    if (Array.isArray(value)) {
      // Merge arrays - append new items
      const existingArray = Array.isArray(existingValue) ? existingValue : []

      // For certain arrays, deduplicate by key fields
      if (key === "ports") {
        // Dedupe by port+protocol (default missing protocol to "tcp")
        const merged = [...existingArray]
        for (const item of value) {
          // Skip entries with NaN/invalid port (NaN !== NaN breaks dedup)
          if (typeof item.port !== "number" || Number.isNaN(item.port)) continue
          const itemProto = item.protocol || "tcp"
          const exists = merged.some(
            (p: any) => p.port === item.port && (p.protocol || "tcp") === itemProto
          )
          if (!exists) merged.push(item)
          else {
            // Update existing entry
            const idx = merged.findIndex(
              (p: any) => p.port === item.port && (p.protocol || "tcp") === itemProto
            )
            if (idx !== -1) merged[idx] = { ...merged[idx], ...item }
          }
        }
        (result as any)[key] = merged
      } else if (key === "credentials") {
        // Dedupe by username+service
        const merged = [...existingArray]
        for (const item of value) {
          const exists = merged.some(
            (c: any) => c.username === item.username && c.service === item.service
          )
          if (!exists) merged.push(item)
          else {
            // Update existing entry
            const idx = merged.findIndex(
              (c: any) => c.username === item.username && c.service === item.service
            )
            if (idx !== -1) merged[idx] = { ...merged[idx], ...item }
          }
        }
        (result as any)[key] = merged
      } else if (key === "sessions") {
        // Dedupe by id
        const merged = [...existingArray]
        for (const item of value) {
          const exists = merged.some((s: any) => s.id === item.id)
          if (!exists) merged.push(item)
          else {
            const idx = merged.findIndex((s: any) => s.id === item.id)
            if (idx !== -1) merged[idx] = { ...merged[idx], ...item }
          }
        }
        (result as any)[key] = merged
      } else if (key === "flags") {
        // Dedupe flags (simple strings)
        const merged = [...new Set([...existingArray, ...value])]
        ;(result as any)[key] = merged
      } else if (key === "toolFailures") {
        // Dedup by tool+method, increment count
        // To clear all failures, use resetToolFailures: true (not an empty array)
        const merged = [...existingArray]
        for (const item of value) {
          const idx = merged.findIndex(
            (f: any) => f.tool === item.tool && (f.method || "") === (item.method || "")
          )
          if (idx !== -1) {
            // BUG-ES-6/ES-7 fix: use ?? instead of || (0 is valid count),
            // and add incoming count instead of always +1
            merged[idx] = {
              ...merged[idx],
              count: (merged[idx].count ?? 0) + (item.count ?? 1),
              lastSeen: item.lastSeen || new Date().toISOString(),
              error: item.error,
            }
          } else {
            merged.push(item)
          }
        }
        (result as any)[key] = merged
      } else if (key === "toolSearchCache") {
        // Dedup by query (case-insensitive), cap at 20
        const merged = [...existingArray]
        for (const item of value) {
          const idx = merged.findIndex(
            (c: any) => c.query.toLowerCase().trim() === item.query.toLowerCase().trim()
          )
          if (idx !== -1) {
            merged[idx] = item
          } else {
            merged.push(item)
          }
        }
        (result as any)[key] = merged.slice(-20)
      } else {
        // For other arrays (vulnerabilities, files, failedAttempts), just append
        (result as any)[key] = [...existingArray, ...value]
      }
    } else if (typeof value === "object" && !Array.isArray(value)) {
      // attackPlan uses replace semantics (not recursive merge)
      if (key === "attackPlan") {
        (result as any)[key] = value
      } else if (typeof existingValue === "object" && !Array.isArray(existingValue)) {
        (result as any)[key] = { ...existingValue, ...value }
      } else {
        (result as any)[key] = value
      }
    } else {
      // Replace scalars
      (result as any)[key] = value
    }
  }

  return result
}

// -----------------------------------------------------------------------------
// Tool Definition
// -----------------------------------------------------------------------------

const DESCRIPTION = `Update the engagement state for the current penetration test session.

This tool maintains shared state between agents, tracking:
- **target**: Target IP and hostname
- **ports**: Discovered ports and services
- **credentials**: Found credentials (usernames, passwords, hashes, keys)
- **vulnerabilities**: Identified vulnerabilities
- **sessions**: Active shell sessions
- **files**: Interesting files found (configs, credentials, flags, SUID binaries)
- **failedAttempts**: What was tried and failed (to avoid repetition)
- **accessLevel**: Current access level (none, user, root)
- **flags**: Captured flags (CTF)

**Merge behavior:**
- Arrays are appended (ports, credentials deduplicated by key fields)
- Scalar values are replaced
- Objects are merged

**Important:** Check \`failedAttempts\` before trying an attack vector. If a similar action already failed, try a different approach.

**Example usage:**
\`\`\`
// Record discovered ports
update_engagement_state({
  ports: [
    { port: 22, protocol: "tcp", service: "ssh", version: "OpenSSH 8.2p1" }
  ]
})

// Record a failed attempt
update_engagement_state({
  failedAttempts: [
    { action: "SSH brute force as root", tool: "hydra", reason: "No valid password found" }
  ]
})

// Update access level after exploitation
update_engagement_state({
  accessLevel: "user",
  sessions: [
    { id: "shell-1", type: "reverse", user: "www-data" }
  ]
})
\`\`\``

const UpdateParametersSchema = z.object({
  target: TargetInfoSchema.optional().describe("Target information (IP, hostname)"),
  ports: z.array(PortInfoSchema).optional().describe("Discovered ports/services to add"),
  credentials: z.array(CredentialInfoSchema).optional().describe("Credentials to add"),
  vulnerabilities: z.array(VulnerabilityInfoSchema).optional().describe("Vulnerabilities to add"),
  sessions: z.array(SessionInfoSchema).optional().describe("Shell sessions to add"),
  files: z.array(FileInfoSchema).optional().describe("Interesting files to add"),
  failedAttempts: z.array(FailedAttemptSchema).optional().describe("Failed attempts to record"),
  accessLevel: z.enum(["none", "user", "root"]).optional().describe("Update access level"),
  flags: z.array(z.string()).optional().describe("Captured flags to add"),
  resetToolFailures: z.boolean().optional().describe("Set to true to clear ALL tool failure counters, unblocking skipped tools"),
}).passthrough()

export function createUpdateEngagementStateTool() {
  return tool({
    description: DESCRIPTION,
    args: {
      target: TargetInfoSchema.optional().describe("Target information (IP, hostname)"),
      ports: z.array(PortInfoSchema).optional().describe("Discovered ports/services to add"),
      credentials: z.array(CredentialInfoSchema).optional().describe("Credentials to add"),
      vulnerabilities: z.array(VulnerabilityInfoSchema).optional().describe("Vulnerabilities to add"),
      sessions: z.array(SessionInfoSchema).optional().describe("Shell sessions to add"),
      files: z.array(FileInfoSchema).optional().describe("Interesting files to add"),
      failedAttempts: z.array(FailedAttemptSchema).optional().describe("Failed attempts to record"),
      accessLevel: z.enum(["none", "user", "root"]).optional().describe("Update access level"),
      flags: z.array(z.string()).optional().describe("Captured flags to add"),
      resetToolFailures: z.boolean().optional().describe("Set to true to clear ALL tool failure counters"),
    },
    async execute(params, ctx): Promise<string> {
      // Use root session ID so all agents in the tree share the same state
      const sessionID = getRootSession(ctx.sessionID)

      // BUG-ES-1 fix: wrap load-merge-save in per-session lock to prevent
      // concurrent sub-agents from overwriting each other's changes
      return withSessionLock(sessionID, async () => {

      log.info("update_engagement_state called", {
        sessionID: sessionID.slice(-8),
        callerSessionID: ctx.sessionID.slice(-8),
        keys: Object.keys(params)
      })

      // Load existing state
      const existingState = await loadEngagementState(sessionID)

      // Capture previous access level for auto-capture check (Doc 13 §Auto-Capture)
      const previousAccessLevel = existingState.accessLevel as "none" | "user" | "root" | undefined

      // Merge updates
      const newState = mergeState(existingState, params)

      // Handle resetToolFailures boolean shortcut
      if (params.resetToolFailures === true) {
        newState.toolFailures = []
      }

      // Save updated state
      await saveEngagementState(sessionID, newState)

      // Check for auto-capture trigger (Doc 13 §Pattern Capture)
      // Run asynchronously to not block the tool response
      const newAccessLevel = newState.accessLevel as "none" | "user" | "root" | undefined
      if (previousAccessLevel !== newAccessLevel && checkAutoCapturePattern) {
        // Fire and forget - don't await, don't block
        checkAutoCapturePattern(sessionID, previousAccessLevel, newAccessLevel).catch((err: unknown) => {
          log.error("auto-capture failed", { error: String(err) })
        })
      }

      // Build summary of what was updated
      const updates: string[] = []
      if (params.target) updates.push(`target: ${params.target.ip}`)
      if (params.ports?.length) updates.push(`ports: +${params.ports.length}`)
      if (params.credentials?.length) updates.push(`credentials: +${params.credentials.length}`)
      if (params.vulnerabilities?.length) updates.push(`vulnerabilities: +${params.vulnerabilities.length}`)
      if (params.sessions?.length) updates.push(`sessions: +${params.sessions.length}`)
      if (params.files?.length) updates.push(`files: +${params.files.length}`)
      if (params.failedAttempts?.length) updates.push(`failedAttempts: +${params.failedAttempts.length}`)
      if (params.accessLevel) updates.push(`accessLevel: ${params.accessLevel}`)
      if (params.flags?.length) updates.push(`flags: +${params.flags.length}`)
      if (params.resetToolFailures === true) updates.push(`toolFailures: CLEARED`)

      const summary = updates.length > 0 ? updates.join(", ") : "no changes"

      ctx.metadata({
        title: `update_engagement_state: ${summary}`,
        metadata: {
          updated: Object.keys(params),
          state: {
            ports: newState.ports?.length ?? 0,
            credentials: newState.credentials?.length ?? 0,
            vulnerabilities: newState.vulnerabilities?.length ?? 0,
            sessions: newState.sessions?.length ?? 0,
            accessLevel: newState.accessLevel ?? "none",
            flags: newState.flags?.length ?? 0,
          },
        },
      })

      // Return current state summary
      return [
        `**Engagement State Updated**`,
        ``,
        `Changes: ${summary}`,
        ``,
        `**Current State:**`,
        `- Target: ${newState.target?.ip ?? "not set"}${newState.target?.hostname ? ` (${newState.target.hostname})` : ""}`,
        `- Ports: ${newState.ports?.length ?? 0} discovered`,
        `- Credentials: ${newState.credentials?.length ?? 0} found`,
        `- Vulnerabilities: ${newState.vulnerabilities?.length ?? 0} identified`,
        `- Sessions: ${newState.sessions?.length ?? 0} active`,
        `- Files: ${newState.files?.length ?? 0} of interest`,
        `- Failed Attempts: ${newState.failedAttempts?.length ?? 0} recorded`,
        `- Access Level: ${newState.accessLevel ?? "none"}`,
        `- Flags: ${newState.flags?.length ?? 0} captured`,
      ].join("\n")

      }) // end withSessionLock
    },
  })
}

// -----------------------------------------------------------------------------
// Read State Tool (for querying current state)
// -----------------------------------------------------------------------------

const READ_DESCRIPTION = `Read the current engagement state for the penetration test session.

Returns the full state including all discoveries, credentials, vulnerabilities, and failed attempts.
Use this to check what has been found and what has been tried before deciding on next steps.

**Important:** Check \`failedAttempts\` before trying an attack vector to avoid repeating failed approaches.`

export function createReadEngagementStateTool() {
  return tool({
    description: READ_DESCRIPTION,
    args: {},
    async execute(_params, ctx): Promise<string> {
      // Use root session ID so all agents in the tree share the same state
      const sessionID = getRootSession(ctx.sessionID)

      log.info("read_engagement_state called", {
        sessionID: sessionID.slice(-8),
        callerSessionID: ctx.sessionID.slice(-8)
      })

      const state = await loadEngagementState(sessionID)

      if (Object.keys(state).length === 0) {
        ctx.metadata({
          title: "read_engagement_state: empty",
          metadata: { empty: true },
        })
        return "No engagement state found. Use `update_engagement_state` to record discoveries."
      }

      const output = yaml.dump(state, {
        indent: 2,
        lineWidth: 120,
        noRefs: true,
      })

      ctx.metadata({
        title: `read_engagement_state: ${state.target?.ip ?? "no target"}`,
        metadata: {
          empty: false,
          target: state.target?.ip,
          ports: state.ports?.length ?? 0,
          credentials: state.credentials?.length ?? 0,
          vulnerabilities: state.vulnerabilities?.length ?? 0,
          accessLevel: state.accessLevel ?? "none",
        },
      })

      return `**Current Engagement State:**\n\n\`\`\`yaml\n${output}\`\`\``
    },
  })
}

// -----------------------------------------------------------------------------
// Helper for Context Injection (used by Task tool when spawning subagents)
// -----------------------------------------------------------------------------

/**
 * Get engagement state formatted for injection into subagent context.
 * Called by Task tool when spawning pentest subagents.
 */
export async function getEngagementStateForInjection(sessionID: string): Promise<string | null> {
  try {
    const state = await loadEngagementState(sessionID)

    if (Object.keys(state).length === 0) {
      return null
    }

    const sections: string[] = []

    // RC2: Port accessibility summary (prepend — most actionable info first)
    if (Array.isArray(state.ports) && state.ports.length > 0) {
      const open = state.ports.filter((p: any) => p.state === "open" || !p.state)
      const filtered = state.ports.filter((p: any) => p.state === "filtered")

      const portLines: string[] = ["### Port Accessibility"]
      if (open.length > 0) {
        portLines.push("**OPEN:** " + open.map(
          (p: any) => `${p.port}/${p.protocol || "tcp"} (${p.service || "unknown"})`
        ).join(", "))
      }
      if (filtered.length > 0) {
        portLines.push("**FILTERED (blocked, do NOT target):** " +
          filtered.map((p: any) => `${p.port}/${p.protocol || "tcp"}`).join(", "))
      }
      sections.push(portLines.join("\n"))
    }

    // RC5: Attack plan
    const plan = (state as any).attackPlan
    if (plan && Array.isArray(plan.steps)) {
      const planLines: string[] = [
        `### Attack Plan: ${plan.title}`,
        `Source: ${plan.source}`,
        "",
      ]
      for (const step of plan.steps) {
        const marker = ({ pending: "[ ]", in_progress: "[>]", completed: "[x]", failed: "[!]", skipped: "[-]" } as Record<string, string>)[step.status] || "[ ]"
        planLines.push(`${marker} Step ${step.step}: ${step.description}${step.source ? ` (${step.source})` : ""}`)
        if (step.notes) planLines.push(`    Notes: ${step.notes}`)
      }
      planLines.push("")
      planLines.push("**Follow this plan. Deviations require justification in TVAR reasoning.**")
      sections.push(planLines.join("\n"))
    }

    // Core: YAML state dump
    const stateYaml = yaml.dump(state, {
      indent: 2,
      lineWidth: 120,
      noRefs: true,
    })
    sections.push("## Current Engagement State\n\nThe following discoveries have been made by other agents. Use this information and avoid repeating failed attempts.\n\n```yaml\n" + stateYaml + "```")

    // RC1: Broken tools warning
    const toolFailures = (state as any).toolFailures
    if (Array.isArray(toolFailures) && toolFailures.length > 0) {
      const warnings = toolFailures
        .filter((f: any) => (f.count || 0) >= 2)
        .map((f: any) => `- **${f.tool}${f.method ? '.' + f.method : ''}**: ${f.error} (failed ${f.count}x)`)
      if (warnings.length > 0) {
        sections.push("### BROKEN TOOLS (Do NOT retry — find alternatives via tool_registry_search)\n\n" + warnings.join("\n"))
      }
    }

    // RC6: Tool search cache
    const cache = (state as any).toolSearchCache
    if (Array.isArray(cache) && cache.length > 0) {
      const cacheLines = cache.slice(-10).map((e: any) => {
        const tools = (e.results || []).map((r: any) => `${r.tool}${r.method ? '.' + r.method : ''}`).join(", ")
        return `- "${e.query}" → ${tools}`
      })
      sections.push("### Recent Tool Searches (use results directly, avoid re-searching)\n\n" + cacheLines.join("\n"))
    }

    return sections.join("\n\n")
  } catch (error) {
    log.error("Failed to get engagement state for injection", { error })
    return null
  }
}

/**
 * Get the path to the findings directory for a session.
 * Subagents write detailed findings here (e.g., findings/recon.md).
 */
export async function getFindingsDir(sessionID: string): Promise<string> {
  return ensureFindingsDir(sessionID)
}
