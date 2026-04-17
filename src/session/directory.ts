/**
 * Session Working Directory
 *
 * Manages session-scoped temporary directories for engagement documents,
 * findings, and artifacts. Uses OS temp location for automatic cleanup.
 *
 * Requirements:
 * - REQ-AGT-016: Session temp directory at /tmp/opensploit-session-{rootSessionID}/
 * - REQ-AGT-017: Cleanup when root session is deleted
 * - Sub-agents share the root session's temp directory
 *
 * Directory Structure:
 * /tmp/opensploit-session-{id}/
 * ├── state.yaml              # Engagement state (Feature 03)
 * ├── findings/
 * │   ├── recon.md            # Reconnaissance findings
 * │   ├── enum.md             # Enumeration findings
 * │   ├── exploit.md          # Exploitation findings
 * │   └── post-exploit.md     # Post-exploitation findings
 * ├── wordlists/              # Custom wordlists for brute-forcing
 * └── artifacts/
 *     ├── screenshots/        # Screenshot evidence
 *     └── loot/               # Captured files, credentials
 */

import { tmpdir } from "os"
import { mkdirSync, rmSync, existsSync, writeFileSync, readFileSync } from "fs"
import { join } from "path"
import { createLog } from "../util/log"
import { getRootSession } from "./hierarchy"

const log = createLog("session.directory")

const SESSION_DIR_PREFIX = "opensploit-session-"

/**
 * Permission patterns for external_directory rules.
 * Used by agent.ts to allow writes to session directories without prompting.
 * Other external directories still require user approval ("ask").
 *
 * These patterns match the session temp directory structure:
 * - PERMISSION_PATTERN: matches the session directory itself
 * - PERMISSION_GLOB: matches all files/subdirs within session directories
 */
export const PERMISSION_PATTERN = join(tmpdir(), `${SESSION_DIR_PREFIX}*`)
export const PERMISSION_GLOB = join(tmpdir(), `${SESSION_DIR_PREFIX}*`, "**")

/**
 * Initialize session directory auto-creation.
 * Creates working directory when a root (parent) session is created.
 * Sub-agents share the root session's directory.
 *
 * NOTE: In the plugin context, Bus/Session event subscriptions are not available.
 * Call create() explicitly when starting a session instead.
 */
export function init(): void {
  // TODO: In the fat fork, this subscribes to Bus/Session.Event.Created.
  // In the plugin, session directory creation should be triggered explicitly
  // by the caller (e.g., when a pentest session starts).
  log.info("session_directory_init (plugin mode — call create() explicitly)")
}

/**
 * Create a temp directory for a session with standard structure.
 * Automatically called for root sessions via init(). Also called lazily
 * by tools as a fallback when the directory doesn't exist yet.
 */
export function create(sessionID: string): string {
  // BUG-TS-2 fix: reject sessionID with path traversal characters
  if (!sessionID || sessionID.includes("..") || sessionID.includes("/") || sessionID.includes("\\") || sessionID.includes("\0")) {
    throw new Error(`Invalid sessionID: must not contain path separators or traversal sequences`)
  }
  const dir = join(tmpdir(), `${SESSION_DIR_PREFIX}${sessionID}`)

  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true })

    // Create standard subdirectories
    mkdirSync(join(dir, "findings"), { recursive: true })
    mkdirSync(join(dir, "wordlists"), { recursive: true })
    mkdirSync(join(dir, "artifacts"), { recursive: true })
    mkdirSync(join(dir, "artifacts", "screenshots"), { recursive: true })
    mkdirSync(join(dir, "artifacts", "loot"), { recursive: true })
    mkdirSync(join(dir, "outputs"), { recursive: true })

    log.info("created", { sessionID: sessionID.slice(-8), dir })
  }

  return dir
}

/**
 * Get the session directory path (does not create).
 */
export function get(sessionID: string): string {
  return join(tmpdir(), `${SESSION_DIR_PREFIX}${sessionID}`)
}

/**
 * Check if session directory exists.
 */
export function exists(sessionID: string): boolean {
  return existsSync(get(sessionID))
}

/**
 * Cleanup session directory.
 * Called when root session is deleted.
 */
export function cleanup(sessionID: string): void {
  const dir = get(sessionID)
  if (existsSync(dir)) {
    rmSync(dir, { recursive: true, force: true })
    log.info("cleanup", { sessionID: sessionID.slice(-8), dir })
  }
}

/**
 * Get path to a specific file in session directory.
 */
export function filePath(sessionID: string, ...segments: string[]): string {
  return join(get(sessionID), ...segments)
}

/**
 * Get findings directory path.
 */
export function findingsDir(sessionID: string): string {
  return join(get(sessionID), "findings")
}

/**
 * Get artifacts directory path.
 */
export function artifactsDir(sessionID: string): string {
  return join(get(sessionID), "artifacts")
}

/**
 * Get wordlists directory path.
 */
export function wordlistsDir(sessionID: string): string {
  return join(get(sessionID), "wordlists")
}

/**
 * Get state file path (state.yaml).
 */
export function statePath(sessionID: string): string {
  return join(get(sessionID), "state.yaml")
}

/**
 * Write a findings file.
 */
export function writeFinding(sessionID: string, phase: string, content: string): void {
  const dir = findingsDir(sessionID)
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true })
  }
  const path = join(dir, `${phase}.md`)
  writeFileSync(path, content, "utf-8")
  log.info("wrote_finding", { sessionID: sessionID.slice(-8), phase, path })
}

/**
 * Read a findings file.
 */
export function readFinding(sessionID: string, phase: string): string | null {
  const path = join(findingsDir(sessionID), `${phase}.md`)
  if (!existsSync(path)) return null
  return readFileSync(path, "utf-8")
}

/**
 * Translate /session/ paths to actual session directory paths on the host.
 *
 * Inside MCP containers, the session directory is mounted at /session/.
 * Built-in tools (Read, Write, Edit) run on the host where /session/ doesn't exist.
 * This function translates /session/ paths to the actual host path.
 *
 * This allows agents to use /session/ paths consistently for both MCP tools
 * and built-in tools, simplifying the mental model.
 *
 * @param filepath - The file path (may start with /session/)
 * @param sessionID - The session ID for resolving the actual path
 * @returns Translated path (or original if not a /session/ path)
 */
export function translateSessionPath(filepath: string, sessionID: string): string {
  // Reject null bytes which can truncate paths at the OS level
  if (filepath.includes("\0")) {
    return filepath // Return as-is — file operations will fail safely on null bytes
  }
  if (filepath.startsWith("/session/")) {
    const relativePath = filepath.slice(9) // "/session/".length = 9
    // Use root session ID so sub-agents share the same directory as root
    const rootSessionID = getRootSession(sessionID)
    const sessionDir = get(rootSessionID)

    // Ensure session directory exists
    if (!existsSync(sessionDir)) {
      create(rootSessionID)
    }

    const resolved = join(sessionDir, relativePath)

    // BUG-SH-6 fix: ensure resolved path stays inside session directory.
    // path.join resolves ".." segments, so /session/../../etc/passwd would
    // escape to /etc/passwd. Reject any path that doesn't start with sessionDir.
    if (!resolved.startsWith(sessionDir)) {
      return join(sessionDir, "BLOCKED_PATH_TRAVERSAL")
    }

    return resolved
  }
  return filepath
}
