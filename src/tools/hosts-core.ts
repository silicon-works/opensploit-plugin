/**
 * Hosts Core — Pure validation and formatting logic for /etc/hosts management.
 *
 * All functions are pure (no I/O, no sudo, no subprocess calls).
 * This module is the brain; the bash helper script is the hands.
 *
 * The helper script (`opensploit-hosts`) is installed once during setup
 * with a scoped NOPASSWD sudoers entry. During engagements, the hosts
 * tool calls it without password prompts.
 */

// =============================================================================
// Types
// =============================================================================

export interface HostEntry {
  ip: string
  hostname: string
}

// =============================================================================
// Constants
// =============================================================================

export const MAX_ENTRIES_PER_SESSION = 50
export const MAX_HOSTNAME_LENGTH = 253

const MARKER_PREFIX = "# opensploit-session:"
const MARKER_END_PREFIX = "# end-opensploit-session:"

// Strict patterns — reject anything that could be a shell/sed injection vector
const SESSION_ID_REGEX = /^[a-zA-Z0-9_-]+$/
const IPV4_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/
const IPV6_REGEX = /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$|^::([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{0,4}$|^[0-9a-fA-F]{1,4}::([0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{0,4}$/
// Hostname: alphanumeric, hyphens, underscores, dots. No leading hyphen. No control chars.
const HOSTNAME_REGEX = /^[a-zA-Z0-9_]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$/

// Characters that must never appear in any input (control chars, shell metacharacters)
const DANGEROUS_CHARS = /[\x00-\x1f\x7f`$|;&(){}\[\]!<>'"\\]/

// =============================================================================
// Validation
// =============================================================================

/**
 * Validate an IP address (IPv4 or IPv6).
 * Rejects anything with control characters, spaces, or shell metacharacters.
 */
export function validateIP(ip: string): boolean {
  if (!ip || DANGEROUS_CHARS.test(ip) || ip.includes(" ")) return false
  return IPV4_REGEX.test(ip) || IPV6_REGEX.test(ip)
}

/**
 * Validate a hostname.
 * Rejects control characters, shell metacharacters, and hostnames > 253 chars.
 */
export function validateHostname(hostname: string): boolean {
  if (!hostname || DANGEROUS_CHARS.test(hostname)) return false
  if (hostname.length > MAX_HOSTNAME_LENGTH) return false
  if (hostname.includes(" ")) return false
  return HOSTNAME_REGEX.test(hostname)
}

/**
 * Validate a session ID.
 * Only alphanumeric, hyphens, and underscores allowed.
 * This is critical because the session ID is interpolated into sed patterns
 * in the bash helper script.
 */
export function validateSessionId(sessionId: string): boolean {
  if (!sessionId) return false
  return SESSION_ID_REGEX.test(sessionId)
}

/**
 * Validate an array of host entries.
 */
export function validateEntries(entries: HostEntry[]): { valid: boolean; error?: string } {
  if (!entries || entries.length === 0) {
    return { valid: false, error: "No entries provided" }
  }

  if (entries.length > MAX_ENTRIES_PER_SESSION) {
    return { valid: false, error: `Too many entries (${entries.length}), limit is ${MAX_ENTRIES_PER_SESSION} per session` }
  }

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i]
    if (!validateIP(entry.ip)) {
      return { valid: false, error: `Invalid IP address at entry ${i}: "${entry.ip}"` }
    }
    if (!validateHostname(entry.hostname)) {
      return { valid: false, error: `Invalid hostname at entry ${i}: "${entry.hostname}"` }
    }
  }

  return { valid: true }
}

// =============================================================================
// Block Formatting
// =============================================================================

/**
 * Format a hosts block with session markers.
 * Output is ready to append to /etc/hosts.
 */
export function formatHostsBlock(sessionId: string, entries: HostEntry[]): string {
  const lines = [
    `${MARKER_PREFIX}${sessionId}`,
    ...entries.map((e) => `${e.ip}\t${e.hostname}`),
    `${MARKER_END_PREFIX}${sessionId}`,
  ]
  return lines.join("\n")
}

// =============================================================================
// Block Parsing
// =============================================================================

/**
 * Parse host entries for a specific session from /etc/hosts content.
 * Only returns entries from complete blocks (start AND end marker present).
 */
export function parseHostsBlock(content: string, sessionId: string): HostEntry[] {
  const startMarker = `${MARKER_PREFIX}${sessionId}`
  const endMarker = `${MARKER_END_PREFIX}${sessionId}`
  const lines = content.split("\n")
  const entries: HostEntry[] = []
  let inBlock = false
  let blockEntries: HostEntry[] = []

  for (const line of lines) {
    if (line.trim() === startMarker) {
      inBlock = true
      blockEntries = []
      continue
    }
    if (line.trim() === endMarker) {
      if (inBlock) {
        // Complete block — add entries
        entries.push(...blockEntries)
      }
      inBlock = false
      continue
    }
    if (inBlock) {
      const trimmed = line.trim()
      if (!trimmed || trimmed.startsWith("#")) continue
      const parts = trimmed.split(/\s+/)
      if (parts.length >= 2) {
        blockEntries.push({ ip: parts[0], hostname: parts[1] })
      }
    }
  }

  // If inBlock is still true, we hit an orphaned start marker — don't return those entries
  return entries
}

// =============================================================================
// Block Removal
// =============================================================================

/**
 * Remove all blocks for a specific session from /etc/hosts content.
 * Returns the modified content string.
 */
export function removeHostsBlock(content: string, sessionId: string): string {
  const startMarker = `${MARKER_PREFIX}${sessionId}`
  const endMarker = `${MARKER_END_PREFIX}${sessionId}`
  const lines = content.split("\n")
  const result: string[] = []
  let inBlock = false

  for (const line of lines) {
    if (line.trim() === startMarker) {
      inBlock = true
      continue
    }
    if (line.trim() === endMarker) {
      inBlock = false
      continue
    }
    if (!inBlock) {
      result.push(line)
    }
  }

  // Collapse runs of 3+ blank lines to at most 2
  return collapseBlankLines(result.join("\n"))
}

/**
 * Remove ALL opensploit blocks from /etc/hosts content (purge).
 * Handles orphaned markers (start without end, end without start).
 *
 * Strategy: find matched start/end pairs first, mark those line ranges for removal.
 * Then remove any remaining orphaned marker lines individually.
 */
export function removeAllBlocks(content: string): string {
  const lines = content.split("\n")

  // Phase 1: Find matched block ranges (start → end, inclusive)
  const removeSet = new Set<number>()
  let blockStart = -1

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim()
    if (trimmed.startsWith(MARKER_PREFIX)) {
      blockStart = i
    } else if (trimmed.startsWith(MARKER_END_PREFIX)) {
      if (blockStart >= 0) {
        // Matched pair — mark the entire range for removal
        for (let j = blockStart; j <= i; j++) {
          removeSet.add(j)
        }
      } else {
        // Orphaned end marker — remove just this line
        removeSet.add(i)
      }
      blockStart = -1
    }
  }

  // Phase 2: If blockStart is still set, we have an orphaned start marker.
  // Only remove the marker line itself — we can't safely determine which
  // subsequent lines are block entries vs legitimate /etc/hosts entries.
  if (blockStart >= 0) {
    removeSet.add(blockStart)
  }

  const result = lines.filter((_, i) => !removeSet.has(i))
  return collapseBlankLines(result.join("\n"))
}

// =============================================================================
// Helpers
// =============================================================================

/** Collapse runs of 3+ consecutive blank lines to at most 2 */
function collapseBlankLines(content: string): string {
  return content.replace(/\n{3,}/g, "\n\n")
}
