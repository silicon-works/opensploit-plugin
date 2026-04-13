import { z } from "zod"
import { tool, type ToolContext } from "@opencode-ai/plugin"
import { spawn } from "bun"
import { createLog } from "../util/log"
import { getRootSession } from "../session/hierarchy"

const log = createLog("tool.hosts")

// Track hosts entries per session for cleanup
const sessionHosts = new Map<string, Set<string>>()

// Marker format for identifying opensploit entries
const MARKER_START = "# opensploit-session:"
const MARKER_END = "# end-opensploit-session:"

interface HostEntry {
  ip: string
  hostname: string
}

/**
 * Parse /etc/hosts and extract opensploit-managed entries by session
 */
async function getHostsContent(): Promise<string> {
  try {
    const file = Bun.file("/etc/hosts")
    return await file.text()
  } catch {
    return ""
  }
}

/**
 * Run a command with sudo
 */
async function runSudo(args: string[]): Promise<{ success: boolean; output: string; error: string }> {
  const proc = spawn(["sudo", ...args], {
    stdout: "pipe",
    stderr: "pipe",
  })

  const stdout = await new Response(proc.stdout).text()
  const stderr = await new Response(proc.stderr).text()
  const exitCode = await proc.exited

  return {
    success: exitCode === 0,
    output: stdout,
    error: stderr,
  }
}

/**
 * Add entries to /etc/hosts with session marker
 */
async function addHostEntries(sessionId: string, entries: HostEntry[]): Promise<{ success: boolean; error?: string }> {
  if (entries.length === 0) {
    return { success: true }
  }

  // Build the entries block
  const lines = [
    `${MARKER_START}${sessionId}`,
    ...entries.map((e) => `${e.ip}\t${e.hostname}`),
    `${MARKER_END}${sessionId}`,
  ]
  const block = lines.join("\n")

  // Use tee with sudo to append to /etc/hosts
  const proc = spawn(["sudo", "tee", "-a", "/etc/hosts"], {
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
  })

  // In Bun, stdin is a FileSink with .write() and .end() methods
  proc.stdin.write("\n" + block + "\n")
  proc.stdin.end()

  const stderr = await new Response(proc.stderr).text()
  const exitCode = await proc.exited

  if (exitCode !== 0) {
    return { success: false, error: stderr || "Failed to write to /etc/hosts" }
  }

  // Track entries for this session
  let sessionSet = sessionHosts.get(sessionId)
  if (!sessionSet) {
    sessionSet = new Set()
    sessionHosts.set(sessionId, sessionSet)
  }
  for (const entry of entries) {
    sessionSet.add(`${entry.ip}\t${entry.hostname}`)
  }

  log.info("added hosts entries", { sessionId, count: entries.length })
  return { success: true }
}

/**
 * Remove all entries for a session from /etc/hosts
 */
async function removeSessionEntries(sessionId: string): Promise<{ success: boolean; error?: string }> {
  const content = await getHostsContent()
  if (!content) {
    return { success: true }
  }

  const startMarker = `${MARKER_START}${sessionId}`
  const endMarker = `${MARKER_END}${sessionId}`

  // Check if session has entries
  if (!content.includes(startMarker)) {
    sessionHosts.delete(sessionId)
    return { success: true }
  }

  // Remove the session block using sed
  // This removes from start marker to end marker inclusive
  const sedPattern = `/${startMarker.replace(/[/]/g, "\\/")}/,/${endMarker.replace(/[/]/g, "\\/")}/d`

  const result = await runSudo(["sed", "-i", sedPattern, "/etc/hosts"])

  if (!result.success) {
    return { success: false, error: result.error || "Failed to remove hosts entries" }
  }

  sessionHosts.delete(sessionId)
  log.info("removed hosts entries", { sessionId })
  return { success: true }
}

/**
 * List entries for a session
 */
async function listSessionEntries(sessionId: string): Promise<HostEntry[]> {
  const content = await getHostsContent()
  const entries: HostEntry[] = []

  const startMarker = `${MARKER_START}${sessionId}`
  const endMarker = `${MARKER_END}${sessionId}`

  const lines = content.split("\n")
  let inSession = false

  for (const line of lines) {
    if (line.includes(startMarker)) {
      inSession = true
      continue
    }
    if (line.includes(endMarker)) {
      inSession = false
      continue
    }
    if (inSession && line.trim() && !line.startsWith("#")) {
      const parts = line.split(/\s+/)
      if (parts.length >= 2) {
        entries.push({ ip: parts[0], hostname: parts[1] })
      }
    }
  }

  return entries
}

const DESCRIPTION = `Manage /etc/hosts entries for hostname resolution during penetration testing.

This tool allows you to add temporary hostname mappings that will be automatically cleaned up when the session ends.

Use cases:
- Map target hostnames to IP addresses for web exploitation
- Configure hostnames for virtual host enumeration
- Set up hostname resolution for internal network targets

IMPORTANT: Requires sudo access. User will be prompted for password if not cached.`

export function createHostsTool() {
  return tool({
    description: DESCRIPTION,
    args: {
      action: z
        .enum(["add", "remove", "list", "cleanup"])
        .describe("Action to perform: add entries, remove specific entries, list current entries, or cleanup all session entries"),
      entries: z
        .array(
          z.object({
            ip: z.string().describe("IP address"),
            hostname: z.string().describe("Hostname to map"),
          })
        )
        .optional()
        .describe("Entries to add or remove (required for add/remove actions)"),
    },
    async execute(params, ctx): Promise<string> {
      const { action, entries } = params
      // Use root session ID so all agents share the same host entries and cleanup works
      const sessionId = getRootSession(ctx.sessionID)

      switch (action) {
        case "add": {
          if (!entries || entries.length === 0) {
            ctx.metadata({
              title: "Hosts: Error",
              metadata: { success: false },
            })
            return "Error: No entries provided. Please specify entries with ip and hostname."
          }

          const result = await addHostEntries(sessionId, entries)
          if (!result.success) {
            ctx.metadata({
              title: "Hosts: Failed",
              metadata: { success: false },
            })
            return `Failed to add hosts entries: ${result.error}\n\nMake sure sudo is configured and you have permission to modify /etc/hosts.`
          }

          const entriesStr = entries.map((e) => `  ${e.ip} -> ${e.hostname}`).join("\n")
          ctx.metadata({
            title: `Hosts: Added ${entries.length} entries`,
            metadata: { success: true, entries },
          })
          return `Successfully added ${entries.length} hosts entries:\n${entriesStr}\n\nThese entries will be automatically removed when the session ends.`
        }

        case "remove": {
          if (!entries || entries.length === 0) {
            ctx.metadata({
              title: "Hosts: Error",
              metadata: { success: false },
            })
            return "Error: No entries provided. Use 'cleanup' action to remove all session entries."
          }

          // For now, just do a full cleanup if any entries are specified
          // A more granular remove would require more complex sed patterns
          const result = await removeSessionEntries(sessionId)
          if (!result.success) {
            ctx.metadata({
              title: "Hosts: Failed",
              metadata: { success: false },
            })
            return `Failed to remove hosts entries: ${result.error}`
          }

          ctx.metadata({
            title: "Hosts: Removed entries",
            metadata: { success: true },
          })
          return "Successfully removed session hosts entries."
        }

        case "list": {
          const sessionEntries = await listSessionEntries(sessionId)
          if (sessionEntries.length === 0) {
            ctx.metadata({
              title: "Hosts: No entries",
              metadata: { success: true, entries: [] },
            })
            return "No hosts entries for this session."
          }

          const entriesStr = sessionEntries.map((e) => `  ${e.ip}\t${e.hostname}`).join("\n")
          ctx.metadata({
            title: `Hosts: ${sessionEntries.length} entries`,
            metadata: { success: true, entries: sessionEntries },
          })
          return `Current hosts entries for this session:\n${entriesStr}`
        }

        case "cleanup": {
          const result = await removeSessionEntries(sessionId)
          if (!result.success) {
            ctx.metadata({
              title: "Hosts: Cleanup failed",
              metadata: { success: false },
            })
            return `Failed to cleanup hosts entries: ${result.error}`
          }

          ctx.metadata({
            title: "Hosts: Cleanup complete",
            metadata: { success: true },
          })
          return "Successfully cleaned up all hosts entries for this session."
        }

        default:
          ctx.metadata({
            title: "Hosts: Error",
            metadata: { success: false },
          })
          return `Unknown action: ${action}`
      }
    },
  })
}

/**
 * Cleanup function to be called when session ends
 */
export async function cleanupSessionHosts(sessionId: string): Promise<void> {
  if (sessionHosts.has(sessionId)) {
    log.info("cleaning up session hosts", { sessionId })
    await removeSessionEntries(sessionId)
  }
}

/**
 * Get all sessions with hosts entries (for debugging/admin)
 */
export function getSessionsWithHosts(): string[] {
  return Array.from(sessionHosts.keys())
}
