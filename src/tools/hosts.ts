/**
 * Hosts Tool — Manage /etc/hosts entries for hostname resolution.
 *
 * Uses a dedicated helper script (opensploit-hosts) installed with a scoped
 * NOPASSWD sudoers entry. No password prompts during engagements.
 *
 * Setup required once:
 *   sudo cp bin/opensploit-hosts /usr/local/bin/
 *   sudo chmod 755 /usr/local/bin/opensploit-hosts
 *   echo "$USER ALL=(ALL) NOPASSWD: /usr/local/bin/opensploit-hosts" | sudo tee /etc/sudoers.d/opensploit
 *
 * All validation happens in TypeScript (hosts-core.ts).
 * The bash helper is a thin I/O layer that trusts its caller.
 */

import { z } from "zod"
import { tool, type ToolContext } from "@opencode-ai/plugin"
import { spawn } from "bun"
import { createLog } from "../util/log"
import { getRootSession } from "../session/hierarchy"
import {
  validateEntries,
  validateSessionId,
  parseHostsBlock,
  type HostEntry,
} from "./hosts-core"

const log = createLog("tool.hosts")

const HELPER_PATH = "/usr/local/bin/opensploit-hosts"

// =============================================================================
// Helper interaction
// =============================================================================

/**
 * Check if the helper script is installed and accessible via sudo without password.
 */
export async function isHelperInstalled(): Promise<boolean> {
  try {
    const proc = spawn(["sudo", "-n", HELPER_PATH, "check"], {
      stdout: "pipe",
      stderr: "pipe",
    })
    const exitCode = await proc.exited
    return exitCode === 0
  } catch {
    return false
  }
}

/**
 * Call the helper script with sudo.
 */
async function callHelper(args: string[]): Promise<{ success: boolean; output: string; error: string }> {
  try {
    const proc = spawn(["sudo", "-n", HELPER_PATH, ...args], {
      stdout: "pipe",
      stderr: "pipe",
    })

    const stdout = await new Response(proc.stdout).text()
    const stderr = await new Response(proc.stderr).text()
    const exitCode = await proc.exited

    return {
      success: exitCode === 0,
      output: stdout.trim(),
      error: stderr.trim(),
    }
  } catch (error) {
    return {
      success: false,
      output: "",
      error: error instanceof Error ? error.message : String(error),
    }
  }
}

/**
 * Read /etc/hosts content (no sudo needed for reading).
 */
async function readHostsFile(): Promise<string> {
  try {
    return await Bun.file("/etc/hosts").text()
  } catch {
    return ""
  }
}

function helperNotInstalledMessage(ctx: ToolContext): string {
  ctx.metadata({ title: "Hosts: Setup required", metadata: { success: false } })
  return [
    "**Hosts helper not installed.**",
    "",
    "Run `opensploit setup` or install manually:",
    "```",
    "sudo cp bin/opensploit-hosts /usr/local/bin/",
    "sudo chmod 755 /usr/local/bin/opensploit-hosts",
    `echo "${process.env.USER} ALL=(ALL) NOPASSWD: /usr/local/bin/opensploit-hosts" | sudo tee /etc/sudoers.d/opensploit`,
    "```",
  ].join("\n")
}

// =============================================================================
// Tool definition
// =============================================================================

const DESCRIPTION = `Manage /etc/hosts entries for hostname resolution during penetration testing.

Adds temporary hostname-to-IP mappings that are tracked per session and
automatically cleaned up when the session ends.

**Use cases:**
- Map target hostnames to IP addresses for web exploitation (virtual hosting)
- Add subdomains discovered during enumeration
- Configure hostname resolution for internal network targets

**Actions:**
- \`add\`: Add hostname mappings (entries required)
- \`remove\`: Remove all entries for this session
- \`list\`: Show current session's hostname mappings
- \`cleanup\`: Same as remove — clean up all session entries
- \`purge\`: Remove ALL opensploit entries from /etc/hosts (all sessions)

**Setup required:** Run \`opensploit setup\` once to install the hosts helper.`

export function createHostsTool() {
  return tool({
    description: DESCRIPTION,
    args: {
      action: z
        .enum(["add", "remove", "list", "cleanup", "purge"])
        .describe("Action: add, remove, list, cleanup, or purge"),
      entries: z
        .array(
          z.object({
            ip: z.string().describe("IP address"),
            hostname: z.string().describe("Hostname to map"),
          })
        )
        .optional()
        .describe("Entries to add (required for add action)"),
    },
    async execute(params, ctx): Promise<string> {
      const { action, entries } = params
      const sessionId = getRootSession(ctx.sessionID)

      // Validate session ID
      if (!validateSessionId(sessionId)) {
        ctx.metadata({ title: "Hosts: Error", metadata: { success: false } })
        return `Error: Invalid session ID format.`
      }

      switch (action) {
        case "add": {
          if (!entries || entries.length === 0) {
            ctx.metadata({ title: "Hosts: Error", metadata: { success: false } })
            return "Error: No entries provided. Specify entries with ip and hostname."
          }

          const validation = validateEntries(entries)
          if (!validation.valid) {
            ctx.metadata({ title: "Hosts: Error", metadata: { success: false } })
            return `Error: ${validation.error}`
          }

          // Check helper AFTER validation passes
          if (!(await isHelperInstalled())) {
            return helperNotInstalledMessage(ctx)
          }

          // Build arguments: "IP HOSTNAME" pairs
          const entryArgs = entries.map((e) => `${e.ip} ${e.hostname}`)
          const result = await callHelper(["add", sessionId, ...entryArgs])

          if (!result.success) {
            log.error("hosts add failed", { sessionId, error: result.error })
            ctx.metadata({ title: "Hosts: Failed", metadata: { success: false } })
            return `Failed to add hosts entries: ${result.error}`
          }

          const entriesStr = entries.map((e) => `  ${e.ip} → ${e.hostname}`).join("\n")
          log.info("hosts added", { sessionId, count: entries.length })
          ctx.metadata({
            title: `Hosts: Added ${entries.length} entries`,
            metadata: { success: true, count: entries.length },
          })
          return `Added ${entries.length} hosts entries:\n${entriesStr}\n\nThese will be removed when the session ends.`
        }

        case "remove":
        case "cleanup": {
          if (!(await isHelperInstalled())) {
            return helperNotInstalledMessage(ctx)
          }

          const result = await callHelper(["remove", sessionId])

          if (!result.success) {
            log.error("hosts remove failed", { sessionId, error: result.error })
            ctx.metadata({ title: "Hosts: Failed", metadata: { success: false } })
            return `Failed to remove hosts entries: ${result.error}`
          }

          log.info("hosts removed", { sessionId })
          ctx.metadata({ title: "Hosts: Cleanup complete", metadata: { success: true } })
          return "Removed all hosts entries for this session."
        }

        case "list": {
          const content = await readHostsFile()
          const sessionEntries = parseHostsBlock(content, sessionId)

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

        case "purge": {
          if (!(await isHelperInstalled())) {
            return helperNotInstalledMessage(ctx)
          }

          const result = await callHelper(["purge"])

          if (!result.success) {
            log.error("hosts purge failed", { error: result.error })
            ctx.metadata({ title: "Hosts: Purge failed", metadata: { success: false } })
            return `Failed to purge hosts entries: ${result.error}`
          }

          log.info("hosts purged all entries")
          ctx.metadata({ title: "Hosts: Purged all entries", metadata: { success: true } })
          return "Purged all opensploit entries from /etc/hosts."
        }

        default:
          ctx.metadata({ title: "Hosts: Error", metadata: { success: false } })
          return `Unknown action: ${action}`
      }
    },
  })
}

// =============================================================================
// Session cleanup (called by event hook when session ends)
// =============================================================================

/**
 * Cleanup hosts entries for a session. Called when root session is deleted.
 * Best-effort — logs errors but doesn't throw.
 */
export async function cleanupSessionHosts(sessionId: string): Promise<void> {
  if (!validateSessionId(sessionId)) return

  // Check if there are actually entries for this session before calling helper
  const content = await readHostsFile()
  // Use regex with line boundary to avoid substring false positives (ses_abc matching ses_abc123)
  // while also matching at EOF without trailing newline
  const markerPattern = new RegExp(`^# opensploit-session:${sessionId}$`, "m")
  if (!markerPattern.test(content)) return

  try {
    const result = await callHelper(["remove", sessionId])
    if (result.success) {
      log.info("session hosts cleaned up", { sessionId: sessionId.slice(-8) })
    } else {
      log.error("session hosts cleanup failed", { sessionId: sessionId.slice(-8), error: result.error })
    }
  } catch (error) {
    log.error("session hosts cleanup error", { error })
  }
}
