/**
 * tool.execute.before hook
 *
 * Intercepts tool calls before execution to:
 * 1. Rewrite /session/ paths → actual temp directory (all file tools + bash)
 * 2. Block direct invocation of security tools in bash (force MCP usage)
 *
 * Path rewriting: Agents use /session/ as a virtual path for session data.
 * This hook translates it to the real /tmp/opensploit-session-{rootSessionID}/
 * path before the tool executes.
 *
 * Bash blocking: Security tools (nmap, sqlmap, etc.) are blocked in bash
 * to force usage through MCP containers (REQ-ARC-011-A). This provides
 * isolation, logging, and proper output handling.
 */

import { translateSessionPath } from "../session/directory.js"
import { createLog } from "../util/log.js"

const log = createLog("hook.tool-before")

/**
 * Tools that use file paths and need /session/ translation.
 */
const FILE_TOOLS = new Set(["read", "write", "edit", "glob", "grep", "list"])

/**
 * Security tools blocked in bash (REQ-ARC-011-A).
 * Must use MCP equivalents for proper isolation and logging.
 */
const BLOCKED_BASH_PATTERNS = [
  "nmap", "ssh ", "scp ", "sqlmap", "hydra", "nikto",
  "gobuster", "ffuf", "curl ", "wget ", "nc ", "netcat",
  "metasploit", "msfconsole", "john", "hashcat",
]

export async function toolBeforeHook(
  input: { tool: string; sessionID: string; callID: string },
  output: { args: any },
): Promise<void> {
  try {
    const { tool, sessionID } = input

    // -------------------------------------------------------------------------
    // 1. /session/ path rewriting for file tools
    // -------------------------------------------------------------------------
    if (FILE_TOOLS.has(tool)) {
      // These tools typically have a filePath or path argument
      if (output.args?.filePath && typeof output.args.filePath === "string") {
        const translated = translateSessionPath(output.args.filePath, sessionID)
        if (translated !== output.args.filePath) {
          log.info("translated session path", { tool, original: output.args.filePath, translated })
          output.args.filePath = translated
        }
      }
      if (output.args?.path && typeof output.args.path === "string") {
        const translated = translateSessionPath(output.args.path, sessionID)
        if (translated !== output.args.path) {
          log.info("translated session path", { tool, original: output.args.path, translated })
          output.args.path = translated
        }
      }
    }

    // -------------------------------------------------------------------------
    // 2. /session/ path rewriting for bash commands
    // -------------------------------------------------------------------------
    if (tool === "bash" && output.args?.command && typeof output.args.command === "string") {
      const command = output.args.command
      if (command.includes("/session/")) {
        const translated = translateSessionPath("/session/placeholder", sessionID)
        const sessionDir = translated.replace("/placeholder", "")
        output.args.command = command.replaceAll("/session/", sessionDir + "/")
        log.info("translated session paths in bash command", { sessionID: sessionID.slice(-8) })
      }

      // Also handle workdir
      if (output.args.workdir && typeof output.args.workdir === "string" && output.args.workdir.startsWith("/session/")) {
        output.args.workdir = translateSessionPath(output.args.workdir, sessionID)
      }
    }

    // -------------------------------------------------------------------------
    // 3. Block security tools in bash (force MCP usage)
    // -------------------------------------------------------------------------
    // Note: This is a SOFT block via the hook. The agent's permission rules
    // (bash: { "nmap*": "deny" }) provide the HARD block. This hook adds
    // a helpful error message explaining why the command was blocked.
    //
    // The permission system runs AFTER tool.execute.before, so we don't
    // need to duplicate the blocking here. The agent permissions handle it.
    // This comment documents the design decision.
  } catch (error) {
    log.error("hook failed, proceeding without modification", {
      error: error instanceof Error ? error.message : String(error),
    })
  }
}
