import { readFileSync } from "fs"
import { join, dirname } from "path"
import { fileURLToPath } from "url"

const __dirname = dirname(fileURLToPath(import.meta.url))
const promptDir = join(__dirname, "prompts")

function readPrompt(name: string): string {
  const fullPath = join(promptDir, name)
  try {
    return readFileSync(fullPath, "utf-8")
  } catch (e) {
    throw new Error(
      `Failed to read agent prompt file: ${fullPath}\n` +
      `Ensure the @opensploit/core package includes the prompts directory.\n` +
      `Original error: ${e instanceof Error ? e.message : String(e)}`
    )
  }
}

/**
 * Bash commands denied for pentest agents — forces MCP tool usage (REQ-ARC-011-A).
 * These tools MUST be invoked through mcp_tool for proper isolation and logging.
 */
const bashSecurityDenials: Record<string, "allow" | "ask" | "deny"> = {
  "*": "allow",
  "nmap*": "deny",
  "ssh *": "deny",
  "scp *": "deny",
  "sqlmap*": "deny",
  "hydra*": "deny",
  "nikto*": "deny",
  "gobuster*": "deny",
  "ffuf*": "deny",
  "curl *": "deny",
  "wget *": "deny",
  "nc *": "deny",
  "netcat*": "deny",
  "metasploit*": "deny",
  "msfconsole*": "deny",
  "john*": "deny",
  "hashcat*": "deny",
}

/**
 * External directory permissions — session dir allowed, others ask.
 * Uses /tmp/opensploit-session-* glob patterns.
 */
const pentestExternalDir: Record<string, "allow" | "ask" | "deny"> = {
  "*": "ask",
  "/tmp/opensploit-session-*": "allow",
  "/tmp/opensploit-session-*/**": "allow",
}

/** Shared permission config for most pentest agents (not report). */
const pentestPermission = {
  "*": "allow" as const,
  doom_loop: "ask" as const,
  external_directory: pentestExternalDir,
  bash: bashSecurityDenials,
}

/**
 * Agent config type matching what the config hook expects.
 * These fields map to the Agent schema in opencode config.ts.
 */
type AgentConfig = {
  mode: "primary" | "subagent" | "all"
  description: string
  prompt: string
  color?: string
  temperature?: number
  hidden?: boolean
  permission?: Record<string, any>
}

/**
 * Load all pentest agent definitions for registration via the config hook.
 *
 * Returns a record keyed by agent name. The config hook merges these
 * into config.agent, making them available to the agent system.
 */
export function loadAgents(): Record<string, AgentConfig> {
  const base = readPrompt("pentest-base.txt")

  return {
    pentest: {
      mode: "primary",
      color: "#e74c3c",
      description:
        "Master penetration testing agent that orchestrates security assessments",
      prompt: base + "\n\n" + readPrompt("pentest.txt"),
      temperature: 0.3,
      permission: {
        ...pentestPermission,
        question: "allow",
        plan_enter: "allow",
      },
    },

    "pentest/recon": {
      mode: "subagent",
      color: "#3498db",
      description:
        "Reconnaissance phase - discover services and gather information",
      prompt: base + "\n\n" + readPrompt("pentest/recon.txt"),
      hidden: true,
      permission: pentestPermission,
    },

    "pentest/enum": {
      mode: "subagent",
      color: "#9b59b6",
      description:
        "Enumeration phase - detailed service analysis and vulnerability identification",
      prompt: base + "\n\n" + readPrompt("pentest/enum.txt"),
      hidden: true,
      permission: pentestPermission,
    },

    "pentest/exploit": {
      mode: "subagent",
      color: "#e74c3c",
      description:
        "Exploitation phase - attempt to gain access using discovered vulnerabilities",
      prompt: base + "\n\n" + readPrompt("pentest/exploit.txt"),
      hidden: true,
      permission: pentestPermission,
    },

    "pentest/post": {
      mode: "subagent",
      color: "#f39c12",
      description:
        "Post-exploitation phase - privilege escalation, lateral movement, persistence",
      prompt: base + "\n\n" + readPrompt("pentest/post.txt"),
      hidden: true,
      permission: pentestPermission,
    },

    "pentest/report": {
      mode: "subagent",
      color: "#27ae60",
      description:
        "Reporting phase - aggregate findings and generate comprehensive reports",
      prompt: base + "\n\n" + readPrompt("pentest/report.txt"),
      hidden: true,
      // Report agent: no bash, just reads findings and writes reports
      permission: {
        "*": "allow",
        doom_loop: "ask",
        external_directory: pentestExternalDir,
        bash: { "*": "deny" },
      },
    },

    "pentest/research": {
      mode: "subagent",
      color: "#1abc9c",
      description:
        "OSINT and research specialist - CVE details, exploit research, default credentials",
      prompt: base + "\n\n" + readPrompt("pentest/research.txt"),
      hidden: true,
      permission: pentestPermission,
    },

    "pentest/build": {
      mode: "subagent",
      color: "#e67e22",
      description:
        "Exploit and payload builder - finds or creates tested exploits",
      prompt: base + "\n\n" + readPrompt("pentest/build.txt"),
      hidden: true,
      permission: pentestPermission,
    },

    "pentest/captcha": {
      mode: "subagent",
      color: "#f1c40f",
      description:
        "CAPTCHA coordinator - detects CAPTCHAs and hands off to human user for solving",
      prompt: base + "\n\n" + readPrompt("pentest/captcha.txt"),
      temperature: 0.2,
      hidden: true,
      permission: {
        ...pentestPermission,
        question: "allow",
      },
    },
  }
}
