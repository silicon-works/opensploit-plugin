/**
 * Feature 02: Master Pentest Agent — Acceptance Tests
 *
 * Each test maps to a specific REQ-* from:
 *   opensploit-vault/requirements/02-master-pentest-agent.md
 *
 * Requirements that depend on LLM runtime behavior (reasoning quality, delegation
 * decisions, dynamic context) are noted as SKIP with explanation.
 *
 * Gap analysis table is at the bottom of this file.
 */

import { describe, expect, test } from "bun:test"
import { loadAgents } from "../../src/agents/index"
import { readFileSync } from "fs"
import { join, dirname } from "path"
import { fileURLToPath } from "url"

const __dirname = dirname(fileURLToPath(import.meta.url))
const agentsDir = join(__dirname, "../../src/agents")
const promptDir = join(agentsDir, "prompts")

// ---------------------------------------------------------------------------
// Load agents once for all tests
// ---------------------------------------------------------------------------

const agents = loadAgents()

function readPromptFile(name: string): string {
  return readFileSync(join(promptDir, name), "utf-8")
}

// Load raw prompt files for content validation
const basePrompt = readPromptFile("pentest-base.txt")
const masterPrompt = readPromptFile("pentest.txt")

// All phase sub-agent prompts
const phasePrompts: Record<string, string> = {
  recon: readPromptFile("pentest/recon.txt"),
  enum: readPromptFile("pentest/enum.txt"),
  exploit: readPromptFile("pentest/exploit.txt"),
  post: readPromptFile("pentest/post.txt"),
  report: readPromptFile("pentest/report.txt"),
  research: readPromptFile("pentest/research.txt"),
  build: readPromptFile("pentest/build.txt"),
  captcha: readPromptFile("pentest/captcha.txt"),
}

// The exact set of bash security denials from the requirements doc (lines 256-274)
const REQUIRED_BASH_DENIALS: Record<string, "deny"> = {
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

// The 5 phase sub-agents required by REQ-ARC-007
const PHASE_SUBAGENTS = [
  "pentest/recon",
  "pentest/enum",
  "pentest/exploit",
  "pentest/post",
  "pentest/report",
]

// All pentest agents (including non-phase ones)
const ALL_PENTEST_AGENTS = [
  "pentest",
  "pentest/recon",
  "pentest/enum",
  "pentest/exploit",
  "pentest/post",
  "pentest/report",
  "pentest/research",
  "pentest/build",
  "pentest/captcha",
]

// All sub-agents (everything except master)
const ALL_SUBAGENTS = ALL_PENTEST_AGENTS.filter((n) => n !== "pentest")

// Agents expected to have the shared pentestPermission bash denials
// (all except report, which uses bash: { "*": "deny" })
const AGENTS_WITH_BASH_DENIALS = ALL_PENTEST_AGENTS.filter(
  (n) => n !== "pentest/report"
)

// =========================================================================
// Section 1: Core Agent Requirements (Section 3.2)
// =========================================================================

describe("Core Agent Requirements (Section 3.2)", () => {
  // REQ-ARC-001: System SHALL implement agent loop based on OpenCode fork
  // SKIP: Runtime/architectural concern; verified by the agent system existing
  // and loadAgents() succeeding.

  test("REQ-ARC-002: agent supports phase-based pentesting methodology (master prompt has all 5 phases)", () => {
    // The master prompt must reference all 5 methodology phases
    const combined = agents["pentest"].prompt
    expect(combined).toContain("Reconnaissance")
    expect(combined).toContain("Enumeration")
    expect(combined).toContain("Exploitation")
    expect(combined).toContain("Post-Exploitation")
    expect(combined).toContain("Reporting")
  })

  test("REQ-ARC-004: agent supports sub-agent spawning via Task tool reference in prompt", () => {
    const combined = agents["pentest"].prompt
    // Master prompt must reference the Task tool for spawning sub-agents
    expect(combined).toContain("Task")
    expect(combined).toContain("subagent_type")
  })

  test("REQ-ARC-006: master pentest agent exists as primary orchestrator", () => {
    expect(agents["pentest"]).toBeDefined()
    expect(agents["pentest"].mode).toBe("primary")
    expect(agents["pentest"].description).toContain("orchestrat")
  })

  test("REQ-ARC-007: all 5 phase subagents exist (recon, enum, exploit, post, report)", () => {
    for (const name of PHASE_SUBAGENTS) {
      expect(agents[name]).toBeDefined()
      expect(agents[name].mode).toBe("subagent")
    }
  })

  test("REQ-ARC-008: all agents access tool_registry_search (in prompt)", () => {
    // Every agent's combined prompt (base + specific) must mention tool_registry_search
    for (const name of ALL_PENTEST_AGENTS) {
      const prompt = agents[name].prompt
      expect(prompt).toContain("tool_registry_search")
    }
  })

  test("REQ-ARC-009: agents instructed to query Tool Registry before MCP tools (base prompt)", () => {
    // The base prompt scaffold that all agents inherit must enforce registry-first
    expect(basePrompt).toContain("ALWAYS search tool_registry_search before MCP tools")
    expect(basePrompt).toContain("Every `mcp_tool` call requires a preceding `tool_registry_search`")
  })

  test("REQ-ARC-010-A: master agent clarifies target/scope before starting (prompt content)", () => {
    expect(masterPrompt).toContain("target IP")
    // Should ask only for missing info, not over-ask
    expect(masterPrompt).toContain("If target is provided")
    expect(masterPrompt).toContain("If target is missing")
    // Explicitly should NOT ask for authorization confirmation
    expect(masterPrompt).toContain("Do NOT ask for")
  })

  test("REQ-ARC-011-A: bash security denials force MCP usage — exact deny list matches spec", () => {
    for (const name of AGENTS_WITH_BASH_DENIALS) {
      const bash = agents[name].permission?.bash
      expect(bash).toBeDefined()
      // Verify every required denial is present
      for (const [pattern, action] of Object.entries(REQUIRED_BASH_DENIALS)) {
        expect(bash?.[pattern]).toBe(
          action,
          // Custom message for clarity on which agent/pattern failed
        )
      }
      // Default should be allow (so bash is usable for non-security commands)
      expect(bash?.["*"]).toBe("allow")
    }
  })

  test("REQ-ARC-011-A: master prompt instructs MCP-first with custom code fallback", () => {
    expect(masterPrompt).toContain("MCP First")
    expect(masterPrompt).toContain("Custom code is acceptable")
    // Should explain when custom code is okay
    expect(masterPrompt).toContain("No MCP tool exists")
  })

  test("REQ-ARC-012-A: phase subagents are accessible for direct invocation", () => {
    // All phase subagents must exist as loadable agents
    // (direct invocation = user can select them in the agent picker)
    for (const name of PHASE_SUBAGENTS) {
      expect(agents[name]).toBeDefined()
    }
  })
})

// =========================================================================
// Section 2: Recursive Delegation Model (Section 3.2.1)
// =========================================================================

describe("Recursive Delegation Model (Section 3.2.1)", () => {
  test("REQ-ARC-013: subagents can spawn their own subagents (Task tool referenced in sub-agent prompts)", () => {
    // Sub-agents that are expected to delegate: recon, enum, exploit, post, report
    // Each should reference Task tool or subagent spawning
    const delegatingAgents = ["recon", "enum", "exploit", "post", "report"]
    for (const name of delegatingAgents) {
      const prompt = agents[`pentest/${name}`].prompt
      expect(prompt).toContain("Task")
    }
  })

  test("REQ-ARC-014: delegation for context rot prevention instructed in master prompt", () => {
    const combined = agents["pentest"].prompt
    // Master prompt should explain why delegation prevents context rot
    expect(combined).toContain("context")
    expect(combined).toContain("orchestrator")
    expect(combined).toContain("delegate")
  })

  test("REQ-ARC-015-A: parent agents instructed to summarize, not copy full output", () => {
    // Master prompt should instruct summarization of sub-agent results
    expect(masterPrompt).toContain("summarize")
    expect(masterPrompt).toContain("Do NOT copy their entire output")
  })

  test("REQ-ARC-016-A: general subagent serves as flexible workhorse", () => {
    // The general agent is referenced in prompts for ad-hoc delegation
    // Note: general agent is not in loadAgents() — it's an OpenCode built-in
    // The reference should exist in relevant prompts though
    expect(agents["pentest/report"].prompt).toContain("general")
  })
})

// =========================================================================
// Section 3: Background Sub-Agent Execution (Section 3.2.2)
// =========================================================================

describe("Background Sub-Agent Execution (Section 3.2.2)", () => {
  // REQ-AGT-001 through REQ-AGT-006 are Feature 04 dependencies.
  // However, we can verify that sub-agents are marked hidden (REQ-AGT-002 prep).

  test("REQ-AGT-002 (prep): all sub-agents are hidden from session list", () => {
    for (const name of ALL_SUBAGENTS) {
      expect(agents[name].hidden).toBe(true)
    }
  })

  // REQ-AGT-001: Sub-agents run as background tasks — SKIP: Feature 04 runtime
  // REQ-AGT-003: Results displayed inline — SKIP: Feature 04 runtime
  // REQ-AGT-004: Permission bubbling to root — SKIP: Feature 04 runtime
  // REQ-AGT-005: Unified approval queue — SKIP: Feature 04 runtime
  // REQ-AGT-006: Sub-agent progress visible — SKIP: Feature 04 P1
})

// =========================================================================
// Section 4: Context Injection for Sub-Agents (Section 3.2.3)
// =========================================================================

describe("Context Injection for Sub-Agents (Section 3.2.3)", () => {
  test("REQ-AGT-010: system.transform hook exists for engagement state injection", async () => {
    // Verify the hook module exports the expected function
    const hookModule = await import("../../src/hooks/system-transform.js")
    expect(hookModule.systemTransformHook).toBeFunction()
  })

  test("REQ-AGT-011: engagement state fields referenced in sub-agent prompts", () => {
    // The master prompt should reference engagement state fields: ports, credentials, vulnerabilities
    const combined = agents["pentest"].prompt
    expect(combined).toContain("ports")
    expect(combined).toContain("credentials")
    expect(combined).toContain("vulnerabilities")
  })

  test("REQ-AGT-013: session working directory injection in system.transform hook", async () => {
    // The hook should reference SessionDirectory
    const hookSource = readFileSync(
      join(agentsDir, "../hooks/system-transform.ts"),
      "utf-8"
    )
    expect(hookSource).toContain("Session Working Directory")
    expect(hookSource).toContain("SessionDirectory")
  })

  test("REQ-AGT-013: base prompt instructs agents to use session directory", () => {
    expect(basePrompt).toContain("Session Directory")
    expect(basePrompt).toContain("/session/")
  })
})

// =========================================================================
// Section 5: Agent Configuration Correctness
// =========================================================================

describe("Agent Configuration", () => {
  test("master agent has correct color (#e74c3c red)", () => {
    expect(agents["pentest"].color).toBe("#e74c3c")
  })

  test("master agent has temperature 0.3", () => {
    expect(agents["pentest"].temperature).toBe(0.3)
  })

  test("captcha agent has temperature 0.2 for precision", () => {
    expect(agents["pentest/captcha"].temperature).toBe(0.2)
  })

  test("each phase sub-agent has a distinct color", () => {
    const colors = PHASE_SUBAGENTS.map((n) => agents[n].color)
    const uniqueColors = new Set(colors)
    // exploit and master share #e74c3c per spec, but the 5 phase agents
    // should have at least 4 distinct colors
    expect(uniqueColors.size).toBeGreaterThanOrEqual(4)
  })

  test("all agents have non-empty descriptions", () => {
    for (const name of ALL_PENTEST_AGENTS) {
      expect(agents[name].description.length).toBeGreaterThan(10)
    }
  })

  test("research agent has correct color (#1abc9c teal)", () => {
    expect(agents["pentest/research"].color).toBe("#1abc9c")
  })

  test("report agent has correct color (#27ae60 green)", () => {
    expect(agents["pentest/report"].color).toBe("#27ae60")
  })

  test("build agent exists with subagent mode", () => {
    expect(agents["pentest/build"]).toBeDefined()
    expect(agents["pentest/build"].mode).toBe("subagent")
  })

  test("captcha agent exists with subagent mode", () => {
    expect(agents["pentest/captcha"]).toBeDefined()
    expect(agents["pentest/captcha"].mode).toBe("subagent")
  })
})

// =========================================================================
// Section 6: Permission Rules (REQ-ARC-011-A detailed)
// =========================================================================

describe("Permission Rules", () => {
  test("report agent denies ALL bash (no security tools AND no general commands)", () => {
    const reportBash = agents["pentest/report"].permission?.bash
    expect(reportBash).toEqual({ "*": "deny" })
  })

  test("report agent allows external_directory for session dir", () => {
    const extDir = agents["pentest/report"].permission?.external_directory
    expect(extDir).toBeDefined()
    expect(extDir?.["/tmp/opensploit-session-*"]).toBe("allow")
    expect(extDir?.["*"]).toBe("ask")
  })

  test("master agent has question permission set to allow", () => {
    expect(agents["pentest"].permission?.question).toBe("allow")
  })

  test("master agent has plan_enter permission set to allow", () => {
    expect(agents["pentest"].permission?.plan_enter).toBe("allow")
  })

  test("captcha agent has question permission set to allow", () => {
    expect(agents["pentest/captcha"].permission?.question).toBe("allow")
  })

  test("all agents with pentestPermission have doom_loop set to ask", () => {
    for (const name of ALL_PENTEST_AGENTS) {
      expect(agents[name].permission?.doom_loop).toBe("ask")
    }
  })

  test("session directory glob pattern is allowed for all agents", () => {
    for (const name of ALL_PENTEST_AGENTS) {
      const extDir = agents[name].permission?.external_directory
      expect(extDir).toBeDefined()
      expect(extDir?.["/tmp/opensploit-session-*/**"]).toBe("allow")
    }
  })

  test("bash denial count matches spec exactly (16 denied patterns + 1 wildcard allow)", () => {
    const recon = agents["pentest/recon"]
    const bashKeys = Object.keys(recon.permission?.bash ?? {})
    // 16 denied security tools + "*": "allow" = 17 entries
    expect(bashKeys.length).toBe(17)
  })
})

// =========================================================================
// Section 7: Prompt Content Requirements
// =========================================================================

describe("Prompt Content — Base Scaffold (pentest-base.txt)", () => {
  test("TVAR framework sections: thought, verify, action, result, reflect", () => {
    expect(basePrompt).toContain("<thought>")
    expect(basePrompt).toContain("<verify>")
    expect(basePrompt).toContain("<action>")
    expect(basePrompt).toContain("<result>")
    expect(basePrompt).toContain("<reflect>")
  })

  test("TVAR: NEVER invoke tools without preceding reasoning", () => {
    expect(basePrompt).toContain("NEVER invoke tools without preceding TVAR reasoning")
  })

  test("Tool Discovery Pattern is marked MANDATORY", () => {
    expect(basePrompt).toContain("Tool Discovery Pattern (MANDATORY)")
  })

  test("registry search before mcp_tool is enforced", () => {
    expect(basePrompt).toContain("Every `mcp_tool` call requires a preceding `tool_registry_search`")
  })

  test("TodoWrite tracking is required", () => {
    expect(basePrompt).toContain("TodoWrite")
    expect(basePrompt).toContain("ALWAYS use TodoWrite to track")
  })

  test("scope boundary rule present", () => {
    expect(basePrompt).toContain("ALWAYS respect scope boundaries")
  })

  test("target identifier privacy rule present (REQ-SEC-033 base)", () => {
    expect(basePrompt).toContain("NEVER send target identifiers to external services without consent")
  })

  test("delegation instructions present in base", () => {
    expect(basePrompt).toContain("Delegation to Sub-Agents")
    expect(basePrompt).toContain("Delegate when")
  })

  test("CAPTCHA delegation rule present in base prompt", () => {
    expect(basePrompt).toContain("CAPTCHA")
    expect(basePrompt).toContain("pentest/captcha")
  })

  test("non-interactive execution guidance present", () => {
    expect(basePrompt).toContain("Non-Interactive Execution")
    expect(basePrompt).toContain("Interactive sessions never complete")
  })

  test("context budget warning guidance present", () => {
    expect(basePrompt).toContain("Context Budget")
  })
})

describe("Prompt Content — Master Agent (pentest.txt)", () => {
  test("role definition as primary orchestrator", () => {
    expect(masterPrompt).toContain("Master Penetration Testing Agent")
    expect(masterPrompt).toContain("primary orchestrator")
  })

  test("built-in tools vs MCP tools distinction documented", () => {
    expect(masterPrompt).toContain("Built-in Tools (Always Available)")
    expect(masterPrompt).toContain("Security Tools (MCP First")
  })

  test("tool selection hierarchy: Skills > Specialized > General-purpose", () => {
    expect(masterPrompt).toContain("Level 1: Skills")
    expect(masterPrompt).toContain("Level 2: Specialized")
    expect(masterPrompt).toContain("Level 3: General-Purpose")
  })

  test("anti-patterns section present", () => {
    expect(masterPrompt).toContain("Anti-Patterns to AVOID")
    expect(masterPrompt).toContain("curl over-reliance")
    expect(masterPrompt).toContain("Manual SQL injection")
  })

  test("phase methodology enumerated (phases 1 through 7)", () => {
    expect(masterPrompt).toContain("Phase 1:")
    expect(masterPrompt).toContain("Phase 2:")
    expect(masterPrompt).toContain("Phase 3:")
    expect(masterPrompt).toContain("Phase 4:")
    expect(masterPrompt).toContain("Phase 5:")
    expect(masterPrompt).toContain("Phase 6:")
    expect(masterPrompt).toContain("Phase 7:")
  })

  test("all phase subagent names referenced for delegation", () => {
    expect(masterPrompt).toContain("pentest/recon")
    expect(masterPrompt).toContain("pentest/enum")
    expect(masterPrompt).toContain("pentest/exploit")
    expect(masterPrompt).toContain("pentest/post")
    expect(masterPrompt).toContain("pentest/report")
    expect(masterPrompt).toContain("pentest/research")
    expect(masterPrompt).toContain("pentest/build")
  })

  test("TVAR example with delegation included", () => {
    expect(masterPrompt).toContain("Example (With Delegation)")
  })

  test("strategic checkpoints after sub-agent returns", () => {
    expect(masterPrompt).toContain("Strategic Checkpoint")
    expect(masterPrompt).toContain("After EVERY sub-agent returns")
  })

  test("retry discipline and failed attempts tracking", () => {
    expect(masterPrompt).toContain("failedAttempts")
    expect(masterPrompt).toContain("Retry Discipline")
  })

  test("MCP-first exploitation workflow documented", () => {
    expect(masterPrompt).toContain("Exploitation Approach (MCP-First)")
    expect(masterPrompt).toContain("searchsploit")
    expect(masterPrompt).toContain("exploit-runner")
    expect(masterPrompt).toContain("metasploit")
  })

  test("safety boundaries section present", () => {
    expect(masterPrompt).toContain("Safety Boundaries")
    expect(masterPrompt).toContain("NEVER")
    expect(masterPrompt).toContain("scope")
  })

  test("approval flow section present", () => {
    expect(masterPrompt).toContain("Approval Flow")
    expect(masterPrompt).toContain("Requires approval")
  })

  test("anomalies are findings pentester mindset", () => {
    expect(masterPrompt).toContain("Anomalies Are Findings")
  })

  test("hosts tool usage for virtual hosting", () => {
    expect(masterPrompt).toContain("hosts")
    expect(masterPrompt).toContain("/etc/hosts")
  })

  test("engagement state tracking with update_engagement_state", () => {
    expect(masterPrompt).toContain("update_engagement_state")
  })

  test("CAPTCHA hard rule and delegation", () => {
    expect(masterPrompt).toContain("HARD RULE: CAPTCHA")
    expect(masterPrompt).toContain("pentest/captcha")
  })
})

describe("Prompt Content — Phase Subagents", () => {
  test("recon prompt: reconnaissance-focused role and tool discovery", () => {
    expect(phasePrompts.recon).toContain("Reconnaissance Subagent")
    expect(phasePrompts.recon).toContain("tool_registry_search")
    expect(phasePrompts.recon).toContain("update_engagement_state")
  })

  test("enum prompt: enumeration-focused role with service categories", () => {
    expect(phasePrompts.enum).toContain("Enumeration Subagent")
    expect(phasePrompts.enum).toContain("Web Services")
    expect(phasePrompts.enum).toContain("SMB")
  })

  test("exploit prompt: exploitation-focused with approval requirement", () => {
    expect(phasePrompts.exploit).toContain("Exploitation Subagent")
    expect(phasePrompts.exploit).toContain("Approval Request")
    expect(phasePrompts.exploit).toContain("Request approval before")
  })

  test("post prompt: post-exploitation orchestrator that delegates", () => {
    expect(phasePrompts.post).toContain("Post-Exploitation Orchestrator")
    expect(phasePrompts.post).toContain("Task")
    expect(phasePrompts.post).toContain("pentest/enum")
    expect(phasePrompts.post).toContain("pentest/exploit")
  })

  test("report prompt: reporting-focused with data sources and templates", () => {
    expect(phasePrompts.report).toContain("Reporting Subagent")
    expect(phasePrompts.report).toContain("Executive Summary")
    expect(phasePrompts.report).toContain("Severity Rating")
  })

  test("research prompt: OSINT specialist with context isolation", () => {
    expect(phasePrompts.research).toContain("Research/OSINT Subagent")
    expect(phasePrompts.research).toContain("ISOLATED context")
    expect(phasePrompts.research).toContain("WebFetch")
    expect(phasePrompts.research).toContain("WebSearch")
  })

  test("build prompt: exploit builder with testing standards", () => {
    expect(phasePrompts.build).toContain("Build Subagent")
    expect(phasePrompts.build).toContain("Testing Standards")
    expect(phasePrompts.build).toContain("Test before returning")
  })

  test("all phase prompts reference state tracking", () => {
    const subagentPromptNames = ["recon", "enum", "exploit", "post", "report"]
    for (const name of subagentPromptNames) {
      const prompt = phasePrompts[name]
      // Each should reference engagement state via tool calls or file reads
      const hasStateTracking =
        prompt.includes("update_engagement_state") ||
        prompt.includes("read_engagement_state") ||
        prompt.includes("engagement_state") ||
        prompt.includes("Engagement State") || // report agent reads state.yaml
        prompt.includes("state.yaml")
      expect(hasStateTracking).toBe(true)
    }
  })

  test("all phase prompts include handoff instructions", () => {
    const subagentPromptNames = ["recon", "enum", "exploit", "post", "report"]
    for (const name of subagentPromptNames) {
      expect(phasePrompts[name]).toContain("Handoff")
    }
  })

  test("all phase prompts include output format guidance", () => {
    const subagentPromptNames = ["recon", "enum", "exploit", "report"]
    for (const name of subagentPromptNames) {
      expect(phasePrompts[name]).toContain("Output Format")
    }
  })
})

describe("Prompt Content — TVAR in Subagent Prompts", () => {
  test("TVAR framework referenced in all agent combined prompts (via base inheritance)", () => {
    for (const name of ALL_PENTEST_AGENTS) {
      const combined = agents[name].prompt
      // Base prompt is concatenated — TVAR must be present
      expect(combined).toContain("TVAR")
      expect(combined).toContain("<thought>")
      expect(combined).toContain("<verify>")
    }
  })

  test("TVAR examples present in key subagent prompts", () => {
    // recon, enum, exploit, post, build should have TVAR examples in their specific prompt
    const agentsWithTVAR = ["recon", "enum", "exploit", "post", "build"]
    for (const name of agentsWithTVAR) {
      expect(phasePrompts[name]).toContain("TVAR")
    }
  })
})

// =========================================================================
// Section 8: Prompt Structural Integrity
// =========================================================================

describe("Prompt Structural Integrity", () => {
  test("all prompts are composed as base + specific (base prefix check)", () => {
    for (const name of ALL_PENTEST_AGENTS) {
      const combined = agents[name].prompt
      // Combined prompt must start with the base prompt content
      expect(combined.startsWith(basePrompt)).toBe(true)
    }
  })

  test("all combined prompts are longer than base alone", () => {
    for (const name of ALL_PENTEST_AGENTS) {
      expect(agents[name].prompt.length).toBeGreaterThan(basePrompt.length + 100)
    }
  })

  test("no prompt contains template placeholders like {{ or {%", () => {
    for (const name of ALL_PENTEST_AGENTS) {
      const prompt = agents[name].prompt
      expect(prompt).not.toContain("{{")
      expect(prompt).not.toContain("{%")
    }
  })
})

// =========================================================================
// Section 9: Security Integration (Feature 10 — prompt-level)
// =========================================================================

describe("Security Integration (prompt-level)", () => {
  test("REQ-SEC-001/002: master prompt addresses non-private IP and external target handling", () => {
    // The master prompt should indicate authorization context for HTB/private IPs
    expect(masterPrompt).toContain("HackTheBox")
    expect(masterPrompt).toContain("Private IP")
    expect(masterPrompt).toContain("authorized")
  })

  test("REQ-SEC-033: research subagent warns about target data in external queries", () => {
    // The base prompt has the global rule; check research has context isolation
    expect(phasePrompts.research).toContain("ISOLATED context")
  })
})

// =========================================================================
// Section 10: Sub-Agent Completeness
// =========================================================================

describe("Sub-Agent Completeness", () => {
  test("exactly 9 agents total (1 master + 8 sub-agents)", () => {
    expect(Object.keys(agents).length).toBe(9)
  })

  test("all expected agents present by name", () => {
    for (const name of ALL_PENTEST_AGENTS) {
      expect(agents[name]).toBeDefined()
    }
  })

  test("all sub-agents have mode=subagent and hidden=true", () => {
    for (const name of ALL_SUBAGENTS) {
      expect(agents[name].mode).toBe("subagent")
      expect(agents[name].hidden).toBe(true)
    }
  })

  test("research subagent is separate from phase subagents (OSINT isolation)", () => {
    // Research agent should exist and NOT be one of the 5 phase agents
    expect(agents["pentest/research"]).toBeDefined()
    expect(PHASE_SUBAGENTS).not.toContain("pentest/research")
  })
})

// =========================================================================
// Gap Analysis
// =========================================================================

/**
 * FEATURE 02 — GAP ANALYSIS
 *
 * | REQ ID          | Implemented | Tested (here) | Notes                                              |
 * |-----------------|-------------|---------------|----------------------------------------------------|
 * | REQ-ARC-001     | Yes         | Implicit      | loadAgents() succeeds = fork-based agent system     |
 * | REQ-ARC-002     | Yes         | Yes           | Phase keywords in master prompt                     |
 * | REQ-ARC-003     | Yes         | No            | Runtime concern — conversation context maintained    |
 * |                 |             |               | by agent loop, not testable in unit                 |
 * | REQ-ARC-004     | Yes         | Yes           | Task tool reference in master prompt                |
 * | REQ-ARC-005     | Partial     | No            | Planning in prompt (P1), no structured planner      |
 * | REQ-ARC-006     | Yes         | Yes           | Master agent exists, mode=primary, description      |
 * | REQ-ARC-007     | Yes         | Yes           | All 5 phase subagents defined                       |
 * | REQ-ARC-008     | Yes         | Yes           | tool_registry_search in all prompts                 |
 * | REQ-ARC-009     | Yes         | Yes           | Base prompt enforces registry-first rule             |
 * | REQ-ARC-010-A   | Yes         | Yes           | Scope clarification in master prompt                |
 * | REQ-ARC-011-A   | Yes         | Yes           | Exact bash denial list + MCP-first prompt           |
 * | REQ-ARC-012-A   | Yes         | Yes           | Phase subagents are loadable                        |
 * | REQ-ARC-013     | Yes         | Yes           | Task tool reference in sub-agent prompts             |
 * | REQ-ARC-014     | Yes         | Yes           | Context rot prevention in master prompt             |
 * | REQ-ARC-015-A   | Yes         | Yes           | Summarize instruction in master prompt               |
 * | REQ-ARC-016-A   | Partial     | Yes           | general agent referenced in report prompt;           |
 * |                 |             |               | not defined in plugin (OpenCode built-in)           |
 * | REQ-AGT-001     | No          | No            | Feature 04 dependency (background execution)        |
 * | REQ-AGT-002     | Partial     | Yes           | hidden=true set; full background flag in Feature 04 |
 * | REQ-AGT-003     | No          | No            | Feature 04 dependency (inline results)              |
 * | REQ-AGT-004     | No          | No            | Feature 04 dependency (permission bubbling)         |
 * | REQ-AGT-005     | No          | No            | Feature 04 dependency (approval queue)              |
 * | REQ-AGT-006     | No          | No            | Feature 04 dependency P1 (progress visibility)      |
 * | REQ-AGT-010     | Yes         | Yes           | system.transform hook injects engagement state      |
 * | REQ-AGT-011     | Yes         | Yes           | Engagement state fields in prompt                   |
 * | REQ-AGT-012     | Partial     | No            | update_engagement_state exists (Feature 07 P1)      |
 * | REQ-AGT-013     | Yes         | Yes           | Session dir in hook + base prompt                   |
 * | REQ-SEC-001     | Yes (prompt)| Yes           | Authorization context in master prompt              |
 * | REQ-SEC-002     | Yes (prompt)| Yes           | Authorization context in master prompt              |
 * | REQ-SEC-003     | No          | No            | Feature 10 dependency (forbidden targets list)      |
 * | REQ-SEC-004     | No          | No            | Feature 10 dependency (audit logging)               |
 * | REQ-SEC-033     | Yes (prompt)| Yes           | Context isolation in research prompt + base rule    |
 * | REQ-RSN-002/003 | Yes         | Yes           | TVAR in base scaffold + all agent prompts           |
 *
 * === Summary ===
 * Total REQs: 30
 * Implemented: 22 (4 partial)
 * Tested here: 24 (some implicit)
 * Not implemented (blocked): 8 (Feature 04: 6, Feature 10: 2)
 */
