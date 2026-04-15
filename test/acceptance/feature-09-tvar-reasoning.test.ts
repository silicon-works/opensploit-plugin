/**
 * Feature 09: TVAR Reasoning — Acceptance Tests
 *
 * Each test maps to a specific REQ-* from:
 *   opensploit-vault/requirements/09-tvar-reasoning.md
 *
 * Scope: Tests PROMPT CONTENT that instructs agents to use TVAR reasoning.
 * TVAR parsing, rendering, and trajectory recording are fork territory
 * (packages/opensploit/src/session/) and are not tested here.
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

const basePrompt = readPromptFile("pentest-base.txt")
const masterPrompt = readPromptFile("pentest.txt")

// Phase-specific prompt files (NOT combined — just the per-agent file)
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

// All pentest agents
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

// Agents that directly invoke security tools (should have TVAR examples in their
// specific prompt, not just via base inheritance). Report, research, and captcha
// do not invoke MCP security tools in the standard TVAR pattern.
const TOOL_INVOKING_AGENTS = ["recon", "enum", "exploit", "build"]

// Post agent orchestrates via Task, not mcp_tool, but still needs TVAR for decisions
const ORCHESTRATING_AGENTS = ["post"]

// =========================================================================
// Section 1: Structured Reasoning Framework (Section 16.1)
// =========================================================================

describe("Structured Reasoning Framework (Section 16.1)", () => {
  test("REQ-RSN-001: base prompt requires explicit structured reasoning for all decisions", () => {
    // The base prompt must explicitly require TVAR reasoning
    expect(basePrompt).toContain("## Reasoning Framework (TVAR)")
    expect(basePrompt).toContain("MUST follow the TVAR pattern")
  })

  test("REQ-RSN-002: base prompt defines TVAR pattern — Thought, Verify, Action, Result", () => {
    // All four core TVAR tags must be documented in the base prompt
    expect(basePrompt).toContain("### <thought>")
    expect(basePrompt).toContain("### <verify>")
    expect(basePrompt).toContain("### <action>")
    expect(basePrompt).toContain("### <result>")
  })

  test("REQ-RSN-002: base prompt includes <reflect> as extension of TVAR for failures", () => {
    // The reflect tag is an opensploit extension to TVAR for failure recovery
    expect(basePrompt).toContain("### <reflect>")
    expect(basePrompt).toContain("MANDATORY after any failure")
  })

  test("REQ-RSN-002: all combined agent prompts contain TVAR tags (via base inheritance)", () => {
    for (const name of ALL_PENTEST_AGENTS) {
      const combined = agents[name].prompt
      expect(combined).toContain("<thought>")
      expect(combined).toContain("<verify>")
      expect(combined).toContain("<action>")
      expect(combined).toContain("<result>")
    }
  })

  test("REQ-RSN-003: base prompt forbids tool invocation without preceding reasoning", () => {
    expect(basePrompt).toContain(
      "NEVER invoke tools without preceding TVAR reasoning"
    )
  })

  test("REQ-RSN-003: master prompt reinforces 'NEVER invoke without Thought and Verify'", () => {
    expect(masterPrompt).toContain(
      "NEVER invoke a tool without completing the Thought and Verify steps first"
    )
  })

  test("REQ-RSN-004: verify step checks tool appropriateness (base prompt)", () => {
    // The <verify> section in base prompt must reference tool selection
    expect(basePrompt).toContain("Is this the right tool for the task?")
    expect(basePrompt).toContain("Have I searched the tool registry first?")
    expect(basePrompt).toContain("Am I following MCP-first policy?")
  })

  test("REQ-RSN-004: verify step checks safety and scope (base prompt)", () => {
    expect(basePrompt).toContain("Is this approach safe and within scope?")
  })

  test("REQ-RSN-005: result step instructs analysis of tool output (base prompt)", () => {
    // The <result> section must instruct analysis before next cycle
    expect(basePrompt).toContain("What did I learn?")
    expect(basePrompt).toContain("What should I do next?")
  })

  test("REQ-RSN-005: result step checks todo advancement (base prompt)", () => {
    expect(basePrompt).toContain(
      "Did this advance my current todo step?"
    )
  })
})

// =========================================================================
// Section 2: Strategic Planning (Section 16.2)
// =========================================================================

describe("Strategic Planning (Section 16.2)", () => {
  test("REQ-RSN-010: master prompt requires initial attack plan at session start", () => {
    // The master prompt must instruct creating an attack plan
    expect(masterPrompt).toContain("Attack Plan Creation")
    expect(masterPrompt).toContain("attackPlan")
  })

  test("REQ-RSN-010: base prompt requires TodoWrite at session start", () => {
    expect(basePrompt).toContain("At the START of your session, create a todo list")
    expect(basePrompt).toContain("TodoWrite")
  })

  test("REQ-RSN-011: master prompt instructs plan updates as findings emerge", () => {
    expect(masterPrompt).toContain("Update step status as agents work")
  })

  test("REQ-RSN-012: master prompt maintains prioritized attack vectors", () => {
    // The master prompt should reference prioritized attack vectors or steps
    expect(masterPrompt).toContain("attackPlan")
    // Attack plan has steps with status tracking
    expect(masterPrompt).toContain("status")
    expect(masterPrompt).toContain("pending")
  })

  test("REQ-RSN-013: plan changes require reasoning (verify block alignment)", () => {
    // The exploit and build prompts require plan step alignment in verify block
    expect(phasePrompts.exploit).toContain("Plan step alignment")
    expect(phasePrompts.build).toContain("Plan step alignment")
  })
})

// =========================================================================
// Section 3: Failure Recovery & Adaptation (Section 16.3)
// =========================================================================

describe("Failure Recovery & Adaptation (Section 16.3)", () => {
  test("REQ-RSN-020: base prompt requires failure analysis via <reflect>", () => {
    expect(basePrompt).toContain("Root cause hypothesis")
    expect(basePrompt).toContain("Why did this fail?")
  })

  test("REQ-RSN-020: <reflect> includes pattern check for shared root causes", () => {
    expect(basePrompt).toContain("Pattern check")
    expect(basePrompt).toContain(
      "Do my recent failures share this same root cause?"
    )
  })

  test("REQ-RSN-021: base prompt forbids repeating identical failed approaches", () => {
    expect(basePrompt).toContain(
      "Does this action advance my current todo step, or am I repeating a failed approach?"
    )
  })

  test("REQ-RSN-021: base prompt warns against semantic loops (surface variations)", () => {
    expect(basePrompt).toContain("semantic loop")
    expect(basePrompt).toContain(
      "cosmetically different approaches"
    )
  })

  test("REQ-RSN-021: master prompt tracks failedAttempts in engagement state", () => {
    expect(masterPrompt).toContain("failedAttempts")
    // Master prompt checks failedAttempts before retrying
    expect(masterPrompt).toContain(
      "same technique appears there, it is BLOCKED"
    )
  })

  test("REQ-RSN-022: base prompt instructs searching for alternatives after failure", () => {
    // After failures, agents should search for alternative tools/methods
    expect(basePrompt).toContain("pattern_search")
    expect(basePrompt).toContain("failedAttempts")
  })

  test("REQ-RSN-022: base prompt instructs alternative approach after stall", () => {
    expect(basePrompt).toContain(
      "next `<thought>` must address the ROOT CAUSE"
    )
  })

  test("REQ-RSN-023: base prompt addresses stalled progress escalation", () => {
    // After 3+ attempts without progress, agents should delegate or escalate
    expect(basePrompt).toContain("3+ attempts at the same sub-goal without progress")
    expect(basePrompt).toContain(
      "Delegate the blocked sub-task to a fresh-context sub-agent"
    )
  })

  test("REQ-RSN-023: base prompt instructs marking blocked steps as failed", () => {
    expect(basePrompt).toContain("mark it \"failed\" and pivot")
  })

  test("REQ-RSN-020: master prompt has mandatory pivot triggers table", () => {
    expect(masterPrompt).toContain("Mandatory Pivot Triggers")
    expect(masterPrompt).toContain("Same technique in `failedAttempts` 2+ times")
  })
})

// =========================================================================
// Section 4: TVAR in Phase-Specific Prompts
// =========================================================================

describe("TVAR in Phase-Specific Prompts", () => {
  test("all tool-invoking agents have TVAR section in their specific prompt", () => {
    for (const name of TOOL_INVOKING_AGENTS) {
      expect(phasePrompts[name]).toContain("TVAR Reasoning (REQUIRED)")
    }
  })

  test("post-exploitation orchestrator has TVAR section for delegation decisions", () => {
    expect(phasePrompts.post).toContain("TVAR Reasoning (REQUIRED)")
  })

  test("recon TVAR example is reconnaissance-specific (port scanning)", () => {
    const prompt = phasePrompts.recon
    // Should contain a TVAR example with recon-specific content
    expect(prompt).toContain("<thought>")
    expect(prompt).toContain("reconnaissance")
    expect(prompt).toContain("port")
  })

  test("enum TVAR example is enumeration-specific (directory/service discovery)", () => {
    const prompt = phasePrompts.enum
    expect(prompt).toContain("<thought>")
    expect(prompt).toContain("enumeration")
    expect(prompt).toContain("discover")
  })

  test("exploit TVAR example is exploitation-specific (vulnerability exploitation)", () => {
    const prompt = phasePrompts.exploit
    expect(prompt).toContain("<thought>")
    expect(prompt).toContain("vulnerability")
    expect(prompt).toContain("exploit")
  })

  test("post TVAR example is post-exploitation-specific (access level, sub-agent spawning)", () => {
    const prompt = phasePrompts.post
    expect(prompt).toContain("<thought>")
    expect(prompt).toContain("Access level")
    expect(prompt).toContain("Sub-agent type")
  })

  test("build TVAR example is build-specific (exploit/payload creation)", () => {
    const prompt = phasePrompts.build
    expect(prompt).toContain("<thought>")
    expect(prompt).toContain("exploit")
    expect(prompt).toContain("payload")
  })

  test("master prompt has TVAR example WITH delegation pattern", () => {
    expect(masterPrompt).toContain("Example (With Delegation)")
    // Should show spawning a subagent in the TVAR example
    expect(masterPrompt).toContain("Delegate?")
  })

  test("master prompt has TVAR example for self-execution (rare case)", () => {
    expect(masterPrompt).toContain("Example (Self-Execution - Rare)")
  })
})

// =========================================================================
// Section 5: Anti-Pattern Prevention via Verify Step
// =========================================================================

describe("Anti-Pattern Prevention via Verify Step", () => {
  test("base prompt verify step includes anti-pattern check", () => {
    // The verify section must check for anti-patterns
    expect(basePrompt).toContain("am I repeating a failed approach")
  })

  test("master prompt documents curl over-reliance anti-pattern", () => {
    expect(masterPrompt).toContain("curl over-reliance")
  })

  test("master prompt documents manual SQL injection anti-pattern", () => {
    expect(masterPrompt).toContain("Manual SQL injection")
  })

  test("master prompt documents manual credential testing anti-pattern", () => {
    expect(masterPrompt).toContain("Manual credential testing")
  })

  test("master prompt documents custom exploit writing anti-pattern", () => {
    expect(masterPrompt).toContain("Writing custom exploits")
  })

  test("enum prompt documents anti-patterns for enumeration (curl for HTTP enum)", () => {
    expect(phasePrompts.enum).toContain("Anti-Patterns to AVOID")
    expect(phasePrompts.enum).toContain("curl for HTTP enumeration")
  })

  test("build prompt documents anti-patterns (building what exists, returning untested)", () => {
    expect(phasePrompts.build).toContain("Anti-Patterns")
    expect(phasePrompts.build).toContain("Building what already exists")
    expect(phasePrompts.build).toContain("Returning untested code")
  })

  test("tool-invoking agents verify tool selection in TVAR example", () => {
    // Each TVAR example in tool-invoking agents should show tool selection reasoning
    // in their <verify> block (wording varies: "Tool selection", "Found existing", etc.)
    for (const name of TOOL_INVOKING_AGENTS) {
      const prompt = phasePrompts[name]
      expect(prompt).toContain("<verify>")
      // The verify block should contain reasoning about approach/tool choice
      const hasToolReasoning =
        prompt.includes("Tool selection") ||
        prompt.includes("Found existing") ||
        prompt.includes("right approach") ||
        prompt.includes("right tool")
      expect(hasToolReasoning).toBe(true)
    }
  })
})

// =========================================================================
// Section 6: Tool Registry Integration in TVAR
// =========================================================================

describe("Tool Registry Integration in TVAR", () => {
  test("base prompt TVAR example shows registry search before mcp_tool", () => {
    // The base prompt's example TVAR should show the registry search pattern
    expect(basePrompt).toContain("tool_registry_search")
    expect(basePrompt).toContain("Example TVAR with Registry Search")
  })

  test("base prompt requires registry confirmation in verify block", () => {
    expect(basePrompt).toContain(
      'Confirm "Registry searched: [yes/no], tool selected: [name] because [reason]"'
    )
  })

  test("master prompt requires registry confirmation in verify block", () => {
    expect(masterPrompt).toContain(
      "Registry searched: yes/no. Selected tool: X because Y"
    )
  })

  test("base prompt warns about search cache to avoid redundant searches", () => {
    expect(basePrompt).toContain("Search cache")
    expect(basePrompt).toContain("toolSearchCache")
  })
})

// =========================================================================
// Section 7: TVAR-Linked Critical Rules
// =========================================================================

describe("TVAR-Linked Critical Rules", () => {
  test("base prompt Critical Rules section references TVAR", () => {
    expect(basePrompt).toContain("Critical Rules (All Pentest Agents)")
    expect(basePrompt).toContain("NEVER invoke tools without preceding TVAR reasoning")
  })

  test("base prompt links <reflect> to failure handling as non-optional", () => {
    expect(basePrompt).toContain(
      "ALWAYS <reflect> after failures"
    )
    expect(basePrompt).toContain("the reflect step is not optional")
  })

  test("base prompt links todo tracking to TVAR verify and reflect steps", () => {
    // Verify should reference todo step, reflect should check todo progress
    expect(basePrompt).toContain("Which step am I currently working on?")
    expect(basePrompt).toContain("What step am I stuck on?")
  })

  test("master prompt links TVAR to delegation decisions", () => {
    // The TVAR <thought> in master should ask about delegation
    expect(masterPrompt).toContain("Delegate?")
    expect(masterPrompt).toContain(
      "Is this phase work, exploit building, or research?"
    )
  })
})

// =========================================================================
// Section 8: Report and Research Agents — TVAR Scope
// =========================================================================

describe("Report and Research Agents — TVAR Scope", () => {
  test("report agent inherits TVAR via base prompt but has no tool-specific TVAR section", () => {
    // Report agent should NOT have its own TVAR section (no tool invocation)
    // but should inherit TVAR from base
    const combined = agents["pentest/report"].prompt
    expect(combined).toContain("TVAR")
    // The report-specific prompt should NOT have a TVAR section
    expect(phasePrompts.report).not.toContain("TVAR")
  })

  test("research agent inherits TVAR via base prompt but has no tool-specific TVAR section", () => {
    // Research agent uses web tools and MCP, but doesn't need its own TVAR section
    const combined = agents["pentest/research"].prompt
    expect(combined).toContain("TVAR")
    expect(phasePrompts.research).not.toContain("TVAR")
  })

  test("captcha agent inherits TVAR via base and has abbreviated TVAR override", () => {
    // Captcha agent inherits full TVAR from base but has a Performance Override
    // section that allows abbreviated single-line reasoning during browser interactions
    const combined = agents["pentest/captcha"].prompt
    expect(combined).toContain("TVAR")
    // Captcha-specific prompt has an abbreviated TVAR policy (not a full TVAR section)
    expect(phasePrompts.captcha).toContain("Abbreviated TVAR")
  })
})

// =========================================================================
// Section 9: Trajectory Recording (prompt-level)
// =========================================================================

describe("Trajectory Recording — Prompt-Level (Section 16.5)", () => {
  // REQ-RSN-030 through REQ-RSN-033 are about the fork's recording infrastructure.
  // However, the prompts contribute by:
  // 1. Instructing agents to produce structured TVAR output (which the parser captures)
  // 2. Instructing agents to save state (which trajectory aggregates from)

  test("REQ-RSN-030/031 (prompt contrib): agents produce parseable TVAR blocks", () => {
    // All combined prompts must instruct agents to produce <thought> ... <verify> ... etc.
    // that the fork's tvar-parser.ts can parse
    for (const name of ALL_PENTEST_AGENTS) {
      const combined = agents[name].prompt
      // Must have opening and closing tags that the parser matches
      expect(combined).toContain("<thought>")
      expect(combined).toContain("</thought>")
      expect(combined).toContain("<verify>")
      expect(combined).toContain("</verify>")
    }
  })

  test("REQ-RSN-030 (prompt contrib): base prompt instructs engagement state saves", () => {
    // Trajectory.fromSession() aggregates from session messages + engagement state
    // Prompts must instruct agents to save state for trajectory completeness
    expect(basePrompt).toContain("update_engagement_state")
    expect(basePrompt).toContain("Save state often")
  })
})

// =========================================================================
// Gap Analysis
// =========================================================================

/**
 * FEATURE 09 — GAP ANALYSIS
 *
 * | REQ ID          | Scope   | Implemented | Tested (here) | Notes                                          |
 * |-----------------|---------|-------------|---------------|-------------------------------------------------|
 * | REQ-RSN-001     | Plugin  | Yes         | Yes           | Base prompt requires TVAR for all decisions      |
 * | REQ-RSN-002     | Plugin  | Yes         | Yes           | All 4 TVAR tags + <reflect> in base prompt       |
 * | REQ-RSN-003     | Plugin  | Yes         | Yes           | "NEVER invoke without TVAR" in base + master     |
 * | REQ-RSN-004     | Plugin  | Yes         | Yes           | Verify step checks tool, registry, safety        |
 * | REQ-RSN-005     | Plugin  | Yes         | Yes           | Result step instructs analysis + todo check      |
 * | REQ-RSN-010     | Plugin  | Yes         | Yes           | Attack plan + TodoWrite at session start         |
 * | REQ-RSN-011     | Plugin  | Yes         | Yes           | Plan update instructions in master prompt        |
 * | REQ-RSN-012     | Plugin  | Yes         | Yes           | attackPlan with status tracking                  |
 * | REQ-RSN-013     | Plugin  | Yes         | Yes           | Plan step alignment in verify block              |
 * | REQ-RSN-020     | Plugin  | Yes         | Yes           | <reflect> with root cause analysis               |
 * | REQ-RSN-021     | Plugin  | Yes         | Yes           | Semantic loop warning + failedAttempts           |
 * | REQ-RSN-022     | Plugin  | Yes         | Yes           | pattern_search + root cause in next <thought>    |
 * | REQ-RSN-023     | Plugin  | Yes         | Yes           | 3+ stall → delegate + mark failed                |
 * | REQ-RSN-030     | Fork    | N/A         | Partial       | Prompt contrib: parseable TVAR blocks            |
 * | REQ-RSN-031     | Fork    | N/A         | No            | Fork: trajectory stored with session data        |
 * | REQ-RSN-032     | Fork    | N/A         | No            | Fork: exportable in training format              |
 * | REQ-RSN-033     | Fork    | N/A         | No            | Fork: timing information in trajectory           |
 * | REQ-RSN-034     | Fork    | N/A         | No            | Fork: TVAR blocks parsed to TVARPart             |
 * | REQ-RSN-035     | Fork    | N/A         | No            | Fork: TVAR stripped from TextPart                |
 * | REQ-RSN-036     | Fork    | N/A         | No            | Fork: muted/collapsed TUI rendering              |
 * | REQ-RSN-037     | Fork    | N/A         | No            | Fork: expandable TVAR details (P1)               |
 * | REQ-RSN-038     | Fork    | N/A         | No            | Fork: togglable TVAR display (P1)                |
 * | REQ-TST-040     | Fork    | N/A         | No            | Fork: trajectory recording during execution      |
 * | REQ-TST-041     | Fork    | N/A         | No            | Fork: TVAR components in trajectory              |
 * | REQ-TST-042     | Neither | No          | No            | Golden Test Set not created (deferred P1)        |
 * | REQ-TST-043     | Neither | No          | No            | Golden Test Set scenarios (deferred P1)          |
 * | REQ-TST-044     | Neither | No          | No            | Tool selection evaluation (deferred P1)          |
 * | REQ-TST-045     | Neither | No          | No            | Anti-pattern flagging (deferred P1)              |
 * | REQ-TST-046     | Neither | No          | No            | Evaluation reports (deferred P1)                 |
 * | REQ-TST-047     | Fork    | N/A         | No            | Fork: trajectory exportable for training         |
 *
 * === Summary ===
 * Total REQs: 27
 * Plugin scope (prompt content): 13 — ALL implemented and tested here
 * Fork scope (parsing/rendering/trajectory): 12 — not testable in plugin
 * Deferred (Golden Test Set P1): 5 — neither plugin nor fork has implemented
 *
 * === Gaps Found ===
 * NONE in plugin scope. All prompt-level TVAR requirements are fully covered.
 *
 * For fork-scope items, see packages/opensploit tests:
 *   test/session/tvar-parser.test.ts (17 tests)
 *   test/session/trajectory.test.ts (21 tests)
 *
 * Golden Test Set (REQ-TST-042 through REQ-TST-046) is explicitly deferred
 * to post-MVP per the requirements document's own recommendation (line 637-639).
 */
