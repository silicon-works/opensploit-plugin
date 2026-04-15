/**
 * Features 12, 17, 18, 19, 20 — Combined Acceptance Tests (Gaps Only)
 *
 * These five smaller features are largely covered by existing tests:
 *   - Feature 02 tests verify agent existence, prompts, permissions for all 9 agents
 *   - Feature 03 tests verify engagement state schema (attackPlan, failedAttempts, credentials)
 *   - agents/index.test.ts verifies structural correctness
 *
 * This file covers GAPS not addressed elsewhere:
 *
 * Feature 12 (Reporting):
 *   - Report prompt has severity rating system, evidence/remediation templates
 *   - Report agent denies all bash (security: no tool execution)
 *   - Report prompt reads from state.yaml AND findings/*.md
 *
 * Feature 17 (Failure Escalation — ARCHIVED):
 *   - failedAttempts tracking in state (schema+persistence covered in F03)
 *   - Master prompt references failedAttempts for retry discipline
 *   - Escalation triggers after 2+ failures of same technique in prompt
 *
 * Feature 18 (Attack Plan Tracking):
 *   - Attack plan schema with step statuses (schema+persistence covered in F03)
 *   - Master prompt references attackPlan for step tracking
 *   - Subagent prompts reference Attack Plan Compliance
 *   - Attack plan step source field in schema
 *
 * Feature 19 (Credential & Session Resilience):
 *   - Credential schema fields: hash, privileged, source, validated
 *   - Schema uses .passthrough() for LLM flexibility (authMethod, lastUsed, etc.)
 *   - Credential dedup by username+service (covered in F03)
 *
 * Feature 20 (pentest/build Subagent):
 *   - Build prompt has FIND->BUILD->TEST->RETURN workflow
 *   - Build agent has correct permissions (pentestPermission, not report-style)
 *   - Build prompt references session directory artifacts
 *   - Master prompt delegates to pentest/build
 */

import { describe, expect, test, afterEach } from "bun:test"
import { loadAgents } from "../../src/agents/index"
import { readFileSync } from "fs"
import { join, dirname } from "path"
import { fileURLToPath } from "url"
import {
  createUpdateEngagementStateTool,
  loadEngagementState,
  saveEngagementState,
  mergeState,
  type EngagementState,
} from "../../src/tools/engagement-state"
import * as SessionDirectory from "../../src/session/directory"
import type { ToolContext } from "@opencode-ai/plugin"

const __dirname = dirname(fileURLToPath(import.meta.url))
const agentsDir = join(__dirname, "../../src/agents")
const promptDir = join(agentsDir, "prompts")

const agents = loadAgents()

function readPromptFile(name: string): string {
  return readFileSync(join(promptDir, name), "utf-8")
}

const masterPrompt = readPromptFile("pentest.txt")
const basePrompt = readPromptFile("pentest-base.txt")
const reportPrompt = readPromptFile("pentest/report.txt")
const buildPrompt = readPromptFile("pentest/build.txt")
const exploitPrompt = readPromptFile("pentest/exploit.txt")

const updateTool = createUpdateEngagementStateTool()

function makeContext(sessionId: string): { ctx: ToolContext; metadataCalls: Array<any> } {
  const metadataCalls: Array<any> = []
  const ctx: ToolContext = {
    sessionID: sessionId,
    messageID: "test-msg",
    agent: "pentest",
    directory: "/tmp",
    worktree: "/tmp",
    abort: new AbortController().signal,
    metadata: (input) => { metadataCalls.push(input) },
    ask: async () => {},
  }
  return { ctx, metadataCalls }
}

let testCounter = 0
function uniqueSessionID(prefix = "misc"): string {
  return `${prefix}-${Date.now()}-${++testCounter}`
}

// =============================================================================
// Feature 12: Reporting
// =============================================================================

describe("Feature 12: Reporting Agent", () => {

  test("REQ-FUN-070: report prompt instructs reading state.yaml for structured findings", () => {
    expect(reportPrompt).toContain("state.yaml")
    expect(reportPrompt).toContain("Engagement State")
    // Must read from BOTH structured and prose sources
    expect(reportPrompt).toContain("findings/*.md")
    expect(reportPrompt).toContain("Compile from BOTH sources")
  })

  test("REQ-FUN-071: report prompt includes severity rating system with CVSS ranges", () => {
    expect(reportPrompt).toContain("Severity Rating")
    expect(reportPrompt).toContain("Critical")
    expect(reportPrompt).toContain("9.0 - 10.0")
    expect(reportPrompt).toContain("High")
    expect(reportPrompt).toContain("7.0 - 8.9")
    expect(reportPrompt).toContain("Medium")
    expect(reportPrompt).toContain("4.0 - 6.9")
    expect(reportPrompt).toContain("Low")
    expect(reportPrompt).toContain("0.1 - 3.9")
    expect(reportPrompt).toContain("Info")
  })

  test("REQ-FUN-072: report prompt includes evidence and reproduction templates", () => {
    // Finding template must include evidence and remediation sections
    expect(reportPrompt).toContain("### Evidence")
    expect(reportPrompt).toContain("### Remediation")
    expect(reportPrompt).toContain("### Description")
    expect(reportPrompt).toContain("### Impact")
    // CVSS score and CVE in finding template
    expect(reportPrompt).toContain("CVSS Score")
    expect(reportPrompt).toContain("CVE")
  })

  test("REQ-FUN-070: report prompt includes executive summary template", () => {
    expect(reportPrompt).toContain("Executive Summary")
    expect(reportPrompt).toContain("Engagement Overview")
    expect(reportPrompt).toContain("Key Findings")
    expect(reportPrompt).toContain("Risk Assessment")
    expect(reportPrompt).toContain("Strategic Recommendations")
  })

  test("REQ-FUN-070: report agent denies ALL bash to prevent tool execution", () => {
    // Report agent should have no bash access — it only reads and writes
    const reportBash = agents["pentest/report"].permission?.bash
    expect(reportBash).toEqual({ "*": "deny" })
  })

  test("REQ-FUN-070: report prompt instructs file output naming convention", () => {
    expect(reportPrompt).toContain("pentest-report-")
    expect(reportPrompt).toContain("pentest-executive-summary-")
    expect(reportPrompt).toContain("pentest-findings-")
  })

  test("REQ-FUN-070: report prompt includes report generation process (ordered steps)", () => {
    expect(reportPrompt).toContain("Gather Information")
    expect(reportPrompt).toContain("Categorize Findings")
    expect(reportPrompt).toContain("Write Executive Summary")
    expect(reportPrompt).toContain("Document Technical Findings")
    expect(reportPrompt).toContain("Create Remediation Roadmap")
  })

  test("REQ-FUN-070: report prompt includes quality checklist", () => {
    expect(reportPrompt).toContain("Quality Checklist")
    expect(reportPrompt).toContain("All findings have severity ratings")
    expect(reportPrompt).toContain("Evidence is included")
    expect(reportPrompt).toContain("No sensitive data is exposed")
  })

  test("REQ-FUN-070: report prompt includes evidence handling guidance", () => {
    expect(reportPrompt).toContain("Evidence Handling")
    expect(reportPrompt).toContain("Sanitize")
    expect(reportPrompt).toContain("placeholders")
  })
})

// =============================================================================
// Feature 17: Failure Escalation Protocol (ARCHIVED — prompt-based approach)
// =============================================================================

describe("Feature 17: Failure Escalation (prompt-level)", () => {

  test("REQ-ESC-001: master prompt tracks failedAttempts in engagement state", () => {
    // Master prompt references failedAttempts for tracking
    expect(masterPrompt).toContain("failedAttempts")
  })

  test("REQ-ESC-002: master prompt triggers escalation after 2+ failures of same technique", () => {
    // The master prompt should reference the 2+ failure threshold
    expect(masterPrompt).toContain("failedAttempts")
    expect(masterPrompt).toContain("2+")
    // Should say to mark it as blocked
    expect(masterPrompt).toContain("blocked")
  })

  test("REQ-ESC-003: master prompt presents escalation options (move to next plan step)", () => {
    // After escalation, the prompt directs agent to move to next attackPlan step
    expect(masterPrompt).toContain("next `attackPlan` step")
  })

  test("REQ-ESC-001: base prompt instructs recording root cause to failedAttempts", () => {
    // Base prompt should instruct agents to record failures
    expect(basePrompt).toContain("failedAttempts")
    expect(basePrompt).toContain("Record the root cause")
  })

  test("REQ-ESC-006: master prompt retry discipline section references engagement state", () => {
    expect(masterPrompt).toContain("Retry Discipline")
    // Should check engagement state before retrying
    expect(masterPrompt).toContain("Check `failedAttempts` in engagement state")
    expect(masterPrompt).toContain("BLOCKED")
  })

  test("REQ-ESC-002: master prompt has anti-pattern for ignoring attackPlan steps", () => {
    // Explicitly calls out ignoring attackPlan as an anti-pattern
    expect(masterPrompt).toContain("Ignoring attackPlan steps")
  })
})

// =============================================================================
// Feature 18: Attack Plan Tracking
// =============================================================================

describe("Feature 18: Attack Plan in Prompts", () => {

  test("REQ-PLN-001: master prompt instructs creating attack plan after research returns", () => {
    expect(masterPrompt).toContain("Attack Plan Creation")
    expect(masterPrompt).toContain("after research returns")
    expect(masterPrompt).toContain("IMMEDIATELY create an attack plan")
  })

  test("REQ-PLN-001: master prompt shows attackPlan structure in update_engagement_state call", () => {
    expect(masterPrompt).toContain("attackPlan")
    expect(masterPrompt).toContain("title:")
    expect(masterPrompt).toContain("source:")
  })

  test("REQ-PLN-003: attack plan step schema includes source field", () => {
    // The AttackStepSchema should support source to track where a step came from
    // Verify by persisting and loading state with source field
    const state: EngagementState = {
      attackPlan: {
        title: "Test plan",
        source: "pentest/research",
        steps: [
          { step: 1, description: "SQLi on login", status: "pending", source: "research" },
          { step: 2, description: "Kernel exploit", status: "pending", source: "enumeration" },
        ],
      },
    }
    // mergeState should preserve source field via .passthrough()
    const result = mergeState({}, state)
    expect(result.attackPlan?.steps![0].source).toBe("research")
    expect(result.attackPlan?.steps![1].source).toBe("enumeration")
  })

  test("REQ-PLN-006: master prompt uses attackPlan in strategic checkpoint", () => {
    // Strategic checkpoint should reference attackPlan
    expect(masterPrompt).toContain("attackPlan")
    expect(masterPrompt).toContain("Check attackPlan")
    expect(masterPrompt).toContain("steps remain")
  })

  test("REQ-PLN-001: exploit subagent prompt includes Attack Plan Compliance section", () => {
    expect(exploitPrompt).toContain("Attack Plan Compliance")
    expect(exploitPrompt).toContain("attackPlan")
    expect(exploitPrompt).toContain("update_engagement_state")
  })

  test("REQ-PLN-001: build subagent prompt includes Attack Plan Compliance section", () => {
    expect(buildPrompt).toContain("Attack Plan Compliance")
    expect(buildPrompt).toContain("attackPlan")
    expect(buildPrompt).toContain("read_engagement_state")
  })

  test("REQ-PLN-004: master prompt supports backup promotion (untried steps prioritized)", () => {
    expect(masterPrompt).toContain("PRIORITIZE untried plan steps")
  })
})

describe("Feature 18: Attack Plan Schema", () => {
  let sessionID: string

  afterEach(() => {
    SessionDirectory.cleanup(sessionID)
  })

  test("REQ-PLN-003: attack step notes field survives round-trip", async () => {
    sessionID = uniqueSessionID("plan-notes")
    const { ctx } = makeContext(sessionID)
    await updateTool.execute({
      target: { ip: "10.10.10.70" },
      attackPlan: {
        title: "Notes test",
        source: "research",
        steps: [
          { step: 1, description: "SQLi", status: "failed", notes: "WAF blocked all payloads" },
          { step: 2, description: "SSTI", status: "in_progress", notes: "Jinja2 detected" },
        ],
      },
    } as any, ctx)

    const state = await loadEngagementState(sessionID)
    expect(state.attackPlan?.steps![0].notes).toBe("WAF blocked all payloads")
    expect(state.attackPlan?.steps![1].notes).toBe("Jinja2 detected")
  })

  test("REQ-PLN-003: attack step status enum supports all required values", async () => {
    sessionID = uniqueSessionID("plan-status")
    const { ctx } = makeContext(sessionID)

    // All valid statuses from the schema: pending, in_progress, completed, failed, skipped
    await updateTool.execute({
      attackPlan: {
        title: "Status enum test",
        source: "test",
        steps: [
          { step: 1, description: "A", status: "pending" },
          { step: 2, description: "B", status: "in_progress" },
          { step: 3, description: "C", status: "completed" },
          { step: 4, description: "D", status: "failed" },
          { step: 5, description: "E", status: "skipped" },
        ],
      },
    } as any, ctx)

    const state = await loadEngagementState(sessionID)
    const statuses = state.attackPlan!.steps!.map(s => s.status)
    expect(statuses).toEqual(["pending", "in_progress", "completed", "failed", "skipped"])
  })
})

// =============================================================================
// Feature 19: Credential & Session Resilience
// =============================================================================

describe("Feature 19: Credential Schema Completeness", () => {

  test("REQ-CRD-001/011: credential schema supports hash field for hash-based auth", () => {
    // Verify hash field persists through mergeState
    const state: EngagementState = {
      credentials: [{
        username: "administrator",
        hash: "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        service: "smb",
      }],
    }
    const result = mergeState({}, state)
    expect(result.credentials![0].hash).toContain("aad3b435b51404ee")
  })

  test("REQ-CRD-008: credential schema supports privileged field", () => {
    const state: EngagementState = {
      credentials: [
        { username: "root", password: "toor", service: "ssh", privileged: true },
        { username: "www-data", password: "web123", service: "ssh", privileged: false },
      ],
    }
    const result = mergeState({}, state)
    expect(result.credentials![0].privileged).toBe(true)
    expect(result.credentials![1].privileged).toBe(false)
  })

  test("REQ-CRD-001: credential schema supports source field for discovery method", () => {
    const state: EngagementState = {
      credentials: [
        { username: "admin", password: "admin123", service: "http", source: "bruteforce" },
        { username: "dbuser", password: "dbpass", service: "mysql", source: "extraction" },
      ],
    }
    const result = mergeState({}, state)
    expect(result.credentials![0].source).toBe("bruteforce")
    expect(result.credentials![1].source).toBe("extraction")
  })

  test("REQ-CRD-002/003: credential schema accepts lastUsed and validatedAt via passthrough", async () => {
    // The schema uses .passthrough() so LLM-provided fields like lastUsed/validatedAt
    // persist even though they aren't in the strict schema definition
    const sessionID = uniqueSessionID("cred-passthrough")
    const { ctx } = makeContext(sessionID)

    await updateTool.execute({
      credentials: [{
        username: "admin",
        password: "secret",
        service: "ssh",
        validated: true,
        authMethod: "password",
        lastUsed: "2026-04-06T10:00:00Z",
        validatedAt: "2026-04-06T09:55:00Z",
        lastUsedSuccess: true,
        port: 22,
      }],
    }, ctx)

    const state = await loadEngagementState(sessionID)
    const cred = state.credentials![0] as any
    expect(cred.username).toBe("admin")
    expect(cred.validated).toBe(true)
    // passthrough fields
    expect(cred.authMethod).toBe("password")
    expect(cred.lastUsed).toBe("2026-04-06T10:00:00Z")
    expect(cred.validatedAt).toBe("2026-04-06T09:55:00Z")
    expect(cred.lastUsedSuccess).toBe(true)
    expect(cred.port).toBe(22)

    SessionDirectory.cleanup(sessionID)
  })

  test("REQ-CRD-006: multiple credentials for same user on different services coexist", () => {
    const existing: EngagementState = {
      credentials: [
        { username: "admin", password: "pass1", service: "ssh" },
      ],
    }
    const updates: Partial<EngagementState> = {
      credentials: [
        { username: "admin", password: "pass2", service: "http" },
        { username: "admin", password: "pass3", service: "mysql" },
      ],
    }
    const result = mergeState(existing, updates)
    // Dedup key is username+service, so all 3 should exist
    expect(result.credentials).toHaveLength(3)
    const services = result.credentials!.map(c => c.service)
    expect(services).toContain("ssh")
    expect(services).toContain("http")
    expect(services).toContain("mysql")
  })

  test("REQ-CRD-001: credential update merges new fields onto existing entry", () => {
    const existing: EngagementState = {
      credentials: [
        { username: "admin", password: "secret", service: "ssh" },
      ],
    }
    const updates: Partial<EngagementState> = {
      credentials: [
        { username: "admin", service: "ssh", validated: true, privileged: true },
      ],
    }
    const result = mergeState(existing, updates)
    expect(result.credentials).toHaveLength(1)
    expect(result.credentials![0].password).toBe("secret") // original preserved
    expect(result.credentials![0].validated).toBe(true)     // new field merged
    expect(result.credentials![0].privileged).toBe(true)    // new field merged
  })
})

// =============================================================================
// Feature 20: pentest/build Subagent
// =============================================================================

describe("Feature 20: pentest/build Subagent", () => {

  test("REQ-BLD-001: build prompt instructs searching for existing exploits before building", () => {
    // Priority 1: Find Existing Exploit
    expect(buildPrompt).toContain("Find Existing Exploit")
    expect(buildPrompt).toContain("Search before building")
    expect(buildPrompt).toContain("searchsploit")
    // Anti-pattern: building what already exists
    expect(buildPrompt).toContain("Building what already exists")
  })

  test("REQ-BLD-002: build prompt mandates testing before returning", () => {
    expect(buildPrompt).toContain("Testing Standards")
    expect(buildPrompt).toContain("Test before returning")
    expect(buildPrompt).toContain("do not return untested code")
    // Testing table with artifact types
    expect(buildPrompt).toContain("Python/Ruby script")
    expect(buildPrompt).toContain("Compiled binary")
    expect(buildPrompt).toContain("Web exploit")
  })

  test("REQ-BLD-003: build prompt instructs returning artifacts with usage instructions", () => {
    expect(buildPrompt).toContain("Usage")
    expect(buildPrompt).toContain("usage instructions")
    // Output format section
    expect(buildPrompt).toContain("Exploit/Payload Ready")
    expect(buildPrompt).toContain("### Artifact")
    expect(buildPrompt).toContain("### Testing Performed")
    expect(buildPrompt).toContain("### Usage")
  })

  test("REQ-BLD-004: build agent uses shared pentestPermission (not custom)", () => {
    const buildAgent = agents["pentest/build"]
    // Should have security tool bash denials like other pentest agents
    expect(buildAgent.permission?.bash?.["nmap*"]).toBe("deny")
    expect(buildAgent.permission?.bash?.["sqlmap*"]).toBe("deny")
    // Should allow general bash (for gcc, python, make, etc.)
    expect(buildAgent.permission?.bash?.["*"]).toBe("allow")
    // Should NOT be like report agent (which denies all bash)
    expect(buildAgent.permission?.bash).not.toEqual({ "*": "deny" })
  })

  test("REQ-BLD-005: build prompt instructs writing artifacts to session directory", () => {
    expect(buildPrompt).toContain("{sessionDir}/artifacts/")
    expect(buildPrompt).toContain("Write artifacts to")
  })

  test("REQ-BLD-006: master prompt delegates to pentest/build", () => {
    expect(masterPrompt).toContain("pentest/build")
  })

  test("REQ-BLD-001: build prompt has priority-ordered workflow (0: Research, 1: Find, 2: Adapt, 3: Build)", () => {
    // Priority 0 comes before Priority 1 in the text
    const researchIdx = buildPrompt.indexOf("Priority 0: Research Before Building")
    const findIdx = buildPrompt.indexOf("Priority 1: Find Existing Exploit")
    const adaptIdx = buildPrompt.indexOf("Priority 2: Adapt Existing Exploit")
    const buildIdx = buildPrompt.indexOf("Priority 3: Build from Scratch")

    expect(researchIdx).toBeGreaterThan(-1)
    expect(findIdx).toBeGreaterThan(-1)
    expect(adaptIdx).toBeGreaterThan(-1)
    expect(buildIdx).toBeGreaterThan(-1)
    expect(researchIdx).toBeLessThan(findIdx)
    expect(findIdx).toBeLessThan(adaptIdx)
    expect(adaptIdx).toBeLessThan(buildIdx)
  })

  test("REQ-BLD-002: build prompt has TVAR reasoning requirement", () => {
    expect(buildPrompt).toContain("TVAR Reasoning (REQUIRED)")
    expect(buildPrompt).toContain("<thought>")
    expect(buildPrompt).toContain("<verify>")
    expect(buildPrompt).toContain("<action>")
    expect(buildPrompt).toContain("<result>")
  })

  test("REQ-BLD-003: build prompt includes handoff instructions", () => {
    expect(buildPrompt).toContain("Handoff")
    expect(buildPrompt).toContain("Return tested artifact to caller")
    expect(buildPrompt).toContain("what requires target testing")
  })

  test("REQ-BLD-005: build prompt includes dynamic recipe creation workflow", () => {
    // Feature 28 integration — build agent can create tool recipes
    expect(buildPrompt).toContain("tool_recipes")
    expect(buildPrompt).toContain("recipe")
    expect(buildPrompt).toContain("MCP server hot-reloads")
  })
})

// =============================================================================
// Gap Analysis
// =============================================================================

/**
 * FEATURE 12 — GAP ANALYSIS
 *
 * | REQ ID      | Covered Before?  | Covered Here? | Notes                                    |
 * |-------------|------------------|---------------|------------------------------------------|
 * | REQ-FUN-070 | Partial (F02)    | Yes           | Report prompt templates, data sources     |
 * | REQ-FUN-071 | No               | Yes           | Severity rating system with CVSS ranges   |
 * | REQ-FUN-072 | No               | Yes           | Evidence/remediation/description templates |
 * | REQ-FUN-073 | No               | No            | Deferred (Phase 2 — HTML/PDF formats)     |
 * | REQ-FUN-074 | No               | No            | Deferred (Phase 3 — professional)         |
 * | REQ-FUN-075 | No               | No            | Deferred (Phase 3 — compliance)           |
 *
 * FEATURE 17 — GAP ANALYSIS (ARCHIVED — concepts in prompts)
 *
 * | REQ ID      | Covered Before?  | Covered Here? | Notes                                    |
 * |-------------|------------------|---------------|------------------------------------------|
 * | REQ-ESC-001 | F03 (schema)     | Yes (prompt)  | failedAttempts in state + prompt ref      |
 * | REQ-ESC-002 | No               | Yes           | 2+ failure threshold in master prompt     |
 * | REQ-ESC-003 | No               | Yes           | Escalation options (next plan step)       |
 * | REQ-ESC-004 | No               | No            | Silent failure detection — LLM runtime    |
 * | REQ-ESC-005 | No               | No            | Environment error detection — LLM runtime |
 * | REQ-ESC-006 | No               | Yes           | Retry discipline references state         |
 * | REQ-ESC-007 | No               | No            | First failure exemption — LLM runtime     |
 *
 * FEATURE 18 — GAP ANALYSIS
 *
 * | REQ ID      | Covered Before?  | Covered Here? | Notes                                    |
 * |-------------|------------------|---------------|------------------------------------------|
 * | REQ-PLN-001 | F03 (schema)     | Yes (prompt)  | Master prompt + subagent compliance       |
 * | REQ-PLN-002 | No               | No            | Primary/backup — Doc 18 uses flat steps   |
 * | REQ-PLN-003 | F03 (persistence)| Yes           | Step notes, source, status enum           |
 * | REQ-PLN-004 | No               | Yes           | Untried steps prioritized in prompt       |
 * | REQ-PLN-005 | No               | No            | Auto-populate from research — LLM runtime |
 * | REQ-PLN-006 | No               | Yes           | Strategic checkpoint references plan       |
 * | REQ-PLN-007 | No               | Yes           | Source field in step schema               |
 *
 * Note: REQ-PLN-002 (primary/backup approaches per phase) is from the
 * original doc spec. The implementation uses a simpler flat-steps model
 * rather than hierarchical phases with primary/backup. This is a known
 * deviation — the flat model works well enough for HTB and the
 * hierarchical model is deferred.
 *
 * FEATURE 19 — GAP ANALYSIS
 *
 * | REQ ID      | Covered Before?  | Covered Here? | Notes                                    |
 * |-------------|------------------|---------------|------------------------------------------|
 * | REQ-CRD-001 | No               | Yes           | authMethod via passthrough, source field  |
 * | REQ-CRD-002 | No               | Yes           | lastUsed via passthrough                  |
 * | REQ-CRD-003 | No               | Yes           | validatedAt via passthrough               |
 * | REQ-CRD-004 | No               | No            | Staleness detection — LLM runtime         |
 * | REQ-CRD-005 | No               | No            | Pre-critical-op validation — LLM runtime  |
 * | REQ-CRD-006 | F03 (dedup)      | Yes           | Multiple services per user                |
 * | REQ-CRD-007 | No               | No            | Session lastVerified — LLM runtime        |
 * | REQ-CRD-008 | No               | Yes           | privileged field in schema                |
 * | REQ-CRD-009 | No               | Yes           | port via passthrough                      |
 * | REQ-CRD-010 | No               | Yes           | lastUsedSuccess via passthrough           |
 * | REQ-CRD-011 | No               | Yes           | hash field in schema                      |
 *
 * Note: Feature 19 specifies strict typed fields (authMethod enum, etc.)
 * but the implementation uses .passthrough() for LLM flexibility.
 * This means the LLM CAN provide these fields and they WILL persist,
 * but there's no schema validation enforcing them. This is by design —
 * the engagement state schema is intentionally permissive.
 *
 * FEATURE 20 — GAP ANALYSIS
 *
 * | REQ ID      | Covered Before?  | Covered Here? | Notes                                    |
 * |-------------|------------------|---------------|------------------------------------------|
 * | REQ-BLD-001 | No               | Yes           | Search-first workflow, anti-patterns      |
 * | REQ-BLD-002 | No               | Yes           | Testing standards, artifact types         |
 * | REQ-BLD-003 | No               | Yes           | Output format with usage instructions     |
 * | REQ-BLD-004 | F02 (exists)     | Yes           | Correct permissions (pentestPermission)   |
 * | REQ-BLD-005 | No               | Yes           | Artifacts to sessionDir + recipe workflow |
 * | REQ-BLD-006 | F02 (delegation) | Yes           | Master prompt references pentest/build    |
 */
