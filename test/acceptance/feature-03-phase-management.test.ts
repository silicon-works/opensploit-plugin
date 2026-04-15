/**
 * Feature 03: Phase Management — Acceptance Tests
 *
 * Each test maps to a specific REQ-* from:
 *   opensploit-vault/requirements/03-phase-management.md
 *
 * Covers gaps not addressed by existing unit tests in:
 *   - test/util/phase-gating.test.ts
 *   - test/tools/engagement-state.test.ts
 *   - test/hooks/system-transform.test.ts
 *
 * Gap analysis (bottom of file) documents which REQs are covered here vs elsewhere.
 */

import { describe, expect, test, afterEach, beforeEach } from "bun:test"
import { readFileSync, existsSync, writeFileSync } from "fs"
import yaml from "js-yaml"
import type { ToolContext } from "@opencode-ai/plugin"

import {
  createUpdateEngagementStateTool,
  createReadEngagementStateTool,
  loadEngagementState,
  saveEngagementState,
  mergeState,
  getEngagementStateForInjection,
  getStateSnapshots,
  getStateAtStep,
  detectStateChanges,
  type EngagementState,
} from "../../src/tools/engagement-state"

import * as SessionDirectory from "../../src/session/directory"
import { registerRootSession, unregister, getRootSession } from "../../src/session/hierarchy"
import { PhaseGating } from "../../src/util/phase-gating"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const updateTool = createUpdateEngagementStateTool()
const readTool = createReadEngagementStateTool()

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

/** Unique session ID per test to avoid collisions */
let testCounter = 0
function uniqueSessionID(prefix = "feat03"): string {
  return `${prefix}-${Date.now()}-${++testCounter}`
}

// =============================================================================
// 1. Engagement State Schema — All Required Fields (REQ-FUN-001..005 state fields)
// =============================================================================

describe("Feature 03: Engagement State Schema", () => {
  const sessionID = uniqueSessionID("schema")

  afterEach(() => {
    SessionDirectory.cleanup(sessionID)
  })

  test("REQ-FUN-001..005: EngagementState schema supports every field from the requirements doc", async () => {
    // The doc (§State Schema) mandates: target, ports, credentials, vulnerabilities,
    // sessions, accessLevel, files, flags, failedAttempts.
    // Implementation adds: toolFailures, attackPlan, toolSearchCache.
    const fullState: EngagementState = {
      target: { ip: "10.10.10.1", hostname: "target.htb" },
      ports: [
        { port: 22, protocol: "tcp", service: "ssh", version: "OpenSSH 8.2p1", state: "open" },
        { port: 80, protocol: "tcp", service: "http", version: "Apache 2.4.41", state: "open" },
      ],
      credentials: [
        { username: "admin", password: "admin123", service: "http", validated: true },
      ],
      vulnerabilities: [
        { name: "SQL Injection", severity: "high", service: "http", port: 80, exploitable: true },
      ],
      sessions: [
        { id: "shell-1", type: "reverse", user: "www-data", privileged: false },
      ],
      files: [
        { path: "/etc/passwd", type: "credential", content: "root:x:0:0:...", notes: "user list" },
      ],
      failedAttempts: [
        { action: "SSH brute force as root", tool: "hydra", reason: "No valid password found", timestamp: "2026-01-15T10:30:00Z" },
      ],
      accessLevel: "user",
      flags: ["HTB{test_flag}"],
      attackPlan: {
        title: "SQLi to shell to root",
        source: "pentest/research",
        steps: [
          { step: 1, description: "Exploit SQLi", status: "completed" },
          { step: 2, description: "Escalate privileges", status: "pending" },
        ],
      },
      toolFailures: [
        { tool: "sqlmap", method: "test_injection", error: "timeout", count: 3, firstSeen: "2026-01-01", lastSeen: "2026-01-02" },
      ],
    }

    // Persist and reload — all fields must survive the round trip
    SessionDirectory.create(sessionID)
    await saveEngagementState(sessionID, fullState)
    const loaded = await loadEngagementState(sessionID)

    expect(loaded.target?.ip).toBe("10.10.10.1")
    expect(loaded.target?.hostname).toBe("target.htb")
    expect(loaded.ports).toHaveLength(2)
    expect(loaded.credentials).toHaveLength(1)
    expect(loaded.vulnerabilities).toHaveLength(1)
    expect(loaded.sessions).toHaveLength(1)
    expect(loaded.files).toHaveLength(1)
    expect(loaded.failedAttempts).toHaveLength(1)
    expect(loaded.accessLevel).toBe("user")
    expect(loaded.flags).toEqual(["HTB{test_flag}"])
    expect(loaded.attackPlan?.title).toBe("SQLi to shell to root")
    expect(loaded.attackPlan?.steps).toHaveLength(2)
    expect(loaded.toolFailures).toHaveLength(1)
  })
})

// =============================================================================
// 2. Merge Semantics — Gaps not covered by engagement-state.test.ts
// =============================================================================

describe("Feature 03: Merge Semantics (gap coverage)", () => {
  test("REQ state.yaml §mergeState: files array appends without deduplication", () => {
    const existing: EngagementState = {
      files: [{ path: "/etc/passwd", type: "credential" }],
    }
    const updates: Partial<EngagementState> = {
      files: [
        { path: "/etc/passwd", type: "credential" }, // duplicate — files are append-only per impl
        { path: "/etc/shadow", type: "credential" },
      ],
    }
    const result = mergeState(existing, updates)

    // files uses append (no dedup key), so duplicate appears
    expect(result.files).toHaveLength(3)
    expect(result.files?.filter(f => f.path === "/etc/passwd")).toHaveLength(2)
  })

  test("REQ state.yaml §mergeState: toolFailures dedup by tool+method with count increment", () => {
    const existing: EngagementState = {
      toolFailures: [
        { tool: "sqlmap", method: "test_injection", error: "timeout", count: 1, firstSeen: "2026-01-01", lastSeen: "2026-01-01" },
      ],
    }
    const updates: Partial<EngagementState> = {
      toolFailures: [
        { tool: "sqlmap", method: "test_injection", error: "connection refused", count: 1, firstSeen: "2026-01-02", lastSeen: "2026-01-02" },
      ],
    }
    const result = mergeState(existing, updates)

    // Should dedup by tool+method; count should increment
    expect(result.toolFailures).toHaveLength(1)
    expect(result.toolFailures![0].count).toBe(2)
    expect(result.toolFailures![0].error).toBe("connection refused") // latest error wins
  })

  test("REQ state.yaml §mergeState: toolFailures different methods are separate entries", () => {
    const existing: EngagementState = {
      toolFailures: [
        { tool: "sqlmap", method: "test_injection", error: "timeout", count: 1, firstSeen: "2026-01-01", lastSeen: "2026-01-01" },
      ],
    }
    const updates: Partial<EngagementState> = {
      toolFailures: [
        { tool: "sqlmap", method: "dump_table", error: "no injection point", count: 1, firstSeen: "2026-01-02", lastSeen: "2026-01-02" },
      ],
    }
    const result = mergeState(existing, updates)

    expect(result.toolFailures).toHaveLength(2)
  })

  test("REQ state.yaml §mergeState: attackPlan uses replace semantics, not merge", () => {
    const existing: EngagementState = {
      attackPlan: {
        title: "Plan A",
        source: "research",
        steps: [
          { step: 1, description: "Do X", status: "completed" },
          { step: 2, description: "Do Y", status: "pending" },
        ],
      },
    }
    const updates: Partial<EngagementState> = {
      attackPlan: {
        title: "Plan B (revised)",
        source: "exploit-agent",
        steps: [
          { step: 1, description: "Do Z instead", status: "in_progress" },
        ],
      },
    }
    const result = mergeState(existing, updates)

    // Replace, not merge: old steps are gone
    expect(result.attackPlan?.title).toBe("Plan B (revised)")
    expect(result.attackPlan?.steps).toHaveLength(1)
    expect(result.attackPlan?.steps![0].description).toBe("Do Z instead")
  })

  test("REQ state.yaml §mergeState: ports dedup key is port+protocol, not port alone", () => {
    const existing: EngagementState = {
      ports: [
        { port: 53, protocol: "tcp", service: "dns" },
      ],
    }
    const updates: Partial<EngagementState> = {
      ports: [
        { port: 53, protocol: "udp", service: "dns" }, // same port, different protocol
      ],
    }
    const result = mergeState(existing, updates)

    // Both should exist — port 53/tcp and 53/udp are distinct
    expect(result.ports).toHaveLength(2)
    expect(result.ports?.find(p => p.protocol === "tcp")).toBeDefined()
    expect(result.ports?.find(p => p.protocol === "udp")).toBeDefined()
  })

  test("REQ state.yaml §mergeState: credentials dedup key is username+service", () => {
    const existing: EngagementState = {
      credentials: [
        { username: "admin", service: "http", password: "old_pass" },
      ],
    }
    const updates: Partial<EngagementState> = {
      credentials: [
        { username: "admin", service: "ssh", password: "different_pass" }, // same user, different service
      ],
    }
    const result = mergeState(existing, updates)

    // Both should exist — admin@http and admin@ssh are distinct
    expect(result.credentials).toHaveLength(2)
  })
})

// =============================================================================
// 3. Failed Attempts Tracking (Doc §failedAttempts)
// =============================================================================

describe("Feature 03: Failed Attempts Tracking", () => {
  let sessionID: string

  beforeEach(() => {
    sessionID = uniqueSessionID("failed")
  })

  afterEach(() => {
    SessionDirectory.cleanup(sessionID)
  })

  test("REQ state.yaml §failedAttempts: multiple failed attempts accumulate", async () => {
    const { ctx: ctx1 } = makeContext(sessionID)
    await updateTool.execute({
      failedAttempts: [
        { action: "SSH brute force as root", tool: "hydra", reason: "No valid password found", timestamp: "2026-01-15T10:30:00Z" },
      ],
    }, ctx1)

    const { ctx: ctx2 } = makeContext(sessionID)
    await updateTool.execute({
      failedAttempts: [
        { action: "LFI via /page?file=", tool: "curl", reason: "Input sanitized", timestamp: "2026-01-15T10:45:00Z" },
      ],
    }, ctx2)

    const state = await loadEngagementState(sessionID)
    expect(state.failedAttempts).toHaveLength(2)
    expect(state.failedAttempts![0].action).toBe("SSH brute force as root")
    expect(state.failedAttempts![1].action).toBe("LFI via /page?file=")
  })

  test("REQ state.yaml §failedAttempts: failed attempts survive YAML round-trip", async () => {
    const { ctx } = makeContext(sessionID)
    await updateTool.execute({
      failedAttempts: [
        { action: "SQL injection on /login", tool: "sqlmap", reason: "WAF blocked all payloads", timestamp: "2026-01-15T11:00:00Z" },
      ],
    }, ctx)

    // Read raw YAML from disk
    const statePath = SessionDirectory.statePath(sessionID)
    const raw = readFileSync(statePath, "utf-8")
    const onDisk = yaml.load(raw) as EngagementState

    expect(onDisk.failedAttempts).toHaveLength(1)
    expect(onDisk.failedAttempts![0].action).toBe("SQL injection on /login")
    expect(onDisk.failedAttempts![0].tool).toBe("sqlmap")
    expect(onDisk.failedAttempts![0].reason).toBe("WAF blocked all payloads")
  })

  test("REQ state.yaml §failedAttempts: injected context includes failedAttempts for subagent visibility", async () => {
    SessionDirectory.create(sessionID)
    await saveEngagementState(sessionID, {
      target: { ip: "10.10.10.1" },
      failedAttempts: [
        { action: "SSH brute force as root", tool: "hydra", reason: "No valid password" },
        { action: "LFI via /page?file=", tool: "curl", reason: "Input sanitized" },
      ],
    })

    const injection = await getEngagementStateForInjection(sessionID)
    expect(injection).not.toBeNull()
    expect(injection).toContain("SSH brute force as root")
    expect(injection).toContain("LFI via /page?file=")
    expect(injection).toContain("avoid repeating failed attempts")
  })
})

// =============================================================================
// 4. State Persistence and YAML Round-Trip
// =============================================================================

describe("Feature 03: State Persistence", () => {
  let sessionID: string

  beforeEach(() => {
    sessionID = uniqueSessionID("persist")
  })

  afterEach(() => {
    SessionDirectory.cleanup(sessionID)
  })

  test("REQ state.yaml: state persists to {sessionDir}/state.yaml and reads back identically", async () => {
    const original: EngagementState = {
      target: { ip: "10.10.10.99", hostname: "persist.htb" },
      ports: [
        { port: 22, protocol: "tcp", service: "ssh", version: "OpenSSH 8.9", state: "open" },
        { port: 80, protocol: "tcp", service: "http", version: "nginx 1.18", state: "open" },
        { port: 445, protocol: "tcp", service: "smb", state: "filtered" },
      ],
      credentials: [
        { username: "admin", password: "Welcome1!", service: "http", validated: true },
        { username: "root", key: "-----BEGIN RSA KEY-----...", service: "ssh" },
      ],
      vulnerabilities: [
        { name: "CVE-2021-3156", severity: "critical", cve: "CVE-2021-3156", exploitable: true },
      ],
      accessLevel: "user",
      flags: ["HTB{first_flag}", "HTB{second_flag}"],
      failedAttempts: [
        { action: "RCE via log4j", tool: "curl", reason: "Not vulnerable" },
      ],
    }

    SessionDirectory.create(sessionID)
    await saveEngagementState(sessionID, original)
    const loaded = await loadEngagementState(sessionID)

    // Verify every field survives round-trip
    expect(loaded.target?.ip).toBe(original.target!.ip)
    expect(loaded.target?.hostname).toBe(original.target!.hostname)
    expect(loaded.ports).toHaveLength(3)
    expect(loaded.ports![2].state).toBe("filtered")
    expect(loaded.credentials).toHaveLength(2)
    expect(loaded.credentials![1].key).toContain("BEGIN RSA KEY")
    expect(loaded.vulnerabilities).toHaveLength(1)
    expect(loaded.vulnerabilities![0].cve).toBe("CVE-2021-3156")
    expect(loaded.accessLevel).toBe("user")
    expect(loaded.flags).toEqual(["HTB{first_flag}", "HTB{second_flag}"])
    expect(loaded.failedAttempts).toHaveLength(1)
  })

  test("REQ state.yaml: state.yaml is written to the correct session directory path", async () => {
    const { ctx } = makeContext(sessionID)
    await updateTool.execute({
      target: { ip: "10.10.10.77" },
    }, ctx)

    const expectedPath = SessionDirectory.statePath(sessionID)
    expect(existsSync(expectedPath)).toBe(true)

    // Verify it's in the right temp directory
    expect(expectedPath).toContain("opensploit-session-")
    expect(expectedPath).toContain(sessionID)
    expect(expectedPath).toEndWith("state.yaml")
  })
})

// =============================================================================
// 5. Phase Gating Warns About Skipped Phases
// =============================================================================

describe("Feature 03: Phase Gating Warnings", () => {
  let sessionID: string

  beforeEach(() => {
    sessionID = uniqueSessionID("gate")
    PhaseGating.clearSession(sessionID)
  })

  test("REQ-FUN-006: phase gating warns when jumping to exploitation without recon+enum", () => {
    const result = PhaseGating.checkToolInvocation(sessionID, "sqlmap")
    expect(result.warning).toBeDefined()
    expect(result.warning).toContain("PHASE WARNING")
    expect(result.warning).toContain("reconnaissance")
    expect(result.warning).toContain("enumeration")
    expect(result.phase).toBe("exploitation")
  })

  test("REQ-FUN-006: no warning when phases are completed in order", () => {
    // Do recon
    const r1 = PhaseGating.checkToolInvocation(sessionID, "nmap")
    expect(r1.warning).toBeUndefined()

    // Do enum
    const r2 = PhaseGating.checkToolInvocation(sessionID, "ffuf")
    expect(r2.warning).toBeUndefined()

    // Do exploit
    const r3 = PhaseGating.checkToolInvocation(sessionID, "sqlmap")
    expect(r3.warning).toBeUndefined()

    // Do post-exploit
    const r4 = PhaseGating.checkToolInvocation(sessionID, "privesc")
    expect(r4.warning).toBeUndefined()
  })

  test("REQ-FUN-006: cyclical workflow — returning to earlier phase after later ones is allowed", () => {
    // Complete recon, enum, exploit
    PhaseGating.recordPhase(sessionID, "reconnaissance")
    PhaseGating.recordPhase(sessionID, "enumeration")
    PhaseGating.recordPhase(sessionID, "exploitation")

    // Return to recon (cyclical) — no warning because recon has no prerequisites
    const result = PhaseGating.checkToolInvocation(sessionID, "nmap")
    expect(result.warning).toBeUndefined()
  })

  test("REQ-FUN-006: warnings are advisory only (not blocking)", () => {
    // The doc explicitly says: "no hardcoded enforcement, no automatic transitions, and no phase gating"
    // Phase gating only WARNS — checkToolInvocation always returns the phase, never blocks
    const result = PhaseGating.checkToolInvocation(sessionID, "hydra")
    expect(result.warning).toBeDefined() // warning present
    expect(result.phase).toBe("exploitation") // but phase is still returned — not blocked
  })
})

// =============================================================================
// 6. State Shared Across Parent/Child Sessions via Root Session
// =============================================================================

describe("Feature 03: State Sharing via Root Session", () => {
  const rootID = uniqueSessionID("root")
  const childA = uniqueSessionID("childA")
  const childB = uniqueSessionID("childB")

  afterEach(() => {
    SessionDirectory.cleanup(rootID)
    unregister(childA)
    unregister(childB)
    unregister(rootID)
  })

  test("REQ context-injection: child sessions read and write to root session state", async () => {
    registerRootSession(childA, rootID)
    registerRootSession(childB, rootID)

    // Verify hierarchy resolution
    expect(getRootSession(childA)).toBe(rootID)
    expect(getRootSession(childB)).toBe(rootID)
    expect(getRootSession(rootID)).toBe(rootID) // root resolves to self

    // Child A: recon agent writes ports
    const { ctx: ctxA } = makeContext(childA)
    await updateTool.execute({
      target: { ip: "10.10.10.200" },
      ports: [
        { port: 22, protocol: "tcp", service: "ssh" },
        { port: 80, protocol: "tcp", service: "http" },
      ],
    }, ctxA)

    // Child B: enum agent writes credentials and vulnerabilities
    const { ctx: ctxB } = makeContext(childB)
    await updateTool.execute({
      credentials: [
        { username: "admin", password: "P@ssw0rd", service: "http", validated: true },
      ],
      vulnerabilities: [
        { name: "SQLi in /login", severity: "high", service: "http", port: 80, exploitable: true },
      ],
    }, ctxB)

    // Read from root session — should see everything
    const state = await loadEngagementState(rootID)
    expect(state.target?.ip).toBe("10.10.10.200")
    expect(state.ports).toHaveLength(2)
    expect(state.credentials).toHaveLength(1)
    expect(state.vulnerabilities).toHaveLength(1)

    // Read via the read tool from childA — should see childB's writes
    const { ctx: readCtx } = makeContext(childA)
    const output = await readTool.execute({}, readCtx)
    expect(output).toContain("admin")
    expect(output).toContain("SQLi in /login")
  })

  test("REQ context-injection: state injection includes data from all children", async () => {
    registerRootSession(childA, rootID)

    // Write state via childA
    const { ctx: ctxA } = makeContext(childA)
    await updateTool.execute({
      target: { ip: "10.10.10.201" },
      ports: [{ port: 443, protocol: "tcp", service: "https" }],
      failedAttempts: [
        { action: "Directory brute force on /api", tool: "ffuf", reason: "All 404s" },
      ],
    }, ctxA)

    // Get injection text for root session — used when spawning new subagents
    const injection = await getEngagementStateForInjection(rootID)
    expect(injection).not.toBeNull()
    expect(injection).toContain("10.10.10.201")
    expect(injection).toContain("443")
    expect(injection).toContain("Directory brute force on /api")
  })
})

// =============================================================================
// 7. Access Level Tracking (none → user → root)
// =============================================================================

describe("Feature 03: Access Level Tracking", () => {
  let sessionID: string

  beforeEach(() => {
    sessionID = uniqueSessionID("access")
  })

  afterEach(() => {
    SessionDirectory.cleanup(sessionID)
  })

  test("REQ state.yaml §accessLevel: progression from none → user → root", async () => {
    // Initial: no access
    const { ctx: ctx1 } = makeContext(sessionID)
    await updateTool.execute({
      target: { ip: "10.10.10.50" },
      accessLevel: "none",
    }, ctx1)

    let state = await loadEngagementState(sessionID)
    expect(state.accessLevel).toBe("none")

    // Gain user access
    const { ctx: ctx2 } = makeContext(sessionID)
    await updateTool.execute({
      accessLevel: "user",
      sessions: [{ id: "shell-1", type: "reverse", user: "www-data", privileged: false }],
    }, ctx2)

    state = await loadEngagementState(sessionID)
    expect(state.accessLevel).toBe("user")
    expect(state.sessions).toHaveLength(1)

    // Escalate to root
    const { ctx: ctx3 } = makeContext(sessionID)
    await updateTool.execute({
      accessLevel: "root",
      sessions: [{ id: "shell-2", type: "ssh", user: "root", privileged: true }],
    }, ctx3)

    state = await loadEngagementState(sessionID)
    expect(state.accessLevel).toBe("root")
    expect(state.sessions).toHaveLength(2)
  })

  test("REQ state.yaml §accessLevel: access level appears in tool output", async () => {
    const { ctx } = makeContext(sessionID)
    const output = await updateTool.execute({ accessLevel: "user" }, ctx)
    expect(output).toContain("Access Level: user")
  })

  test("REQ state.yaml §accessLevel: access level appears in context injection", async () => {
    SessionDirectory.create(sessionID)
    await saveEngagementState(sessionID, {
      target: { ip: "10.10.10.50" },
      accessLevel: "root",
    })

    const injection = await getEngagementStateForInjection(sessionID)
    expect(injection).toContain("root")
  })
})

// =============================================================================
// 8. Attack Plan Tracking with Step Status
// =============================================================================

describe("Feature 03: Attack Plan Tracking", () => {
  let sessionID: string

  beforeEach(() => {
    sessionID = uniqueSessionID("plan")
  })

  afterEach(() => {
    SessionDirectory.cleanup(sessionID)
  })

  test("REQ attackPlan: plan persists with all step statuses", async () => {
    const { ctx } = makeContext(sessionID)
    await updateTool.execute({
      target: { ip: "10.10.10.60" },
      attackPlan: {
        title: "Web app to root",
        source: "pentest/research",
        steps: [
          { step: 1, description: "Discover SQLi", status: "completed" },
          { step: 2, description: "Extract credentials from DB", status: "in_progress" },
          { step: 3, description: "SSH with extracted creds", status: "pending" },
          { step: 4, description: "Kernel exploit for root", status: "failed", notes: "Kernel patched" },
          { step: 5, description: "Try SUID binary", status: "skipped" },
        ],
      },
    } as any, ctx)

    const state = await loadEngagementState(sessionID)
    expect(state.attackPlan?.steps).toHaveLength(5)

    const statuses = state.attackPlan!.steps!.map(s => s.status)
    expect(statuses).toEqual(["completed", "in_progress", "pending", "failed", "skipped"])
  })

  test("REQ attackPlan: plan visible in context injection with status markers", async () => {
    SessionDirectory.create(sessionID)
    await saveEngagementState(sessionID, {
      target: { ip: "10.10.10.60" },
      attackPlan: {
        title: "SQL injection → shell → root",
        source: "pentest/research",
        steps: [
          { step: 1, description: "Find SQLi in login form", status: "completed" },
          { step: 2, description: "Extract DB credentials", status: "in_progress" },
          { step: 3, description: "SSH with extracted creds", status: "pending" },
        ],
      },
    })

    const injection = await getEngagementStateForInjection(sessionID)
    expect(injection).toContain("Attack Plan")
    expect(injection).toContain("SQL injection")
    expect(injection).toContain("[x]")  // completed
    expect(injection).toContain("[>]")  // in_progress
    expect(injection).toContain("[ ]")  // pending
  })

  test("REQ attackPlan: replacing plan overwrites old steps entirely", async () => {
    const { ctx: ctx1 } = makeContext(sessionID)
    await updateTool.execute({
      target: { ip: "10.10.10.60" },
      attackPlan: {
        title: "Plan A",
        source: "research",
        steps: [
          { step: 1, description: "Old step 1", status: "failed" },
          { step: 2, description: "Old step 2", status: "pending" },
        ],
      },
    } as any, ctx1)

    // Replace with new plan
    const { ctx: ctx2 } = makeContext(sessionID)
    await updateTool.execute({
      attackPlan: {
        title: "Plan B (new approach)",
        source: "exploit-agent",
        steps: [
          { step: 1, description: "New step 1", status: "in_progress" },
        ],
      },
    } as any, ctx2)

    const state = await loadEngagementState(sessionID)
    expect(state.attackPlan?.title).toBe("Plan B (new approach)")
    expect(state.attackPlan?.steps).toHaveLength(1)
    expect(state.attackPlan?.steps![0].description).toBe("New step 1")
  })
})

// =============================================================================
// 9. Session Directory Structure
// =============================================================================

describe("Feature 03: Session Directory Structure", () => {
  let sessionID: string

  beforeEach(() => {
    sessionID = uniqueSessionID("dir")
  })

  afterEach(() => {
    SessionDirectory.cleanup(sessionID)
  })

  test("REQ-AGT-016: session directory created at /tmp/opensploit-session-{id}/ with standard subdirs", () => {
    const dir = SessionDirectory.create(sessionID)

    expect(dir).toContain("opensploit-session-")
    expect(existsSync(dir)).toBe(true)
    expect(existsSync(SessionDirectory.findingsDir(sessionID))).toBe(true)
    expect(existsSync(SessionDirectory.artifactsDir(sessionID))).toBe(true)
    expect(existsSync(SessionDirectory.wordlistsDir(sessionID))).toBe(true)
  })

  test("REQ findings/*.md: writeFinding/readFinding round-trip", () => {
    SessionDirectory.create(sessionID)

    const content = "# Reconnaissance Findings\n\n## Port Scan\nTarget 10.10.10.1 has ports 22, 80 open."
    SessionDirectory.writeFinding(sessionID, "recon", content)

    const read = SessionDirectory.readFinding(sessionID, "recon")
    expect(read).toBe(content)
  })

  test("REQ findings/*.md: multiple findings files coexist", () => {
    SessionDirectory.create(sessionID)

    SessionDirectory.writeFinding(sessionID, "recon", "# Recon\nPorts found.")
    SessionDirectory.writeFinding(sessionID, "enum", "# Enum\nDirectories found.")
    SessionDirectory.writeFinding(sessionID, "exploit", "# Exploit\nShell gained.")
    SessionDirectory.writeFinding(sessionID, "post-exploit", "# Post\nPrivesc done.")

    expect(SessionDirectory.readFinding(sessionID, "recon")).toContain("Ports found")
    expect(SessionDirectory.readFinding(sessionID, "enum")).toContain("Directories found")
    expect(SessionDirectory.readFinding(sessionID, "exploit")).toContain("Shell gained")
    expect(SessionDirectory.readFinding(sessionID, "post-exploit")).toContain("Privesc done")
  })

  test("REQ-AGT-017: cleanup removes entire session directory", () => {
    SessionDirectory.create(sessionID)
    SessionDirectory.writeFinding(sessionID, "recon", "test")

    expect(existsSync(SessionDirectory.get(sessionID))).toBe(true)

    SessionDirectory.cleanup(sessionID)
    expect(existsSync(SessionDirectory.get(sessionID))).toBe(false)
  })
})

// =============================================================================
// 10. translateSessionPath
// =============================================================================

describe("Feature 03: translateSessionPath", () => {
  let sessionID: string

  beforeEach(() => {
    sessionID = uniqueSessionID("translate")
  })

  afterEach(() => {
    SessionDirectory.cleanup(sessionID)
  })

  test("REQ /session/ path: translates /session/ prefix to actual host path", () => {
    SessionDirectory.create(sessionID)
    const translated = SessionDirectory.translateSessionPath("/session/state.yaml", sessionID)

    expect(translated).not.toStartWith("/session/")
    expect(translated).toContain("opensploit-session-")
    expect(translated).toEndWith("state.yaml")
  })

  test("REQ /session/ path: non-session paths are returned unchanged", () => {
    const path = "/etc/passwd"
    const translated = SessionDirectory.translateSessionPath(path, sessionID)
    expect(translated).toBe(path)
  })

  test("REQ /session/ path: child session translates to root session directory", () => {
    const rootID = uniqueSessionID("xlate-root")
    registerRootSession(sessionID, rootID)
    SessionDirectory.create(rootID)

    const translated = SessionDirectory.translateSessionPath("/session/findings/recon.md", sessionID)
    expect(translated).toContain(rootID)
    expect(translated).toContain("findings/recon.md")

    // Cleanup
    SessionDirectory.cleanup(rootID)
    unregister(sessionID)
  })
})

// =============================================================================
// 11. State History and Change Detection (Doc 13 integration)
// =============================================================================

describe("Feature 03: State History and Change Detection", () => {
  let sessionID: string

  beforeEach(() => {
    sessionID = uniqueSessionID("history")
  })

  afterEach(() => {
    SessionDirectory.cleanup(sessionID)
  })

  test("REQ state history: each save appends a snapshot", async () => {
    SessionDirectory.create(sessionID)

    await saveEngagementState(sessionID, { target: { ip: "10.10.10.1" }, accessLevel: "none" })
    await saveEngagementState(sessionID, { target: { ip: "10.10.10.1" }, accessLevel: "user" })
    await saveEngagementState(sessionID, { target: { ip: "10.10.10.1" }, accessLevel: "root" })

    const snapshots = await getStateSnapshots(sessionID)
    expect(snapshots).toHaveLength(3)
    expect(snapshots[0].stepIndex).toBe(0)
    expect(snapshots[1].stepIndex).toBe(1)
    expect(snapshots[2].stepIndex).toBe(2)
    expect(snapshots[0].state.accessLevel).toBe("none")
    expect(snapshots[2].state.accessLevel).toBe("root")
  })

  test("REQ state history: getStateAtStep retrieves correct snapshot", async () => {
    SessionDirectory.create(sessionID)

    await saveEngagementState(sessionID, { target: { ip: "10.10.10.1" }, accessLevel: "none" })
    await saveEngagementState(sessionID, { target: { ip: "10.10.10.1" }, accessLevel: "user", ports: [{ port: 22, protocol: "tcp" }] })
    await saveEngagementState(sessionID, { target: { ip: "10.10.10.1" }, accessLevel: "root" })

    const snapshots = await getStateSnapshots(sessionID)
    const atStep1 = getStateAtStep(snapshots, 1)
    expect(atStep1?.state.accessLevel).toBe("user")
    expect(atStep1?.state.ports).toHaveLength(1)
  })

  test("REQ state history: detectStateChanges identifies access level escalation", async () => {
    const before = { timestamp: 1000, stepIndex: 0, state: { accessLevel: "none" as const } }
    const after = { timestamp: 2000, stepIndex: 1, state: { accessLevel: "user" as const, credentials: [{ username: "admin", password: "pass" }] } }

    const changes = detectStateChanges(before, after)
    expect(changes.accessLevelChanged).toBe(true)
    expect(changes.fromAccess).toBe("none")
    expect(changes.toAccess).toBe("user")
    expect(changes.credentialsAdded).toBe(1)
  })

  test("REQ state history: detectStateChanges handles undefined before (first snapshot)", () => {
    const after = {
      timestamp: 1000,
      stepIndex: 0,
      state: {
        target: { ip: "10.10.10.1" },
        ports: [{ port: 22, protocol: "tcp" as const }],
        flags: ["HTB{flag}"],
      },
    }

    const changes = detectStateChanges(undefined, after)
    // No access level change (undefined/"none" → undefined/"none")
    expect(changes.accessLevelChanged).toBe(false)
    expect(changes.flagsAdded).toBe(1)
  })
})

// =============================================================================
// 12. Phase Definitions — Canonical Values
// =============================================================================

describe("Feature 03: Phase Definitions", () => {
  test("REQ-FUN-001..005: all five phases exist with canonical values", () => {
    // The doc specifies canonical values: reconnaissance, enumeration, exploitation,
    // post_exploitation, reporting
    // NOTE: The implementation uses "post-exploitation" (hyphen) instead of
    // "post_exploitation" (underscore) from the doc. This is a known deviation.
    expect(PhaseGating.PHASES).toContain("reconnaissance")
    expect(PhaseGating.PHASES).toContain("enumeration")
    expect(PhaseGating.PHASES).toContain("exploitation")
    expect(PhaseGating.PHASES).toContain("post-exploitation")
    expect(PhaseGating.PHASES).toContain("reporting")
    expect(PhaseGating.PHASES).toHaveLength(5)
  })

  test("REQ-FUN-001..005: phases are in correct methodological order", () => {
    const phases = PhaseGating.PHASES
    expect(phases.indexOf("reconnaissance")).toBeLessThan(phases.indexOf("enumeration"))
    expect(phases.indexOf("enumeration")).toBeLessThan(phases.indexOf("exploitation"))
    expect(phases.indexOf("exploitation")).toBeLessThan(phases.indexOf("post-exploitation"))
    expect(phases.indexOf("post-exploitation")).toBeLessThan(phases.indexOf("reporting"))
  })
})

// =============================================================================
// 13. Tool Failure Reset
// =============================================================================

describe("Feature 03: Tool Failure Management", () => {
  let sessionID: string

  beforeEach(() => {
    sessionID = uniqueSessionID("toolfail")
  })

  afterEach(() => {
    SessionDirectory.cleanup(sessionID)
  })

  test("REQ toolFailures: resetToolFailures clears all tool failure counters", async () => {
    // Add some tool failures
    const { ctx: ctx1 } = makeContext(sessionID)
    await updateTool.execute({
      target: { ip: "10.10.10.1" },
    }, ctx1)

    // Manually save state with tool failures
    const state = await loadEngagementState(sessionID)
    state.toolFailures = [
      { tool: "sqlmap", method: "test", error: "timeout", count: 3, firstSeen: "2026-01-01", lastSeen: "2026-01-02" },
      { tool: "hydra", error: "connection refused", count: 2, firstSeen: "2026-01-01", lastSeen: "2026-01-01" },
    ]
    await saveEngagementState(sessionID, state)

    // Reset via tool
    const { ctx: ctx2 } = makeContext(sessionID)
    const output = await updateTool.execute({ resetToolFailures: true }, ctx2)
    expect(output).toContain("CLEARED")

    // Verify cleared
    const after = await loadEngagementState(sessionID)
    expect(after.toolFailures).toEqual([])
  })
})

// =============================================================================
// 14. Broken Tools Warning in Context Injection
// =============================================================================

describe("Feature 03: Broken Tools Warning", () => {
  let sessionID: string

  beforeEach(() => {
    sessionID = uniqueSessionID("broken")
    SessionDirectory.create(sessionID)
  })

  afterEach(() => {
    SessionDirectory.cleanup(sessionID)
  })

  test("REQ toolFailures: tools with 2+ failures appear in BROKEN TOOLS warning", async () => {
    await saveEngagementState(sessionID, {
      target: { ip: "10.10.10.1" },
      toolFailures: [
        { tool: "sqlmap", method: "test_injection", error: "timeout", count: 3, firstSeen: "2026-01-01", lastSeen: "2026-01-02" },
        { tool: "nmap", method: "scan", error: "host down", count: 1, firstSeen: "2026-01-01", lastSeen: "2026-01-01" },
      ],
    })

    const injection = await getEngagementStateForInjection(sessionID)
    expect(injection).toContain("BROKEN TOOLS")
    expect(injection).toContain("sqlmap")
    // nmap only failed once — should NOT appear in broken tools
    expect(injection!.split("BROKEN TOOLS")[1]).not.toContain("nmap")
  })

  test("REQ toolFailures: no BROKEN TOOLS section when all tools healthy", async () => {
    await saveEngagementState(sessionID, {
      target: { ip: "10.10.10.1" },
      toolFailures: [
        { tool: "nmap", error: "once", count: 1, firstSeen: "2026-01-01", lastSeen: "2026-01-01" },
      ],
    })

    const injection = await getEngagementStateForInjection(sessionID)
    expect(injection).not.toContain("BROKEN TOOLS")
  })
})

// =============================================================================
// Gap Analysis
// =============================================================================
//
// REQ-FUN-001..005 (phase support):
//   - Covered HERE: schema fields, canonical phase values, phase order
//   - Covered in phase-gating.test.ts: tool-to-phase mapping, phase recording
//   - NOT testable here: subagent prompts (text content, not code behavior)
//
// REQ-FUN-006 (phase transitions based on findings):
//   - Covered HERE: phase gating warnings, cyclical workflow, advisory-only
//   - Covered in phase-gating.test.ts: checkPrerequisites, checkToolInvocation
//   - NOT testable here: LLM decision-making (requires live agent)
//
// REQ-FUN-007 (manual phase direction):
//   - NOT testable in unit/acceptance tests — this is natural language interaction
//   - Acceptance: agent prompts include guidance for user direction (manual review)
//
// REQ-FUN-090 (registry phase tags):
//   - Covered in phase-gating.test.ts: TOOL_PHASES mapping
//   - Covered in feature-01 tests: registry schema includes phases
//
// REQ-FUN-091 (phase relevance in search ranking):
//   - Covered in feature-01 tests: search ranking with phase weight
//
// State Management:
//   - Covered HERE: full schema round-trip, merge semantics (files, toolFailures,
//     attackPlan replace, port+protocol dedup, credential dedup), persistence,
//     failed attempts accumulation, access level progression, state history,
//     change detection, session directory structure, path translation
//   - Covered in engagement-state.test.ts: core merge, execute tests, cross-tool
//   - Covered in system-transform.test.ts: context injection, attack plan markers
//
// KNOWN DEVIATION:
//   - Doc says "post_exploitation" (underscore), code uses "post-exploitation" (hyphen)
//   - Not a bug — the doc says "Use these canonical values in registry phase tags"
//     and the registry already uses the hyphenated form. The underscore in the doc
//     table is inconsistent with the doc's own YAML examples.
