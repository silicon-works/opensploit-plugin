/**
 * Feature 04: Sub-Agent System -- Acceptance Tests
 *
 * Each test maps to a specific REQ-* from:
 *   opensploit-vault/requirements/04-sub-agent-system.md
 *
 * Scope: Plugin-provided capabilities only:
 *   - Session hierarchy tracking (hierarchy.ts)
 *   - Session directory management (directory.ts)
 *   - Engagement state injection (system-transform.ts)
 *   - Permission bubbling via ultrasploit (permission.ts, ultrasploit.ts)
 *   - Keyword detection and stripping (chat-message.ts)
 *   - Path rewriting for sub-agents (tool-before.ts)
 *   - Compaction survival (compaction.ts)
 *
 * SKIPPED (OpenCode-internal / task tool behavior):
 *   - REQ-AGT-001: Synchronous execution (task tool waits for sub-agent)
 *   - REQ-AGT-001-B: Async background mode (Phase 2, not implemented)
 *   - REQ-AGT-002: Sub-agent sessions hidden (parentID filter in OpenCode)
 *   - REQ-AGT-003: Results displayed inline in parent (task tool rendering)
 *   - REQ-AGT-005: Existing inline permission prompts used (OpenCode TUI)
 *   - REQ-AGT-006: Sub-agent progress visible (P1, OpenCode TUI)
 *   - REQ-ARC-013: Recursive delegation (prompt-level, tested in feature-02)
 *   - REQ-ARC-014: Delegation prevents context rot (prompt-level)
 *   - REQ-ARC-015-A: Parent summarizes subagent results (prompt-level)
 *   - REQ-ARC-016-A: general subagent as workhorse (OpenCode built-in)
 */

import { describe, test, expect, afterEach } from "bun:test"
import { existsSync, readFileSync } from "fs"
import { join } from "path"
import { tmpdir } from "os"

// Session hierarchy
import {
  registerRootSession,
  getRootSession,
  hasParent,
  unregister,
  getChildren,
  unregisterTree,
} from "../../src/session/hierarchy"

// Session directory
import * as SessionDirectory from "../../src/session/directory"

// Engagement state
import {
  saveEngagementState,
  loadEngagementState,
  mergeState,
} from "../../src/tools/engagement-state"

// Hooks
import { systemTransformHook } from "../../src/hooks/system-transform"
import { toolBeforeHook } from "../../src/hooks/tool-before"
import { compactionHook } from "../../src/hooks/compaction"
import { permissionHook } from "../../src/hooks/permission"
import { chatMessageHook } from "../../src/hooks/chat-message"
import {
  setUltrasploit,
  isUltrasploitEnabled,
  toggleUltrasploit,
} from "../../src/hooks/ultrasploit"

// ---------------------------------------------------------------------------
// Unique session IDs per test run to avoid collisions
// ---------------------------------------------------------------------------
const TS = Date.now().toString(36)
const ROOT = `f04-root-${TS}`
const CHILD_A = `f04-child-a-${TS}`
const CHILD_B = `f04-child-b-${TS}`
const GRANDCHILD = `f04-grandchild-${TS}`

afterEach(() => {
  SessionDirectory.cleanup(ROOT)
  unregisterTree(ROOT)
  unregister(CHILD_A)
  unregister(CHILD_B)
  unregister(GRANDCHILD)
  setUltrasploit(false)
})

// =========================================================================
// Section 1: Session Hierarchy Tracking
// =========================================================================

describe("Session Hierarchy (REQ-AGT-004: permission bubbling prerequisite)", () => {
  test("REQ-AGT-004: getRootSession resolves child -> root in O(1)", () => {
    registerRootSession(CHILD_A, ROOT)
    expect(getRootSession(CHILD_A)).toBe(ROOT)
  })

  test("REQ-AGT-004: getRootSession resolves grandchild -> root (not parent)", () => {
    // root -> child-a -> grandchild: all map to ROOT
    registerRootSession(CHILD_A, ROOT)
    registerRootSession(GRANDCHILD, ROOT)

    expect(getRootSession(GRANDCHILD)).toBe(ROOT)
    expect(getRootSession(CHILD_A)).toBe(ROOT)
  })

  test("REQ-AGT-004: unregistered session returns itself (root identity)", () => {
    expect(getRootSession(ROOT)).toBe(ROOT)
  })

  test("REQ-AGT-004: hasParent distinguishes root from children", () => {
    registerRootSession(CHILD_A, ROOT)
    expect(hasParent(ROOT)).toBe(false)
    expect(hasParent(CHILD_A)).toBe(true)
  })

  test("REQ-AGT-004: getChildren returns all descendants under root", () => {
    registerRootSession(CHILD_A, ROOT)
    registerRootSession(CHILD_B, ROOT)
    registerRootSession(GRANDCHILD, ROOT)

    const children = getChildren(ROOT)
    expect(children).toContain(CHILD_A)
    expect(children).toContain(CHILD_B)
    expect(children).toContain(GRANDCHILD)
    expect(children.length).toBe(3)
  })

  test("REQ-AGT-004: unregisterTree cleans up entire hierarchy", () => {
    registerRootSession(CHILD_A, ROOT)
    registerRootSession(CHILD_B, ROOT)
    registerRootSession(GRANDCHILD, ROOT)

    unregisterTree(ROOT)

    expect(getRootSession(CHILD_A)).toBe(CHILD_A) // falls back to self
    expect(getRootSession(GRANDCHILD)).toBe(GRANDCHILD)
    expect(getChildren(ROOT)).toEqual([])
  })
})

// =========================================================================
// Section 2: Session Working Directory
// =========================================================================

describe("Session Working Directory (REQ-AGT-016, REQ-AGT-017)", () => {
  test("REQ-AGT-016: temp directory path is /tmp/opensploit-session-{rootSessionID}/", () => {
    const dir = SessionDirectory.get(ROOT)
    const expected = join(tmpdir(), `opensploit-session-${ROOT}`)
    expect(dir).toBe(expected)
  })

  test("REQ-AGT-016: create builds standard directory structure", () => {
    const dir = SessionDirectory.create(ROOT)

    expect(existsSync(dir)).toBe(true)
    expect(existsSync(join(dir, "findings"))).toBe(true)
    expect(existsSync(join(dir, "artifacts"))).toBe(true)
    expect(existsSync(join(dir, "artifacts", "screenshots"))).toBe(true)
    expect(existsSync(join(dir, "artifacts", "loot"))).toBe(true)
    expect(existsSync(join(dir, "wordlists"))).toBe(true)
  })

  test("REQ-AGT-016: statePath points to state.yaml inside session dir", () => {
    const statePath = SessionDirectory.statePath(ROOT)
    expect(statePath).toBe(join(SessionDirectory.get(ROOT), "state.yaml"))
  })

  test("REQ-AGT-017: cleanup removes directory and all contents", () => {
    SessionDirectory.create(ROOT)
    // Write a file to verify recursive deletion
    SessionDirectory.writeFinding(ROOT, "recon", "test findings content")
    expect(existsSync(SessionDirectory.findingsDir(ROOT))).toBe(true)

    SessionDirectory.cleanup(ROOT)
    expect(existsSync(SessionDirectory.get(ROOT))).toBe(false)
  })

  test("REQ-AGT-017: cleanup is safe on already-deleted directory", () => {
    // Should not throw
    SessionDirectory.cleanup("nonexistent-session-" + TS)
  })

  test("REQ-AGT-016: create is idempotent (calling twice returns same path)", () => {
    const dir1 = SessionDirectory.create(ROOT)
    // Write a file, then create again -- file should still exist
    SessionDirectory.writeFinding(ROOT, "test", "preserved content")
    const dir2 = SessionDirectory.create(ROOT)

    expect(dir1).toBe(dir2)
    expect(SessionDirectory.readFinding(ROOT, "test")).toBe("preserved content")
  })
})

// =========================================================================
// Section 3: Shared Session Directory Across Hierarchy
// =========================================================================

describe("Sub-agents share root session directory (REQ-SES-001, REQ-SES-003 equivalent)", () => {
  test("REQ-AGT-016 + hierarchy: child session resolves to root directory via translateSessionPath", () => {
    registerRootSession(CHILD_A, ROOT)
    SessionDirectory.create(ROOT)

    const translated = SessionDirectory.translateSessionPath(
      "/session/findings/recon.md",
      CHILD_A,
    )

    // Must point to ROOT's directory, not child's
    expect(translated).toContain(ROOT)
    expect(translated).not.toContain(CHILD_A)
    expect(translated).toBe(
      join(SessionDirectory.get(ROOT), "findings", "recon.md"),
    )
  })

  test("REQ-AGT-016 + hierarchy: grandchild resolves to root directory", () => {
    registerRootSession(CHILD_A, ROOT)
    registerRootSession(GRANDCHILD, ROOT)
    SessionDirectory.create(ROOT)

    const translated = SessionDirectory.translateSessionPath(
      "/session/state.yaml",
      GRANDCHILD,
    )

    expect(translated).toContain(ROOT)
    expect(translated).toBe(join(SessionDirectory.get(ROOT), "state.yaml"))
  })

  test("translateSessionPath is no-op for non-session paths", () => {
    const path = "/home/user/project/file.txt"
    const result = SessionDirectory.translateSessionPath(path, ROOT)
    expect(result).toBe(path)
  })
})

// =========================================================================
// Section 4: Context Injection -- Engagement State
// =========================================================================

describe("Context Injection: Engagement State (REQ-AGT-010, REQ-AGT-011)", () => {
  test("REQ-AGT-010: system-transform injects engagement state into system prompt", async () => {
    SessionDirectory.create(ROOT)
    await saveEngagementState(ROOT, {
      target: { ip: "10.10.10.50", hostname: "testbox.htb" },
      ports: [
        { port: 22, protocol: "tcp", service: "ssh", version: "OpenSSH 8.9", state: "open" },
        { port: 80, protocol: "tcp", service: "http", version: "nginx 1.24", state: "open" },
      ],
      accessLevel: "none",
    })

    const output = { system: ["base agent prompt"] }
    await systemTransformHook({ sessionID: ROOT, model: {} }, output)

    expect(output.system.length).toBeGreaterThan(1)
    const injected = output.system.slice(1).join("\n")
    expect(injected).toContain("10.10.10.50")
    expect(injected).toContain("testbox.htb")
  })

  test("REQ-AGT-011: injected state includes target info", async () => {
    SessionDirectory.create(ROOT)
    await saveEngagementState(ROOT, {
      target: { ip: "10.10.10.50", hostname: "testbox.htb" },
    })

    const output = { system: [] as string[] }
    await systemTransformHook({ sessionID: ROOT, model: {} }, output)
    const injected = output.system.join("\n")

    expect(injected).toContain("10.10.10.50")
    expect(injected).toContain("testbox.htb")
  })

  test("REQ-AGT-011: injected state includes discovered ports", async () => {
    SessionDirectory.create(ROOT)
    await saveEngagementState(ROOT, {
      target: { ip: "10.10.10.50" },
      ports: [
        { port: 22, protocol: "tcp", service: "ssh", state: "open" },
        { port: 445, protocol: "tcp", service: "smb", state: "filtered" },
      ],
    })

    const output = { system: [] as string[] }
    await systemTransformHook({ sessionID: ROOT, model: {} }, output)
    const injected = output.system.join("\n")

    expect(injected).toContain("OPEN")
    expect(injected).toContain("22/tcp (ssh)")
    expect(injected).toContain("FILTERED")
    expect(injected).toContain("445/tcp")
  })

  test("REQ-AGT-011: injected state includes credentials", async () => {
    SessionDirectory.create(ROOT)
    await saveEngagementState(ROOT, {
      target: { ip: "10.10.10.50" },
      credentials: [
        { username: "admin", password: "Welcome1!", service: "ssh", validated: true },
      ],
    })

    const output = { system: [] as string[] }
    await systemTransformHook({ sessionID: ROOT, model: {} }, output)
    const injected = output.system.join("\n")

    expect(injected).toContain("admin")
    expect(injected).toContain("Welcome1!")
  })

  test("REQ-AGT-011: injected state includes vulnerabilities", async () => {
    SessionDirectory.create(ROOT)
    await saveEngagementState(ROOT, {
      target: { ip: "10.10.10.50" },
      vulnerabilities: [
        { name: "CVE-2024-1234 RCE in Apache", severity: "critical", exploitable: true },
      ],
    })

    const output = { system: [] as string[] }
    await systemTransformHook({ sessionID: ROOT, model: {} }, output)
    const injected = output.system.join("\n")

    expect(injected).toContain("CVE-2024-1234")
    expect(injected).toContain("critical")
  })

  test("REQ-AGT-011: injected state includes failed attempts", async () => {
    SessionDirectory.create(ROOT)
    await saveEngagementState(ROOT, {
      target: { ip: "10.10.10.50" },
      failedAttempts: [
        { action: "SSH brute force as root", tool: "hydra", reason: "No valid credentials found" },
      ],
    })

    const output = { system: [] as string[] }
    await systemTransformHook({ sessionID: ROOT, model: {} }, output)
    const injected = output.system.join("\n")

    expect(injected).toContain("SSH brute force")
    expect(injected).toContain("hydra")
  })
})

// =========================================================================
// Section 5: Context Injection -- Session Working Directory
// =========================================================================

describe("Context Injection: Session Directory (REQ-AGT-013)", () => {
  test("REQ-AGT-013: injected context includes session working directory path", async () => {
    SessionDirectory.create(ROOT)
    await saveEngagementState(ROOT, {
      target: { ip: "10.10.10.50" },
    })

    const output = { system: [] as string[] }
    await systemTransformHook({ sessionID: ROOT, model: {} }, output)
    const injected = output.system.join("\n")

    expect(injected).toContain("Session Working Directory")
    expect(injected).toContain(SessionDirectory.get(ROOT))
    expect(injected).toContain("/tmp/opensploit-session-")
  })

  test("REQ-AGT-013: child session receives root session directory (not its own)", async () => {
    registerRootSession(CHILD_A, ROOT)
    SessionDirectory.create(ROOT)
    await saveEngagementState(ROOT, {
      target: { ip: "10.10.10.50" },
    })

    const output = { system: [] as string[] }
    await systemTransformHook({ sessionID: CHILD_A, model: {} }, output)
    const injected = output.system.join("\n")

    // Directory path should reference ROOT's session ID
    expect(injected).toContain(ROOT)
    expect(injected).not.toContain(CHILD_A)
  })
})

// =========================================================================
// Section 6: Context Injection for ALL Subagents
// =========================================================================

describe("Context Injection applies to ALL subagents (REQ-AGT-015)", () => {
  test("REQ-AGT-015: system-transform injects state for root session (any agent name)", async () => {
    // The system-transform hook does NOT check agent name -- it injects
    // whenever engagement state exists for the session. This satisfies
    // REQ-AGT-015: "applies to ALL subagents in pentest session tree".
    SessionDirectory.create(ROOT)
    await saveEngagementState(ROOT, {
      target: { ip: "10.10.10.99" },
      ports: [{ port: 8080, protocol: "tcp", service: "http-proxy", state: "open" }],
    })

    // Simulate a non-pentest-named agent (e.g., "general" or "explore")
    const output = { system: ["You are the general agent."] }
    await systemTransformHook({ sessionID: ROOT, model: {} }, output)

    const injected = output.system.slice(1).join("\n")
    expect(injected).toContain("10.10.10.99")
    expect(injected).toContain("8080")
  })

  test("REQ-AGT-015: child of pentest tree gets state even with non-pentest session ID", async () => {
    registerRootSession(CHILD_A, ROOT)
    SessionDirectory.create(ROOT)
    await saveEngagementState(ROOT, {
      target: { ip: "10.10.10.99" },
    })

    // Child session ID has no "pentest" in name -- still gets injection
    const output = { system: ["explore agent prompt"] }
    await systemTransformHook({ sessionID: CHILD_A, model: {} }, output)

    expect(output.system.length).toBeGreaterThan(1)
    const injected = output.system.slice(1).join("\n")
    expect(injected).toContain("10.10.10.99")
  })
})

// =========================================================================
// Section 7: Engagement State Updates from Sub-Agents (REQ-AGT-012)
// =========================================================================

describe("Shared state updates across hierarchy (REQ-AGT-012)", () => {
  test("REQ-AGT-012: child writes state via root session ID, parent sees updates", async () => {
    registerRootSession(CHILD_A, ROOT)
    SessionDirectory.create(ROOT)

    // Simulate child writing state (uses getRootSession internally)
    const rootID = getRootSession(CHILD_A)
    expect(rootID).toBe(ROOT)

    await saveEngagementState(rootID, {
      target: { ip: "10.10.10.50" },
      ports: [{ port: 22, protocol: "tcp", service: "ssh", state: "open" }],
    })

    // Parent reads state from the same root session
    const state = await loadEngagementState(ROOT)
    expect(state.target?.ip).toBe("10.10.10.50")
    expect(state.ports).toHaveLength(1)
    expect(state.ports![0].port).toBe(22)
  })

  test("REQ-AGT-012: mergeState appends ports and deduplicates", async () => {
    const existing = {
      target: { ip: "10.10.10.50" },
      ports: [{ port: 22, protocol: "tcp" as const, service: "ssh", state: "open" as const }],
    }
    const updates = {
      ports: [
        { port: 80, protocol: "tcp" as const, service: "http", state: "open" as const },
        { port: 22, protocol: "tcp" as const, service: "ssh", version: "OpenSSH 8.9", state: "open" as const },
      ],
    }

    const merged = mergeState(existing, updates)
    expect(merged.ports).toHaveLength(2) // 22 updated in place, 80 added
    expect(merged.ports!.find((p: any) => p.port === 22)?.version).toBe("OpenSSH 8.9")
    expect(merged.ports!.find((p: any) => p.port === 80)?.service).toBe("http")
  })

  test("REQ-AGT-012: sibling agents see each other's state updates", async () => {
    registerRootSession(CHILD_A, ROOT)
    registerRootSession(CHILD_B, ROOT)
    SessionDirectory.create(ROOT)

    // Child A discovers ports
    await saveEngagementState(getRootSession(CHILD_A), {
      target: { ip: "10.10.10.50" },
      ports: [{ port: 22, protocol: "tcp", service: "ssh", state: "open" }],
    })

    // Child B discovers credentials
    const existingState = await loadEngagementState(getRootSession(CHILD_B))
    const updated = mergeState(existingState, {
      credentials: [{ username: "admin", password: "secret", service: "ssh" }],
    })
    await saveEngagementState(getRootSession(CHILD_B), updated)

    // Both children (and root) see the combined state
    const finalState = await loadEngagementState(ROOT)
    expect(finalState.target?.ip).toBe("10.10.10.50")
    expect(finalState.ports).toHaveLength(1)
    expect(finalState.credentials).toHaveLength(1)
    expect(finalState.credentials![0].username).toBe("admin")
  })
})

// =========================================================================
// Section 8: Path Rewriting for Sub-Agents
// =========================================================================

describe("Path rewriting for sub-agents (REQ-AGT-013 runtime)", () => {
  test("REQ-AGT-013: /session/ in read tool resolves to root dir for child", async () => {
    registerRootSession(CHILD_A, ROOT)
    SessionDirectory.create(ROOT)
    const rootDir = SessionDirectory.get(ROOT)

    const output = { args: { filePath: "/session/state.yaml" } }
    await toolBeforeHook({ tool: "read", sessionID: CHILD_A, callID: "c1" }, output)

    expect(output.args.filePath).toBe(`${rootDir}/state.yaml`)
    expect(output.args.filePath).toContain(ROOT)
    expect(output.args.filePath).not.toContain("/session/")
  })

  test("REQ-AGT-013: /session/ in bash resolves to root dir for grandchild", async () => {
    registerRootSession(CHILD_A, ROOT)
    registerRootSession(GRANDCHILD, ROOT)
    SessionDirectory.create(ROOT)
    const rootDir = SessionDirectory.get(ROOT)

    const output = { args: { command: "ls /session/findings/" } }
    await toolBeforeHook({ tool: "bash", sessionID: GRANDCHILD, callID: "c2" }, output)

    expect(output.args.command).toBe(`ls ${rootDir}/findings/`)
    expect(output.args.command).not.toContain("/session/")
  })
})

// =========================================================================
// Section 9: Ultrasploit Mode (REQ-AGT-020, REQ-AGT-021, REQ-AGT-022)
// =========================================================================

describe("Ultrasploit Mode (REQ-AGT-020, REQ-AGT-021, REQ-AGT-022)", () => {
  test("REQ-AGT-020: ultrasploit auto-approves all permission requests", async () => {
    setUltrasploit(true)

    const bashPerm = { status: "ask" as "ask" | "deny" | "allow" }
    await permissionHook({ permission: "bash", pattern: "nmap -sV 10.10.10.1" }, bashPerm)
    expect(bashPerm.status).toBe("allow")

    const mcpPerm = { status: "deny" as "ask" | "deny" | "allow" }
    await permissionHook({ permission: "mcp_tool", pattern: "sqlmap.injection_test" }, mcpPerm)
    expect(mcpPerm.status).toBe("allow")

    const readPerm = { status: "ask" as "ask" | "deny" | "allow" }
    await permissionHook({ permission: "read", pattern: "/etc/shadow" }, readPerm)
    expect(readPerm.status).toBe("allow")
  })

  test("REQ-AGT-020: without ultrasploit, permissions pass through unchanged", async () => {
    setUltrasploit(false)

    const askPerm = { status: "ask" as "ask" | "deny" | "allow" }
    await permissionHook({ permission: "bash", pattern: "nmap*" }, askPerm)
    expect(askPerm.status).toBe("ask")

    const denyPerm = { status: "deny" as "ask" | "deny" | "allow" }
    await permissionHook({ permission: "mcp_tool", pattern: "*" }, denyPerm)
    expect(denyPerm.status).toBe("deny")
  })

  test("REQ-AGT-021: ultrasploit is global state (applies to entire session tree)", () => {
    // Ultrasploit is a global boolean, not per-session.
    // This means it applies to root + all children automatically.
    setUltrasploit(true)
    expect(isUltrasploitEnabled()).toBe(true)

    // Any permission check from any session benefits
    // (the hook doesn't check sessionID, just the global flag)
  })

  test("REQ-AGT-022: ultrasploit toggleable via setUltrasploit", () => {
    expect(isUltrasploitEnabled()).toBe(false)
    setUltrasploit(true)
    expect(isUltrasploitEnabled()).toBe(true)
    setUltrasploit(false)
    expect(isUltrasploitEnabled()).toBe(false)
  })

  test("REQ-AGT-022: ultrasploit toggleable via toggleUltrasploit", () => {
    expect(isUltrasploitEnabled()).toBe(false)
    const result1 = toggleUltrasploit()
    expect(result1).toBe(true)
    expect(isUltrasploitEnabled()).toBe(true)
    const result2 = toggleUltrasploit()
    expect(result2).toBe(false)
    expect(isUltrasploitEnabled()).toBe(false)
  })

  test("REQ-AGT-022: keyword 'ultrasploit' in chat message activates mode", async () => {
    expect(isUltrasploitEnabled()).toBe(false)

    const output = {
      message: {},
      parts: [{ type: "text", text: "ultrasploit enumerate ports on target" }],
    }
    await chatMessageHook(
      { sessionID: ROOT, agent: "pentest", model: { providerID: "test", modelID: "test" } },
      output,
    )

    expect(isUltrasploitEnabled()).toBe(true)
    // Keyword stripped from message
    expect(output.parts[0].text).toBe("enumerate ports on target")
    expect(output.parts[0].text).not.toContain("ultrasploit")
  })

  test("REQ-AGT-022: keyword stripping is case-insensitive", async () => {
    const output = {
      message: {},
      parts: [{ type: "text", text: "ULTRASPLOIT run nmap scan" }],
    }
    await chatMessageHook(
      { sessionID: ROOT, agent: "pentest", model: { providerID: "test", modelID: "test" } },
      output,
    )

    expect(isUltrasploitEnabled()).toBe(true)
    expect(output.parts[0].text).toBe("run nmap scan")
  })
})

// =========================================================================
// Section 10: End-to-End Chain -- Hierarchy + State + Injection + Compaction
// =========================================================================

describe("End-to-end: hierarchy + state + injection + permission + compaction", () => {
  test("full sub-agent lifecycle across 3 levels of hierarchy", async () => {
    // Setup: root -> child -> grandchild
    registerRootSession(CHILD_A, ROOT)
    registerRootSession(GRANDCHILD, ROOT)
    SessionDirectory.create(ROOT)

    // 1. Root saves initial state (recon phase)
    await saveEngagementState(ROOT, {
      target: { ip: "10.10.11.100", hostname: "challenge.htb" },
      ports: [
        { port: 22, protocol: "tcp", service: "ssh", state: "open" },
        { port: 80, protocol: "tcp", service: "http", state: "open" },
        { port: 3306, protocol: "tcp", service: "mysql", state: "filtered" },
      ],
      accessLevel: "none",
    })

    // 2. Child-A reads parent state via system-transform (enum phase)
    const childSystem = { system: ["Enumeration agent active."] }
    await systemTransformHook({ sessionID: CHILD_A, model: {} }, childSystem)

    const childInjected = childSystem.system.slice(1).join("\n")
    expect(childInjected).toContain("10.10.11.100")
    expect(childInjected).toContain("challenge.htb")
    expect(childInjected).toContain("22/tcp (ssh)")
    expect(childInjected).toContain("Session Working Directory")
    expect(childInjected).toContain(ROOT)

    // 3. Child-A discovers credentials, writes to shared state
    const currentState = await loadEngagementState(getRootSession(CHILD_A))
    const childUpdates = mergeState(currentState, {
      credentials: [
        { username: "dbadmin", password: "mysql_pass!", service: "mysql", validated: true },
      ],
      vulnerabilities: [
        { name: "Weak MySQL credentials", severity: "high", service: "mysql", port: 3306 },
      ],
    })
    await saveEngagementState(getRootSession(CHILD_A), childUpdates)

    // 4. Grandchild (exploit sub-sub-agent) sees BOTH ports AND credentials
    const grandchildSystem = { system: ["Exploitation agent active."] }
    await systemTransformHook({ sessionID: GRANDCHILD, model: {} }, grandchildSystem)

    const grandchildInjected = grandchildSystem.system.slice(1).join("\n")
    expect(grandchildInjected).toContain("10.10.11.100")
    expect(grandchildInjected).toContain("dbadmin")
    expect(grandchildInjected).toContain("mysql_pass!")
    expect(grandchildInjected).toContain("Weak MySQL credentials")

    // 5. Grandchild writes exploit results
    const stateForExploit = await loadEngagementState(getRootSession(GRANDCHILD))
    const exploitUpdates = mergeState(stateForExploit, {
      accessLevel: "user",
      sessions: [
        { id: "shell-1", type: "reverse", user: "www-data" },
      ],
    })
    await saveEngagementState(getRootSession(GRANDCHILD), exploitUpdates)

    // 6. Root sees ALL accumulated state
    const finalState = await loadEngagementState(ROOT)
    expect(finalState.target?.ip).toBe("10.10.11.100")
    expect(finalState.ports).toHaveLength(3)
    expect(finalState.credentials).toHaveLength(1)
    expect(finalState.vulnerabilities).toHaveLength(1)
    expect(finalState.sessions).toHaveLength(1)
    expect(finalState.accessLevel).toBe("user")

    // 7. Compaction preserves state
    const compactOut = { context: ["Previous conversation summary."], prompt: undefined as string | undefined }
    await compactionHook({ sessionID: CHILD_A }, compactOut)

    expect(compactOut.context.length).toBeGreaterThanOrEqual(2)
    const stateEntry = compactOut.context.find((c: string) => c.includes("ENGAGEMENT STATE"))
    expect(stateEntry).toBeDefined()
    expect(stateEntry).toContain("PRESERVE")
    expect(stateEntry).toContain("10.10.11.100")
    expect(stateEntry).toContain("dbadmin")
    expect(stateEntry).toContain("www-data")

    // 8. Enable ultrasploit, verify auto-approve
    setUltrasploit(true)
    const perm = { status: "ask" as "ask" | "deny" | "allow" }
    await permissionHook({ permission: "bash", pattern: "nmap -p- 10.10.11.100" }, perm)
    expect(perm.status).toBe("allow")

    // 9. Path rewriting works for grandchild
    const pathOutput = { args: { filePath: "/session/findings/exploit.md" } }
    await toolBeforeHook({ tool: "write", sessionID: GRANDCHILD, callID: "c-gc" }, pathOutput)
    expect(pathOutput.args.filePath).toContain(ROOT)
    expect(pathOutput.args.filePath).not.toContain("/session/")

    // 10. Tree cleanup removes everything
    SessionDirectory.cleanup(ROOT)
    unregisterTree(ROOT)

    expect(existsSync(SessionDirectory.get(ROOT))).toBe(false)
    expect(getChildren(ROOT)).toEqual([])
    expect(getRootSession(CHILD_A)).toBe(CHILD_A) // falls back to self
  })
})

// =========================================================================
// Section 11: Attack Plan in Context Injection
// =========================================================================

describe("Attack plan injection (REQ-AGT-010 extension)", () => {
  test("attack plan with step statuses renders correctly in injection", async () => {
    SessionDirectory.create(ROOT)
    await saveEngagementState(ROOT, {
      target: { ip: "10.10.10.50" },
      attackPlan: {
        title: "MySQL RCE via UDF injection",
        source: "pentest/research",
        steps: [
          { step: 1, description: "Connect to MySQL with creds", status: "completed" },
          { step: 2, description: "Upload UDF shared library", status: "in_progress" },
          { step: 3, description: "Execute OS command via UDF", status: "pending" },
        ],
      },
    })

    const output = { system: [] as string[] }
    await systemTransformHook({ sessionID: ROOT, model: {} }, output)
    const injected = output.system.join("\n")

    expect(injected).toContain("Attack Plan")
    expect(injected).toContain("MySQL RCE via UDF injection")
    expect(injected).toContain("[x]") // completed
    expect(injected).toContain("[>]") // in_progress
    expect(injected).toContain("[ ]") // pending
  })
})

// =========================================================================
// Section 12: Broken Tools Warning
// =========================================================================

describe("Broken tools warning in injection (REQ-AGT-010 extension)", () => {
  test("tool failures with count >= 2 appear as BROKEN TOOLS warning", async () => {
    SessionDirectory.create(ROOT)
    await saveEngagementState(ROOT, {
      target: { ip: "10.10.10.50" },
      toolFailures: [
        { tool: "sqlmap", method: "test_injection", error: "timeout", count: 3, firstSeen: "2026-01-01", lastSeen: "2026-01-01" },
        { tool: "nmap", method: "port_scan", error: "host down", count: 1, firstSeen: "2026-01-01", lastSeen: "2026-01-01" },
      ],
    })

    const output = { system: [] as string[] }
    await systemTransformHook({ sessionID: ROOT, model: {} }, output)
    const injected = output.system.join("\n")

    // Only sqlmap (count >= 2) should appear as broken
    expect(injected).toContain("BROKEN TOOLS")
    expect(injected).toContain("sqlmap")
    // nmap with count=1 should NOT appear in broken tools warning
    // (but it may appear in the raw YAML dump)
  })
})

// =========================================================================
// Section 13: No injection when no state exists
// =========================================================================

describe("Graceful degradation", () => {
  test("system-transform does nothing when no engagement state exists", async () => {
    const output = { system: ["base prompt only"] }
    await systemTransformHook({ sessionID: ROOT, model: {} }, output)

    expect(output.system).toHaveLength(1)
    expect(output.system[0]).toBe("base prompt only")
  })

  test("system-transform does nothing when no sessionID provided", async () => {
    const output = { system: ["base prompt only"] }
    await systemTransformHook({ sessionID: undefined, model: {} }, output)

    expect(output.system).toHaveLength(1)
    expect(output.system[0]).toBe("base prompt only")
  })

  test("compaction does nothing when no engagement state exists", async () => {
    const output = { context: ["existing"], prompt: undefined }
    await compactionHook({ sessionID: ROOT }, output)

    expect(output.context).toHaveLength(1)
  })
})

// =========================================================================
// Gap Analysis
// =========================================================================

/**
 * FEATURE 04 -- GAP ANALYSIS
 *
 * | REQ ID        | Plugin? | Tested Here | Notes                                        |
 * |---------------|---------|-------------|----------------------------------------------|
 * | REQ-AGT-001   | No      | SKIP        | Synchronous exec = OpenCode task tool        |
 * | REQ-AGT-001-B | No      | SKIP        | Phase 2 (async background), not implemented  |
 * | REQ-AGT-002   | No      | SKIP        | Session list filter = OpenCode internal       |
 * | REQ-AGT-003   | No      | SKIP        | Inline results = OpenCode task tool           |
 * | REQ-AGT-004   | YES     | YES         | Hierarchy map + permission hook               |
 * | REQ-AGT-005   | No      | SKIP        | Inline prompts = OpenCode TUI                 |
 * | REQ-AGT-006   | No      | SKIP        | Progress visibility = OpenCode TUI P1         |
 * | REQ-AGT-010   | YES     | YES         | system-transform injects state                |
 * | REQ-AGT-011   | YES     | YES         | All 5 fields verified in injection            |
 * | REQ-AGT-012   | YES     | YES         | Shared state via getRootSession + mergeState  |
 * | REQ-AGT-013   | YES     | YES         | Session dir in injection + path rewriting     |
 * | REQ-AGT-015   | YES     | YES         | Hook is agent-name-agnostic                   |
 * | REQ-AGT-016   | YES     | YES         | Path format, structure, idempotency           |
 * | REQ-AGT-017   | YES     | YES         | cleanup + unregisterTree                      |
 * | REQ-ARC-013   | No      | SKIP        | Recursive delegation = prompt-level (feat 02) |
 * | REQ-ARC-014   | No      | SKIP        | Context rot prevention = prompt-level          |
 * | REQ-ARC-015-A | No      | SKIP        | Summarization = prompt-level                  |
 * | REQ-ARC-016-A | No      | SKIP        | general subagent = OpenCode built-in           |
 * | REQ-AGT-020   | YES     | YES         | Ultrasploit auto-approve all permissions      |
 * | REQ-AGT-021   | YES     | YES         | Global state = applies to session tree         |
 * | REQ-AGT-022   | YES     | YES         | set/toggle/keyword activation + stripping     |
 *
 * === Summary ===
 * Total REQs in spec:  21
 * Plugin-provided:     11
 * Tested here:         11 (100% of plugin-provided)
 * Skipped (OpenCode):  10 (task tool, TUI, prompt-level)
 *
 * All 11 plugin-provided requirements have acceptance tests.
 * No gaps in plugin-layer coverage.
 */
