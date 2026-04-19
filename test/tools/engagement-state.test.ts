import { describe, expect, test, afterEach } from "bun:test"
import type { ToolContext } from "@opencode-ai/plugin"
import yaml from "js-yaml"
import { readFileSync, writeFileSync } from "fs"
import * as SessionDirectory from "../../src/session/directory"
import {
  createUpdateEngagementStateTool,
  createReadEngagementStateTool,
  loadEngagementState,
  getEngagementStateForInjection,
  mergeState,
} from "../../src/tools/engagement-state"
import { registerRootSession } from "../../src/session/hierarchy"

describe("tool.engagement-state", () => {
  const testSessionID = "test-engagement-session-12345"

  // Clean up after each test
  afterEach(() => {
    SessionDirectory.cleanup(testSessionID)
  })

  test("loadEngagementState returns empty object when no state file exists", async () => {
    // Don't create session directory - state file won't exist
    const state = await loadEngagementState(testSessionID)
    expect(state).toEqual({})
  })

  test("loadEngagementState loads state from state.yaml", async () => {
    // Create session directory and write state
    SessionDirectory.create(testSessionID)
    const statePath = SessionDirectory.statePath(testSessionID)

    const stateContent = yaml.dump({
      target: { ip: "10.10.10.1", hostname: "target.htb" },
      ports: [{ port: 22, protocol: "tcp", service: "ssh" }],
      accessLevel: "none",
    })
    writeFileSync(statePath, stateContent)

    const state = await loadEngagementState(testSessionID)
    expect(state.target?.ip).toBe("10.10.10.1")
    expect(state.ports?.length).toBe(1)
    expect(state.ports?.[0].port).toBe(22)
    expect(state.accessLevel).toBe("none")
  })

  test("getEngagementStateForInjection returns null when no state exists", async () => {
    const injection = await getEngagementStateForInjection(testSessionID)
    expect(injection).toBeNull()
  })

  test("getEngagementStateForInjection returns formatted state when state exists", async () => {
    // Create session directory and write state
    SessionDirectory.create(testSessionID)
    const statePath = SessionDirectory.statePath(testSessionID)

    const stateContent = yaml.dump({
      target: { ip: "10.10.10.1" },
      ports: [{ port: 80, protocol: "tcp", service: "http" }],
    })
    writeFileSync(statePath, stateContent)

    const injection = await getEngagementStateForInjection(testSessionID)
    expect(injection).not.toBeNull()
    expect(injection).toContain("## Current Engagement State")
    expect(injection).toContain("10.10.10.1")
    expect(injection).toContain("port: 80")
  })

  // ---------------------------------------------------------------------------
  // Merge Semantics Tests
  // ---------------------------------------------------------------------------

  describe("mergeState", () => {
    test("replaces scalar values", () => {
      const existing = { accessLevel: "none" as const }
      const updates = { accessLevel: "user" as const }
      const result = mergeState(existing, updates)
      expect(result.accessLevel).toBe("user")
    })

    test("merges target object", () => {
      const existing = { target: { ip: "10.10.10.1" } }
      const updates = { target: { ip: "10.10.10.1", hostname: "target.htb" } }
      const result = mergeState(existing, updates)
      expect(result.target?.ip).toBe("10.10.10.1")
      expect(result.target?.hostname).toBe("target.htb")
    })

    test("appends to ports array with deduplication", () => {
      const existing = {
        ports: [{ port: 22, protocol: "tcp" as const, service: "ssh" }],
      }
      const updates = {
        ports: [
          { port: 22, protocol: "tcp" as const, version: "OpenSSH 8.2" }, // Update existing
          { port: 80, protocol: "tcp" as const, service: "http" }, // New port
        ],
      }
      const result = mergeState(existing, updates)

      expect(result.ports?.length).toBe(2)
      // Port 22 should be updated with version
      const port22 = result.ports?.find((p) => p.port === 22)
      expect(port22?.service).toBe("ssh")
      expect(port22?.version).toBe("OpenSSH 8.2")
      // Port 80 should be added
      const port80 = result.ports?.find((p) => p.port === 80)
      expect(port80?.service).toBe("http")
    })

    test("appends to credentials array with deduplication", () => {
      const existing = {
        credentials: [{ username: "admin", service: "http", password: "old" }],
      }
      const updates = {
        credentials: [
          { username: "admin", service: "http", password: "new", validated: true }, // Update existing
          { username: "root", service: "ssh" }, // New credential
        ],
      }
      const result = mergeState(existing, updates)

      expect(result.credentials?.length).toBe(2)
      // admin@http should be updated
      const adminHttp = result.credentials?.find(
        (c) => c.username === "admin" && c.service === "http"
      )
      expect(adminHttp?.password).toBe("new")
      expect(adminHttp?.validated).toBe(true)
      // root@ssh should be added
      const rootSsh = result.credentials?.find(
        (c) => c.username === "root" && c.service === "ssh"
      )
      expect(rootSsh).toBeDefined()
    })

    test("appends to sessions array with deduplication by id", () => {
      const existing = {
        sessions: [{ id: "shell-1", user: "www-data" }],
      }
      const updates = {
        sessions: [
          { id: "shell-1", privileged: true }, // Update existing
          { id: "shell-2", user: "root" }, // New session
        ],
      }
      const result = mergeState(existing, updates)

      expect(result.sessions?.length).toBe(2)
      const shell1 = result.sessions?.find((s) => s.id === "shell-1")
      expect(shell1?.user).toBe("www-data")
      expect(shell1?.privileged).toBe(true)
    })

    test("deduplicates flags as a set", () => {
      const existing = { flags: ["flag1", "flag2"] }
      const updates = { flags: ["flag2", "flag3"] }
      const result = mergeState(existing, updates)

      expect(result.flags?.length).toBe(3)
      expect(result.flags).toContain("flag1")
      expect(result.flags).toContain("flag2")
      expect(result.flags).toContain("flag3")
    })

    test("appends to failedAttempts without deduplication", () => {
      const existing = {
        failedAttempts: [{ action: "SSH brute force", reason: "No password" }],
      }
      const updates = {
        failedAttempts: [{ action: "SQL injection", reason: "Input sanitized" }],
      }
      const result = mergeState(existing, updates)

      expect(result.failedAttempts?.length).toBe(2)
    })

    test("appends to vulnerabilities without deduplication", () => {
      const existing = {
        vulnerabilities: [{ name: "SQLi", severity: "high" as const }],
      }
      const updates = {
        vulnerabilities: [{ name: "XSS", severity: "medium" as const }],
      }
      const result = mergeState(existing, updates)

      expect(result.vulnerabilities?.length).toBe(2)
    })

    test("handles empty existing state", () => {
      const existing = {}
      const updates = {
        target: { ip: "10.10.10.1" },
        ports: [{ port: 22, protocol: "tcp" as const }],
        accessLevel: "none" as const,
      }
      const result = mergeState(existing, updates)

      expect(result.target?.ip).toBe("10.10.10.1")
      expect(result.ports?.length).toBe(1)
      expect(result.accessLevel).toBe("none")
    })

    test("ignores null and undefined values", () => {
      const existing = { accessLevel: "user" as const }
      const updates = { accessLevel: undefined, target: null } as any
      const result = mergeState(existing, updates)

      expect(result.accessLevel).toBe("user")
      expect(result.target).toBeUndefined()
    })
  })

  describe("objective and currentPhase", () => {
    test("objective is set and replaced on update", () => {
      const result = mergeState(
        { objective: "get root on target.htb" },
        { objective: "lateral movement to DC" },
      )
      expect(result.objective).toBe("lateral movement to DC")
    })

    test("currentPhase is set and replaced on update", () => {
      const result = mergeState(
        { currentPhase: "recon" },
        { currentPhase: "enumeration" },
      )
      expect(result.currentPhase).toBe("enumeration")
    })

    test("objective survives unrelated updates", () => {
      const result = mergeState(
        { objective: "get root on target.htb", accessLevel: "none" },
        { accessLevel: "user" },
      )
      expect(result.objective).toBe("get root on target.htb")
      expect(result.accessLevel).toBe("user")
    })
  })
})

// =============================================================================
// execute() Tests — through createUpdate/ReadEngagementStateTool
// =============================================================================

const updateTool = createUpdateEngagementStateTool()
const readTool = createReadEngagementStateTool()

/** Build a minimal ToolContext for testing. Captures metadata calls. */
function makeContext(sessionId = "test-exec-session") {
  const metadataCalls: Array<{ title?: string; metadata?: Record<string, any> }> = []
  const ctx: ToolContext = {
    sessionID: sessionId,
    messageID: "test-msg",
    agent: "pentest",
    directory: "/tmp",
    worktree: "/tmp",
    abort: new AbortController().signal,
    metadata: (input) => {
      metadataCalls.push(input)
    },
    ask: async () => {},
  }
  return { ctx, metadataCalls }
}

// ---------------------------------------------------------------------------
// update_engagement_state execute tests
// ---------------------------------------------------------------------------

describe("update_engagement_state execute", () => {
  const sessionID = "test-update-exec-001"

  afterEach(() => {
    SessionDirectory.cleanup(sessionID)
  })

  test("returns 'Engagement State Updated' with port count", async () => {
    const { ctx, metadataCalls } = makeContext(sessionID)

    const result = await updateTool.execute(
      {
        ports: [
          { port: 22, protocol: "tcp", service: "ssh" },
          { port: 80, protocol: "tcp", service: "http" },
        ],
      },
      ctx,
    )

    expect(result).toContain("Engagement State Updated")
    expect(result).toContain("Ports: 2 discovered")
  })

  test("merges and deduplicates ports through execute", async () => {
    const { ctx } = makeContext(sessionID)

    // First call: two ports
    await updateTool.execute(
      {
        ports: [
          { port: 22, protocol: "tcp", service: "ssh" },
          { port: 80, protocol: "tcp", service: "http" },
        ],
      },
      ctx,
    )

    // Second call: one overlap (port 22 with version), one new (443)
    const { ctx: ctx2 } = makeContext(sessionID)
    const result = await updateTool.execute(
      {
        ports: [
          { port: 22, protocol: "tcp", version: "OpenSSH 8.2p1" },
          { port: 443, protocol: "tcp", service: "https" },
        ],
      },
      ctx2,
    )

    expect(result).toContain("Ports: 3 discovered")

    // Verify the merged state on disk
    const state = await loadEngagementState(sessionID)
    expect(state.ports?.length).toBe(3)
    const port22 = state.ports?.find((p) => p.port === 22)
    expect(port22?.service).toBe("ssh")
    expect(port22?.version).toBe("OpenSSH 8.2p1")
  })

  test("accessLevel appears in output", async () => {
    const { ctx } = makeContext(sessionID)

    const result = await updateTool.execute(
      { accessLevel: "user" },
      ctx,
    )

    expect(result).toContain("Access Level: user")
  })

  test("resetToolFailures produces CLEARED in output", async () => {
    const { ctx } = makeContext(sessionID)

    const result = await updateTool.execute(
      { resetToolFailures: true },
      ctx,
    )

    expect(result).toContain("CLEARED")
  })

  test("emits metadata with title summary and state counts", async () => {
    const { ctx, metadataCalls } = makeContext(sessionID)

    await updateTool.execute(
      {
        target: { ip: "10.10.10.50" },
        ports: [{ port: 22, protocol: "tcp" }],
        accessLevel: "none",
      },
      ctx,
    )

    expect(metadataCalls).toHaveLength(1)
    const meta = metadataCalls[0]
    expect(meta.title).toContain("update_engagement_state")
    expect(meta.title).toContain("target: 10.10.10.50")
    expect(meta.title).toContain("ports: +1")
    expect(meta.metadata?.state?.ports).toBe(1)
    expect(meta.metadata?.state?.accessLevel).toBe("none")
  })

  test("state file is written to session directory", async () => {
    const { ctx } = makeContext(sessionID)

    await updateTool.execute(
      {
        target: { ip: "10.10.10.99", hostname: "box.htb" },
        ports: [{ port: 8080, protocol: "tcp", service: "http-proxy" }],
      },
      ctx,
    )

    // Read the state file directly from disk
    const statePath = SessionDirectory.statePath(sessionID)
    const raw = readFileSync(statePath, "utf-8")
    const onDisk = yaml.load(raw) as any

    expect(onDisk.target.ip).toBe("10.10.10.99")
    expect(onDisk.target.hostname).toBe("box.htb")
    expect(onDisk.ports).toHaveLength(1)
    expect(onDisk.ports[0].port).toBe(8080)
  })
})

// ---------------------------------------------------------------------------
// read_engagement_state execute tests
// ---------------------------------------------------------------------------

describe("read_engagement_state execute", () => {
  const sessionID = "test-read-exec-001"

  afterEach(() => {
    SessionDirectory.cleanup(sessionID)
  })

  test("returns 'No engagement state found' on empty session", async () => {
    const { ctx, metadataCalls } = makeContext(sessionID)

    const result = await readTool.execute({}, ctx)

    expect(result).toContain("No engagement state found")
    expect(metadataCalls).toHaveLength(1)
    expect(metadataCalls[0].metadata?.empty).toBe(true)
  })

  test("returns YAML output after state is written", async () => {
    // Write state via update tool
    const { ctx: updateCtx } = makeContext(sessionID)
    await updateTool.execute(
      {
        target: { ip: "10.10.10.77", hostname: "yaml-test.htb" },
        ports: [{ port: 3306, protocol: "tcp", service: "mysql" }],
        accessLevel: "user",
      },
      updateCtx,
    )

    // Read it back
    const { ctx: readCtx, metadataCalls } = makeContext(sessionID)
    const result = await readTool.execute({}, readCtx)

    expect(result).toContain("Current Engagement State")
    expect(result).toContain("```yaml")
    expect(result).toContain("10.10.10.77")
    expect(result).toContain("yaml-test.htb")
    expect(result).toContain("3306")
    expect(result).toContain("mysql")
    expect(result).toContain("user")
  })

  test("emits metadata with target and counts", async () => {
    // Write state first
    const { ctx: updateCtx } = makeContext(sessionID)
    await updateTool.execute(
      {
        target: { ip: "10.10.10.88" },
        credentials: [{ username: "admin", password: "secret", service: "ssh" }],
      },
      updateCtx,
    )

    // Read and check metadata
    const { ctx: readCtx, metadataCalls } = makeContext(sessionID)
    await readTool.execute({}, readCtx)

    expect(metadataCalls).toHaveLength(1)
    const meta = metadataCalls[0]
    expect(meta.title).toContain("10.10.10.88")
    expect(meta.metadata?.empty).toBe(false)
    expect(meta.metadata?.target).toBe("10.10.10.88")
    expect(meta.metadata?.credentials).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// Cross-tool integration tests
// ---------------------------------------------------------------------------

describe("engagement-state cross-tool integration", () => {
  const sessionID = "test-cross-tool-001"

  afterEach(() => {
    SessionDirectory.cleanup(sessionID)
    SessionDirectory.cleanup("test-cross-root-001")
  })

  test("update then read returns what was written", async () => {
    // Update
    const { ctx: updateCtx } = makeContext(sessionID)
    await updateTool.execute(
      {
        target: { ip: "10.10.10.42" },
        ports: [
          { port: 22, protocol: "tcp", service: "ssh" },
          { port: 80, protocol: "tcp", service: "http" },
        ],
        accessLevel: "none",
        flags: ["HTB{test_flag_123}"],
      },
      updateCtx,
    )

    // Read
    const { ctx: readCtx } = makeContext(sessionID)
    const result = await readTool.execute({}, readCtx)

    expect(result).toContain("10.10.10.42")
    expect(result).toContain("ssh")
    expect(result).toContain("http")
    expect(result).toContain("none")
    expect(result).toContain("HTB{test_flag_123}")
  })

  test("two sessions sharing a root session see the same state", async () => {
    const rootID = "test-cross-root-001"
    const childA = "test-cross-child-a"
    const childB = "test-cross-child-b"

    // Register both children under the same root
    registerRootSession(childA, rootID)
    registerRootSession(childB, rootID)

    // Child A writes ports
    const { ctx: ctxA } = makeContext(childA)
    await updateTool.execute(
      {
        target: { ip: "10.10.10.55" },
        ports: [{ port: 22, protocol: "tcp", service: "ssh" }],
      },
      ctxA,
    )

    // Child B writes credentials
    const { ctx: ctxB } = makeContext(childB)
    await updateTool.execute(
      {
        credentials: [{ username: "admin", password: "pass123", service: "ssh" }],
      },
      ctxB,
    )

    // Read from child A — should see both ports and credentials
    const { ctx: readCtxA } = makeContext(childA)
    const resultA = await readTool.execute({}, readCtxA)

    expect(resultA).toContain("10.10.10.55")
    expect(resultA).toContain("ssh")
    expect(resultA).toContain("admin")
    expect(resultA).toContain("pass123")

    // Read from child B — should see the same data
    const { ctx: readCtxB } = makeContext(childB)
    const resultB = await readTool.execute({}, readCtxB)

    expect(resultB).toContain("10.10.10.55")
    expect(resultB).toContain("admin")
  })
})
