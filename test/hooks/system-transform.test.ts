import { describe, test, expect, afterEach } from "bun:test"
import { systemTransformHook } from "../../src/hooks/system-transform"
import { registerRootSession, unregister } from "../../src/session/hierarchy"
import * as SessionDirectory from "../../src/session/directory"
import { saveEngagementState } from "../../src/tools/engagement-state"

/**
 * Tests for the experimental.chat.system.transform hook.
 *
 * This hook injects engagement state into every agent's system prompt.
 * We test with real session directories and engagement state files.
 */

const ROOT_SESSION = "test-systransform-root"
const CHILD_SESSION = "test-systransform-child"

afterEach(async () => {
  SessionDirectory.cleanup(ROOT_SESSION)
  unregister(CHILD_SESSION)
  unregister(ROOT_SESSION)
})

describe("hook.system-transform", () => {
  test("does nothing when no sessionID provided", async () => {
    const output = { system: ["existing prompt"] }
    await systemTransformHook({ sessionID: undefined, model: {} }, output)
    expect(output.system).toHaveLength(1)
    expect(output.system[0]).toBe("existing prompt")
  })

  test("does nothing when no engagement state exists", async () => {
    const output = { system: ["existing prompt"] }
    await systemTransformHook({ sessionID: ROOT_SESSION, model: {} }, output)
    // No state file, no injection
    expect(output.system).toHaveLength(1)
  })

  test("injects engagement state when state exists", async () => {
    // Set up session directory and state
    SessionDirectory.create(ROOT_SESSION)
    await saveEngagementState(ROOT_SESSION, {
      target: { ip: "10.10.10.1", hostname: "target.htb" },
      ports: [
        { port: 22, protocol: "tcp", service: "ssh", state: "open" },
        { port: 80, protocol: "tcp", service: "http", state: "open" },
      ],
      accessLevel: "none",
    })

    const output = { system: ["existing prompt"] }
    await systemTransformHook({ sessionID: ROOT_SESSION, model: {} }, output)

    // Should have added to system array
    expect(output.system.length).toBeGreaterThan(1)

    // The injected content should contain engagement state
    const injected = output.system.slice(1).join("\n")
    expect(injected).toContain("10.10.10.1")
    expect(injected).toContain("22")
    expect(injected).toContain("ssh")
    expect(injected).toContain("80")
  })

  test("injects session directory path", async () => {
    SessionDirectory.create(ROOT_SESSION)
    await saveEngagementState(ROOT_SESSION, {
      target: { ip: "10.10.10.1" },
    })

    const output = { system: ["existing prompt"] }
    await systemTransformHook({ sessionID: ROOT_SESSION, model: {} }, output)

    const injected = output.system.slice(1).join("\n")
    expect(injected).toContain("Session Working Directory")
    expect(injected).toContain("/tmp/opensploit-session-")
  })

  test("child session gets root session state", async () => {
    // Register child → root relationship
    registerRootSession(CHILD_SESSION, ROOT_SESSION)
    SessionDirectory.create(ROOT_SESSION)
    await saveEngagementState(ROOT_SESSION, {
      target: { ip: "10.10.10.5" },
      credentials: [
        { username: "admin", password: "secret123", service: "ssh" },
      ],
    })

    const output = { system: ["child prompt"] }
    await systemTransformHook({ sessionID: CHILD_SESSION, model: {} }, output)

    // Child should see root's state
    const injected = output.system.slice(1).join("\n")
    expect(injected).toContain("10.10.10.5")
    expect(injected).toContain("admin")
  })

  test("preserves existing system prompt entries", async () => {
    SessionDirectory.create(ROOT_SESSION)
    await saveEngagementState(ROOT_SESSION, {
      target: { ip: "10.10.10.1" },
    })

    const output = { system: ["first prompt", "second prompt"] }
    await systemTransformHook({ sessionID: ROOT_SESSION, model: {} }, output)

    // Original entries preserved
    expect(output.system[0]).toBe("first prompt")
    expect(output.system[1]).toBe("second prompt")
    // State appended
    expect(output.system.length).toBe(3)
  })

  test("includes attack plan when present", async () => {
    SessionDirectory.create(ROOT_SESSION)
    await saveEngagementState(ROOT_SESSION, {
      target: { ip: "10.10.10.1" },
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

    const output = { system: [] }
    await systemTransformHook({ sessionID: ROOT_SESSION, model: {} }, output)

    const injected = output.system.join("\n")
    expect(injected).toContain("Attack Plan")
    expect(injected).toContain("SQL injection")
    expect(injected).toContain("[x]") // completed
    expect(injected).toContain("[>]") // in_progress
    expect(injected).toContain("[ ]") // pending
  })

  test("includes broken tools warning", async () => {
    SessionDirectory.create(ROOT_SESSION)
    await saveEngagementState(ROOT_SESSION, {
      target: { ip: "10.10.10.1" },
      toolFailures: [
        { tool: "sqlmap", method: "test_injection", error: "connection timeout", count: 3, firstSeen: "2026-01-01", lastSeen: "2026-01-01" },
      ],
    })

    const output = { system: [] }
    await systemTransformHook({ sessionID: ROOT_SESSION, model: {} }, output)

    const injected = output.system.join("\n")
    expect(injected).toContain("BROKEN TOOLS")
    expect(injected).toContain("sqlmap")
  })

  test("includes port accessibility summary", async () => {
    SessionDirectory.create(ROOT_SESSION)
    await saveEngagementState(ROOT_SESSION, {
      target: { ip: "10.10.10.1" },
      ports: [
        { port: 22, protocol: "tcp", service: "ssh", state: "open" },
        { port: 445, protocol: "tcp", service: "smb", state: "filtered" },
      ],
    })

    const output = { system: [] }
    await systemTransformHook({ sessionID: ROOT_SESSION, model: {} }, output)

    const injected = output.system.join("\n")
    expect(injected).toContain("OPEN")
    expect(injected).toContain("22/tcp")
    expect(injected).toContain("FILTERED")
    expect(injected).toContain("445/tcp")
  })
})
