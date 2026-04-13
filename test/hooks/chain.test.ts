import { describe, test, expect, afterEach } from "bun:test"
import { systemTransformHook } from "../../src/hooks/system-transform"
import { toolBeforeHook } from "../../src/hooks/tool-before"
import { compactionHook } from "../../src/hooks/compaction"
import { permissionHook } from "../../src/hooks/permission"
import { setUltrasploit } from "../../src/hooks/ultrasploit"
import { registerRootSession, unregister } from "../../src/session/hierarchy"
import * as SessionDirectory from "../../src/session/directory"
import { saveEngagementState } from "../../src/tools/engagement-state"

/**
 * Integration test: hooks working together in a realistic pen test scenario.
 *
 * Simulates a multi-phase engagement (recon → enum → compaction → post)
 * using real file I/O and the actual hook functions. No mocks. Each step
 * builds on the previous to verify hooks cooperate correctly.
 */

const ROOT = "test-chain-root-" + Date.now().toString(36)
const CHILD = "test-chain-child-" + Date.now().toString(36)

afterEach(() => {
  SessionDirectory.cleanup(ROOT)
  unregister(CHILD)
  unregister(ROOT)
  setUltrasploit(false)
})

describe("hook chain: multi-phase pen test with compaction", () => {

  test("full scenario", async () => {
    // -------------------------------------------------------------------------
    // Step 1: Setup — create root session, register child
    // -------------------------------------------------------------------------
    SessionDirectory.create(ROOT)
    registerRootSession(CHILD, ROOT)

    const rootDir = SessionDirectory.get(ROOT)
    expect(SessionDirectory.exists(ROOT)).toBe(true)
    expect(rootDir).toContain("opensploit-session-")

    // -------------------------------------------------------------------------
    // Step 2: Recon phase — save engagement state with discovered ports
    // -------------------------------------------------------------------------
    await saveEngagementState(ROOT, {
      target: { ip: "10.10.11.42", hostname: "bizdev.htb" },
      ports: [
        { port: 22, protocol: "tcp", service: "ssh", version: "OpenSSH 8.9p1", state: "open" },
        { port: 80, protocol: "tcp", service: "http", version: "Apache 2.4.52", state: "open" },
        { port: 3306, protocol: "tcp", service: "mysql", state: "filtered" },
      ],
      accessLevel: "none",
    })

    // -------------------------------------------------------------------------
    // Step 3: Verify system-transform — ports appear in system prompt
    // -------------------------------------------------------------------------
    const systemOut1 = { system: ["You are a penetration testing agent."] }
    await systemTransformHook({ sessionID: CHILD, model: {} }, systemOut1)

    // Child session should get root's state (hierarchy resolution)
    expect(systemOut1.system.length).toBeGreaterThan(1)
    const injected1 = systemOut1.system.slice(1).join("\n")

    // Port accessibility summary
    expect(injected1).toContain("OPEN")
    expect(injected1).toContain("22/tcp (ssh)")
    expect(injected1).toContain("80/tcp (http)")
    expect(injected1).toContain("FILTERED")
    expect(injected1).toContain("3306/tcp")

    // Session directory path
    expect(injected1).toContain("Session Working Directory")
    expect(injected1).toContain(rootDir)

    // YAML state dump
    expect(injected1).toContain("10.10.11.42")
    expect(injected1).toContain("bizdev.htb")
    expect(injected1).toContain("OpenSSH 8.9p1")

    // Original prompt preserved
    expect(systemOut1.system[0]).toBe("You are a penetration testing agent.")

    // -------------------------------------------------------------------------
    // Step 4: Path rewriting — read tool with /session/ path
    // -------------------------------------------------------------------------
    const readOutput = { args: { filePath: "/session/state.yaml" } }
    await toolBeforeHook({ tool: "read", sessionID: CHILD, callID: "call-1" }, readOutput)

    // Should resolve to root's session dir (child → root hierarchy)
    expect(readOutput.args.filePath).toBe(`${rootDir}/state.yaml`)
    expect(readOutput.args.filePath).not.toContain("/session/")

    // -------------------------------------------------------------------------
    // Step 5: Bash path rewriting — cat with /session/ path
    // -------------------------------------------------------------------------
    const bashOutput = { args: { command: "cat /session/findings/recon.md" } }
    await toolBeforeHook({ tool: "bash", sessionID: CHILD, callID: "call-2" }, bashOutput)

    expect(bashOutput.args.command).toBe(`cat ${rootDir}/findings/recon.md`)
    expect(bashOutput.args.command).not.toContain("/session/")

    // -------------------------------------------------------------------------
    // Step 6: Enum phase — update engagement state with credentials
    // -------------------------------------------------------------------------
    const { loadEngagementState, mergeState } = await import("../../src/tools/engagement-state")
    const currentState = await loadEngagementState(ROOT)
    const enumUpdates = {
      credentials: [
        { username: "webadmin", password: "P@ssw0rd2026!", service: "mysql", validated: true },
        { username: "root", hash: "5f4dcc3b5aa765d61d8327deb882cf99", service: "mysql" },
      ],
      vulnerabilities: [
        { name: "SQL Injection in login form", severity: "critical" as const, service: "http", port: 80, exploitable: true },
      ],
      accessLevel: "user" as const,
    }
    const merged = mergeState(currentState, enumUpdates)
    await saveEngagementState(ROOT, merged)

    // -------------------------------------------------------------------------
    // Step 7: Verify system-transform again — shows BOTH ports AND credentials
    // -------------------------------------------------------------------------
    const systemOut2 = { system: [] as string[] }
    await systemTransformHook({ sessionID: ROOT, model: {} }, systemOut2)

    expect(systemOut2.system.length).toBeGreaterThan(0)
    const injected2 = systemOut2.system.join("\n")

    // Ports from recon still present
    expect(injected2).toContain("22/tcp (ssh)")
    expect(injected2).toContain("80/tcp (http)")

    // New credentials from enum
    expect(injected2).toContain("webadmin")
    expect(injected2).toContain("P@ssw0rd2026!")

    // Vulnerability
    expect(injected2).toContain("SQL Injection")

    // Updated access level
    expect(injected2).toContain("user")

    // -------------------------------------------------------------------------
    // Step 8: Compaction — engagement state survives context trimming
    // -------------------------------------------------------------------------
    const compactOut = { context: ["You found a login page."] as string[], prompt: undefined as string | undefined }
    await compactionHook({ sessionID: CHILD }, compactOut)

    // Original context preserved
    expect(compactOut.context[0]).toBe("You found a login page.")

    // Engagement state injected with preservation directive
    expect(compactOut.context.length).toBe(2)
    const compactionInjected = compactOut.context[1]
    expect(compactionInjected).toContain("CRITICAL")
    expect(compactionInjected).toContain("PRESERVE")

    // Contains the full state — ports, creds, vulns
    expect(compactionInjected).toContain("10.10.11.42")
    expect(compactionInjected).toContain("22")
    expect(compactionInjected).toContain("webadmin")
    expect(compactionInjected).toContain("SQL Injection")

    // -------------------------------------------------------------------------
    // Step 9: Post-compaction — system-transform still works (reads from disk)
    // -------------------------------------------------------------------------
    // After compaction, a fresh system-transform should still inject state
    // because it reads from the state.yaml file, not from in-memory cache.
    const systemOut3 = { system: ["Post-compaction prompt."] }
    await systemTransformHook({ sessionID: ROOT, model: {} }, systemOut3)

    expect(systemOut3.system.length).toBeGreaterThan(1)
    const injected3 = systemOut3.system.slice(1).join("\n")

    // All accumulated state still present
    expect(injected3).toContain("10.10.11.42")
    expect(injected3).toContain("bizdev.htb")
    expect(injected3).toContain("webadmin")
    expect(injected3).toContain("SQL Injection")
    expect(injected3).toContain("22/tcp (ssh)")

    // -------------------------------------------------------------------------
    // Step 10: Ultrasploit — permission hook auto-approves
    // -------------------------------------------------------------------------
    // Before enabling: permission stays as "ask"
    const permOut1 = { status: "ask" as "ask" | "deny" | "allow" }
    await permissionHook({ permission: "bash", pattern: "nmap -sV 10.10.11.42" }, permOut1)
    expect(permOut1.status).toBe("ask")

    // Enable ultrasploit
    setUltrasploit(true)

    // After enabling: permission auto-approved
    const permOut2 = { status: "ask" as "ask" | "deny" | "allow" }
    await permissionHook({ permission: "bash", pattern: "nmap -sV 10.10.11.42" }, permOut2)
    expect(permOut2.status).toBe("allow")

    // Even "deny" gets overridden
    const permOut3 = { status: "deny" as "ask" | "deny" | "allow" }
    await permissionHook({ permission: "mcp_tool", pattern: "sqlmap.test_injection" }, permOut3)
    expect(permOut3.status).toBe("allow")
  })
})
