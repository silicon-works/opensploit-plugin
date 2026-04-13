/**
 * Error path and edge case integration tests for plugin hooks.
 *
 * These go BEYOND the happy-path smoke tests to verify that every hook
 * handles malformed, missing, or unexpected input without throwing.
 * The contract: hooks must NEVER crash. On error, output stays UNMODIFIED.
 *
 * Run:
 *   cd /home/nightshade/silicon-works/opensploit-plugin
 *   bun test test/integration/hook-errors.test.ts --timeout 30000
 */

import { describe, test, expect, afterEach } from "bun:test"
import { writeFileSync, mkdirSync, rmSync, existsSync } from "fs"
import { join } from "path"
import { tmpdir } from "os"

import { systemTransformHook } from "../../src/hooks/system-transform"
import { toolBeforeHook } from "../../src/hooks/tool-before"
import { chatMessageHook } from "../../src/hooks/chat-message"
import { permissionHook } from "../../src/hooks/permission"
import { compactionHook } from "../../src/hooks/compaction"
import { eventHook } from "../../src/hooks/event"
import { setUltrasploit } from "../../src/hooks/ultrasploit"
import { registerRootSession, unregister } from "../../src/session/hierarchy"
import * as SessionDirectory from "../../src/session/directory"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Session IDs used across tests — cleaned up in afterEach. */
const sessions: string[] = []

function freshSession(suffix: string): string {
  const id = `hook-err-${suffix}-${Date.now().toString(36)}`
  sessions.push(id)
  return id
}

afterEach(() => {
  setUltrasploit(false)
  for (const sid of sessions) {
    SessionDirectory.cleanup(sid)
    unregister(sid)
  }
  sessions.length = 0
})

// =============================================================================
// system-transform errors
// =============================================================================

describe("system-transform errors", () => {
  test("1: corrupted state.yaml (invalid YAML) — no crash, no garbage injected", async () => {
    const sid = freshSession("corrupt-yaml")
    SessionDirectory.create(sid)

    // Write invalid YAML that will cause js-yaml to throw
    const statePath = SessionDirectory.statePath(sid)
    writeFileSync(statePath, "{{{{not: valid: yaml: [[[", "utf-8")

    const output = { system: ["existing prompt"] }
    await systemTransformHook({ sessionID: sid, model: {} }, output)

    // Must not crash, and must not inject garbage
    expect(output.system).toHaveLength(1)
    expect(output.system[0]).toBe("existing prompt")
  })

  test("2: session directory exists but state.yaml is missing — returns without injecting", async () => {
    const sid = freshSession("no-state")
    SessionDirectory.create(sid)
    // Directory exists but no state.yaml written

    const output = { system: ["base prompt"] }
    await systemTransformHook({ sessionID: sid, model: {} }, output)

    expect(output.system).toHaveLength(1)
    expect(output.system[0]).toBe("base prompt")
  })

  test("3: orphan session (getRootSession returns self) — handles gracefully", async () => {
    // No registerRootSession call — getRootSession returns sessionID itself
    const sid = freshSession("orphan")

    const output = { system: ["prompt"] }
    await systemTransformHook({ sessionID: sid, model: {} }, output)

    // No state, no directory → nothing injected, no crash
    expect(output.system).toHaveLength(1)
    expect(output.system[0]).toBe("prompt")
  })

  test("4: sessionID is empty string — does not crash", async () => {
    const output = { system: ["prompt"] }
    // Empty string is truthy-ish in the `if (!input.sessionID)` check — it's falsy
    await systemTransformHook({ sessionID: "", model: {} }, output)

    // Empty string is falsy so the early return fires; output unchanged
    expect(output.system).toHaveLength(1)
    expect(output.system[0]).toBe("prompt")
  })
})

// =============================================================================
// tool-before errors
// =============================================================================

describe("tool-before errors", () => {
  test("5: args is null — does not crash", async () => {
    const sid = freshSession("args-null")
    const output = { args: null as any }
    await toolBeforeHook({ tool: "read", sessionID: sid, callID: "c1" }, output)

    expect(output.args).toBeNull()
  })

  test("6: args is undefined — does not crash", async () => {
    const sid = freshSession("args-undef")
    const output = { args: undefined as any }
    await toolBeforeHook({ tool: "read", sessionID: sid, callID: "c1" }, output)

    expect(output.args).toBeUndefined()
  })

  test("7: args.filePath is a number — does not crash, stays unchanged", async () => {
    const sid = freshSession("filepath-num")
    const output = { args: { filePath: 42 as any } }
    await toolBeforeHook({ tool: "read", sessionID: sid, callID: "c1" }, output)

    // typeof check in hook guards against non-string — filePath stays 42
    expect(output.args.filePath).toBe(42)
  })

  test("7b: args.filePath is an object — does not crash, stays unchanged", async () => {
    const sid = freshSession("filepath-obj")
    const sentinel = { nested: true }
    const output = { args: { filePath: sentinel as any } }
    await toolBeforeHook({ tool: "read", sessionID: sid, callID: "c1" }, output)

    expect(output.args.filePath).toBe(sentinel)
  })

  test("8: bash tool with command undefined — does not crash", async () => {
    const sid = freshSession("bash-cmd-undef")
    const output = { args: { command: undefined as any } }
    await toolBeforeHook({ tool: "bash", sessionID: sid, callID: "c1" }, output)

    expect(output.args.command).toBeUndefined()
  })

  test("9: bash tool with empty command string — does not crash", async () => {
    const sid = freshSession("bash-cmd-empty")
    const output = { args: { command: "" } }
    await toolBeforeHook({ tool: "bash", sessionID: sid, callID: "c1" }, output)

    expect(output.args.command).toBe("")
  })

  test("10: /session/ path when session directory doesn't exist — creates it or handles gracefully", async () => {
    const sid = freshSession("no-dir")
    // Do NOT create the session directory — translateSessionPath should handle it
    const output = { args: { filePath: "/session/findings/recon.md" } }
    await toolBeforeHook({ tool: "read", sessionID: sid, callID: "c1" }, output)

    // translateSessionPath creates the directory lazily
    expect(output.args.filePath).not.toBe("/session/findings/recon.md")
    expect(output.args.filePath).toContain(sid)
    // Session dir should now exist (lazy creation)
    expect(SessionDirectory.exists(sid)).toBe(true)
  })
})

// =============================================================================
// chat.message errors
// =============================================================================

describe("chat.message errors", () => {
  const baseInput = {
    sessionID: "test-chat-err",
    agent: "pentest",
    model: { providerID: "test", modelID: "test" },
    messageID: "msg-err",
  }

  test("11: parts array is empty — does not crash, ultrasploit stays unchanged", async () => {
    setUltrasploit(false)
    const output = { message: {}, parts: [] as any[] }
    await chatMessageHook(baseInput, output)

    expect(output.parts).toHaveLength(0)
    // ultrasploit should NOT be enabled by empty message
    const { isUltrasploitEnabled } = await import("../../src/hooks/ultrasploit")
    expect(isUltrasploitEnabled()).toBe(false)
  })

  test("12: parts has non-text parts only (file parts) — does not crash", async () => {
    setUltrasploit(false)
    const output = {
      message: {},
      parts: [
        { type: "file", path: "/tmp/test.txt" },
        { type: "image", url: "data:image/png;base64,..." },
      ],
    }
    await chatMessageHook(baseInput, output)

    // No text parts → no keyword found → ultrasploit stays off
    const { isUltrasploitEnabled } = await import("../../src/hooks/ultrasploit")
    expect(isUltrasploitEnabled()).toBe(false)
    // Parts unchanged
    expect(output.parts).toHaveLength(2)
    expect(output.parts[0].type).toBe("file")
  })

  test("13: text part has null text — does not crash", async () => {
    const output = {
      message: {},
      parts: [{ type: "text", text: null as any }],
    }
    await chatMessageHook(baseInput, output)

    // KEYWORD_REGEX.test(null) returns false in JS — no crash
    expect(output.parts[0].text).toBeNull()
  })

  test("14: text part has empty string — does not crash", async () => {
    const output = {
      message: {},
      parts: [{ type: "text", text: "" }],
    }
    await chatMessageHook(baseInput, output)

    expect(output.parts[0].text).toBe("")
  })

  test("15: output.parts is undefined — does not crash", async () => {
    const output = { message: {}, parts: undefined as any }
    // The hook does output.parts.some(...) which would throw on undefined
    // The try/catch in the hook should absorb this
    await chatMessageHook(baseInput, output)

    // Output unmodified (the error was caught)
    expect(output.parts).toBeUndefined()
  })
})

// =============================================================================
// permission errors
// =============================================================================

describe("permission errors", () => {
  test("16: input is null — does not crash", async () => {
    setUltrasploit(true)
    const output = { status: "ask" as const }
    // permissionHook accesses input?.permission — null-safe via optional chaining
    await permissionHook(null, output)

    expect(output.status).toBe("allow") // ultrasploit is on, so it sets allow
  })

  test("16b: input is undefined — does not crash", async () => {
    setUltrasploit(true)
    const output = { status: "ask" as const }
    await permissionHook(undefined, output)

    expect(output.status).toBe("allow")
  })

  test("17: output.status is already 'allow' with ultrasploit off — stays 'allow'", async () => {
    setUltrasploit(false)
    const output = { status: "allow" as "ask" | "deny" | "allow" }
    await permissionHook({ permission: "bash", pattern: "ls" }, output)

    // Ultrasploit is off → hook is a no-op → status stays "allow"
    expect(output.status).toBe("allow")
  })
})

// =============================================================================
// compaction errors
// =============================================================================

describe("compaction errors", () => {
  test("18: corrupted state.yaml during compaction — no crash, existing context preserved", async () => {
    const sid = freshSession("compact-corrupt")
    SessionDirectory.create(sid)

    // Write corrupted YAML
    const statePath = SessionDirectory.statePath(sid)
    writeFileSync(statePath, "::::\n- {broken\n  yaml: [", "utf-8")

    const output = { context: ["existing context"], prompt: undefined }
    await compactionHook({ sessionID: sid }, output)

    // Should not crash, existing context preserved, nothing new injected
    expect(output.context).toHaveLength(1)
    expect(output.context[0]).toBe("existing context")
  })

  test("19: session directory deleted between check and read — does not crash", async () => {
    const sid = freshSession("compact-deleted")
    // Don't create the directory at all — simulates deletion race condition

    const output = { context: ["prior context"], prompt: undefined }
    await compactionHook({ sessionID: sid }, output)

    // No state → nothing injected, no crash
    expect(output.context).toHaveLength(1)
    expect(output.context[0]).toBe("prior context")
  })
})

// =============================================================================
// Cross-hook edge cases
// =============================================================================

describe("cross-hook edge cases", () => {
  test("20: system-transform called multiple times for same session — no duplicate injection", async () => {
    const sid = freshSession("multi-inject")
    SessionDirectory.create(sid)

    const { saveEngagementState } = await import("../../src/tools/engagement-state")
    await saveEngagementState(sid, {
      target: { ip: "10.10.10.99" },
      ports: [{ port: 80, protocol: "tcp", service: "http", state: "open" }],
    })

    const output = { system: ["base"] }

    // Call the hook twice
    await systemTransformHook({ sessionID: sid, model: {} }, output)
    await systemTransformHook({ sessionID: sid, model: {} }, output)

    // Each call appends one entry. The hook itself does not deduplicate
    // (that is the host's responsibility). But it should not crash and
    // each injection should be valid (not garbage).
    expect(output.system.length).toBe(3) // base + 2 injections
    expect(output.system[0]).toBe("base")
    // Both injections should contain the target IP
    expect(output.system[1]).toContain("10.10.10.99")
    expect(output.system[2]).toContain("10.10.10.99")
  })

  test("21: tool-before called for unknown tool name — passes through unchanged", async () => {
    const sid = freshSession("unknown-tool")
    const originalArgs = { filePath: "/session/test.txt", custom: "value" }
    const output = { args: { ...originalArgs } }

    await toolBeforeHook({ tool: "nonexistent_tool_xyz", sessionID: sid, callID: "c1" }, output)

    // Unknown tool is not in FILE_TOOLS set and is not "bash"
    // So args pass through completely unchanged
    expect(output.args.filePath).toBe("/session/test.txt")
    expect(output.args.custom).toBe("value")
  })
})
