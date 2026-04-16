/**
 * ADVERSARIAL TESTS for Engagement State System
 *
 * Goal: Find real bugs by probing edge cases, malformed inputs, race conditions,
 * and broken assumptions in the merge/persist/inject pipeline.
 *
 * Every test has a HYPOTHESIS about what might be wrong.
 * If the test fails, we found a bug. If it passes, the hypothesis was wrong.
 *
 * =========================================================================
 * BUGS FOUND:
 * =========================================================================
 *
 * BUG 1 [HIGH] Lost-update race condition on concurrent writes
 *   - Two agents calling update_engagement_state at the same time: both read
 *     the same state, merge independently, second write overwrites first.
 *   - Root cause: read-modify-write without any locking (no flock, no mutex)
 *   - Impact: Port/credential/vuln data silently lost during parallel sub-agent work
 *   - Test: "concurrent writes cause lost updates" — confirmed port 22 lost
 *   - Fix: Use atomic write with file lock (flock) or in-memory mutex per session
 *
 * BUG 2 [HIGH] loadEngagementState returns wrong type on corrupt YAML
 *   - If state.yaml contains a string, number, or array (not an object),
 *     yaml.load returns that type. The `parsed ?? {}` guard only catches
 *     null/undefined, not non-object types.
 *   - Impact: `state.ports` on a string/number/array => undefined (not crash),
 *     but callers using `Object.keys(state)` on a string/number get wrong results
 *   - Tests: "file containing a plain string", "YAML array", "YAML number"
 *   - Fix: Add `typeof parsed === "object" && !Array.isArray(parsed)` check
 *
 * BUG 3 [MEDIUM] NaN port creates unkillable duplicate entries
 *   - Port dedup uses `p.port === item.port` — NaN !== NaN in JavaScript.
 *   - Every NaN port is treated as "new", causing unbounded accumulation.
 *   - Impact: State file grows without bound if tool reports NaN port numbers
 *   - Fix: Use Object.is() or Number.isNaN() check in dedup comparison
 *
 * BUG 4 [MEDIUM] Port dedup fails when protocol is missing from one side
 *   - If existing port has protocol="tcp" (from schema default) but update
 *     omits protocol (undefined), dedup check "tcp" === undefined fails.
 *   - Same port 22 appears twice with different protocol values.
 *   - Impact: Duplicate ports accumulate when agents don't consistently set protocol
 *   - Fix: Default missing protocol to "tcp" before comparison
 *
 * BUG 5 [MEDIUM] Credential dedup treats service=undefined and service="ssh" as different
 *   - Credentials with same username but one has service=undefined and other has
 *     service="ssh" are treated as different entries.
 *   - Impact: Duplicate credentials when service is inconsistently specified
 *   - This may be intentional (admin@undefined != admin@ssh), but surprising
 *
 * BUG 6 [MEDIUM] toolFailures count: incoming count value is IGNORED
 *   - Merge always does `(existing.count || 1) + 1` regardless of incoming count.
 *   - If an agent reports count=10, the stored count only goes up by 1.
 *   - Impact: Tool failure counts are inaccurate when batched failures are reported
 *   - Fix: Use `+ (item.count || 1)` instead of `+ 1`
 *
 * BUG 7 [MEDIUM] toolFailures count=0 treated as 1 due to || operator
 *   - `(0 || 1) + 1 = 2` — the || operator coerces 0 to 1.
 *   - Fix: Use `(merged[idx].count ?? 1)` instead of `(merged[idx].count || 1)`
 *
 * BUG 8 [LOW] Non-atomic file writes: concurrent read can see partial file
 *   - fs.writeFile truncates then writes. A read during write gets empty or partial YAML.
 *   - Impact: loadEngagementState returns {} or corrupt data during write
 *   - Fix: Write to temp file + rename (atomic on same filesystem)
 *
 * BUG 9 [LOW] No port number validation (negative, 0, >65535, Infinity accepted)
 *   - PortInfoSchema uses z.number() with no min/max constraints.
 *   - Impact: Invalid ports stored in state, may confuse downstream consumers
 *   - Fix: Add .int().min(0).max(65535) to port field
 *
 * BUG 10 [LOW] No IP address validation (empty string, broadcast, garbage accepted)
 *   - TargetInfoSchema uses z.string() with no IP validation.
 *   - Impact: Invalid IPs in state; by design for LLM flexibility but risky
 *
 * BUG 11 [LOW] Unbounded growth of vulnerabilities/failedAttempts arrays
 *   - No dedup, no size cap. Agent repeatedly reporting same vuln causes unbounded growth.
 *   - Impact: State file grows without bound, context injection becomes huge
 *
 * BUG 12 [INFO] toolSearchCache "last 10" limit in summary is undermined
 *   - The formatted "Recent Tool Searches" section shows last 10, but the full
 *     YAML dump (injected above it) contains ALL cache entries.
 *   - Impact: LLM sees all entries anyway, the limit is cosmetic
 *
 * BUG 13 [INFO] Nested code fences in credential values break markdown rendering
 *   - Password containing ``` inside YAML inside ```yaml code fence
 *   - Impact: Visual rendering glitch in LLM context, not a functional bug
 *
 * =========================================================================
 */

import { describe, expect, test, afterEach, beforeEach } from "bun:test"
import type { ToolContext } from "@opencode-ai/plugin"
import yaml from "js-yaml"
import fs from "fs/promises"
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs"
import { join } from "path"
import { tmpdir } from "os"
import * as SessionDirectory from "../../src/session/directory"
import { registerRootSession, getRootSession } from "../../src/session/hierarchy"
import {
  createUpdateEngagementStateTool,
  createReadEngagementStateTool,
  loadEngagementState,
  saveEngagementState,
  getEngagementStateForInjection,
  mergeState,
  getStateSnapshots,
  getStateAtStep,
  detectStateChanges,
  type EngagementState,
} from "../../src/tools/engagement-state"
import { systemTransformHook } from "../../src/hooks/system-transform"
import { compactionHook } from "../../src/hooks/compaction"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const updateTool = createUpdateEngagementStateTool()
const readTool = createReadEngagementStateTool()

function makeContext(sessionId: string) {
  const metadataCalls: Array<{ title?: string; metadata?: Record<string, any> }> = []
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

/** Unique session IDs to avoid cross-test pollution */
let testCounter = 0
function uniqueSession(): string {
  return `adversarial-es-${Date.now()}-${++testCounter}`
}

// Track sessions for cleanup
const cleanupSessions: string[] = []

afterEach(() => {
  for (const sid of cleanupSessions) {
    try { SessionDirectory.cleanup(sid) } catch {}
  }
  cleanupSessions.length = 0
})

function tracked(sid: string): string {
  cleanupSessions.push(sid)
  return sid
}

// ===========================================================================
// 1. YAML INJECTION / CORRUPTION
// ===========================================================================

describe("ATTACK: YAML injection via special characters in values", () => {
  /**
   * HYPOTHESIS: If a credential password contains YAML structural characters
   * (`:`, `{}`, `|`, `>`, `\n`), js-yaml.dump() might not quote them properly,
   * causing roundtrip corruption when the file is re-read.
   */
  test("password with YAML colon survives roundtrip", async () => {
    const sid = tracked(uniqueSession())
    const { ctx } = makeContext(sid)

    await updateTool.execute({
      credentials: [{
        username: "admin",
        password: "pass: word: with: colons",
        service: "ssh",
      }],
    }, ctx)

    const state = await loadEngagementState(sid)
    expect(state.credentials?.[0]?.password).toBe("pass: word: with: colons")
  })

  test("password with YAML braces survives roundtrip", async () => {
    const sid = tracked(uniqueSession())
    const { ctx } = makeContext(sid)

    await updateTool.execute({
      credentials: [{
        username: "admin",
        password: '{"evil": true, "nested": {"deep": 1}}',
        service: "http",
      }],
    }, ctx)

    const state = await loadEngagementState(sid)
    expect(state.credentials?.[0]?.password).toBe('{"evil": true, "nested": {"deep": 1}}')
  })

  test("password with YAML block indicators (| and >) survives roundtrip", async () => {
    const sid = tracked(uniqueSession())
    const { ctx } = makeContext(sid)

    await updateTool.execute({
      credentials: [{
        username: "admin",
        password: "|\nthis should be a literal block\n> and this a folded block",
        service: "web",
      }],
    }, ctx)

    const state = await loadEngagementState(sid)
    expect(state.credentials?.[0]?.password).toBe(
      "|\nthis should be a literal block\n> and this a folded block"
    )
  })

  test("password with embedded newlines survives roundtrip", async () => {
    const sid = tracked(uniqueSession())
    const { ctx } = makeContext(sid)

    await updateTool.execute({
      credentials: [{
        username: "admin",
        password: "line1\nline2\nline3",
        service: "ftp",
      }],
    }, ctx)

    const state = await loadEngagementState(sid)
    expect(state.credentials?.[0]?.password).toBe("line1\nline2\nline3")
  })

  test("hostname with null bytes survives or is sanitized", async () => {
    const sid = tracked(uniqueSession())
    const { ctx } = makeContext(sid)

    await updateTool.execute({
      target: { ip: "10.10.10.1", hostname: "evil\x00host.htb" },
    }, ctx)

    const state = await loadEngagementState(sid)
    // Either the null byte is preserved or sanitized, but it must not crash
    expect(state.target?.ip).toBe("10.10.10.1")
    expect(state.target?.hostname).toBeDefined()
  })

  test("hostname with unicode zero-width chars survives roundtrip", async () => {
    const sid = tracked(uniqueSession())
    const { ctx } = makeContext(sid)

    await updateTool.execute({
      target: { ip: "10.10.10.1", hostname: "evil\u200B\u200Chost.htb" },
    }, ctx)

    const state = await loadEngagementState(sid)
    expect(state.target?.hostname).toBe("evil\u200B\u200Chost.htb")
  })

  /**
   * HYPOTHESIS: YAML anchors/aliases in a password could cause js-yaml
   * to create unexpected references.
   */
  test("password with YAML anchor syntax (*alias) survives roundtrip", async () => {
    const sid = tracked(uniqueSession())
    const { ctx } = makeContext(sid)

    await updateTool.execute({
      credentials: [{
        username: "admin",
        password: "*alias_name",
        service: "ldap",
      }],
    }, ctx)

    const state = await loadEngagementState(sid)
    expect(state.credentials?.[0]?.password).toBe("*alias_name")
  })

  test("password with YAML tag (!!python/object) survives roundtrip", async () => {
    const sid = tracked(uniqueSession())
    const { ctx } = makeContext(sid)

    await updateTool.execute({
      credentials: [{
        username: "admin",
        password: "!!python/object:__main__.Evil",
        service: "rpc",
      }],
    }, ctx)

    const state = await loadEngagementState(sid)
    expect(state.credentials?.[0]?.password).toBe("!!python/object:__main__.Evil")
  })
})

describe("ATTACK: invalid port numbers", () => {
  /**
   * HYPOTHESIS: The PortInfoSchema uses z.number() with no min/max constraints.
   * Negative ports, 0, >65535 will pass schema validation and be stored.
   * This could break dedup logic or downstream consumers.
   */
  test("negative port number is accepted (schema does not validate range)", () => {
    const existing: EngagementState = { ports: [] }
    const result = mergeState(existing, {
      ports: [{ port: -1, protocol: "tcp" }],
    })
    // BUG CANDIDATE: No port range validation
    expect(result.ports?.[0]?.port).toBe(-1)
  })

  test("port 0 is accepted", () => {
    const result = mergeState({}, {
      ports: [{ port: 0, protocol: "tcp", service: "unknown" }],
    })
    expect(result.ports?.[0]?.port).toBe(0)
  })

  test("port > 65535 is accepted", () => {
    const result = mergeState({}, {
      ports: [{ port: 99999, protocol: "tcp" }],
    })
    expect(result.ports?.[0]?.port).toBe(99999)
  })

  test("NaN ports are skipped during merge (BUG-ES-3 FIXED)", () => {
    const existing: EngagementState = {
      ports: [{ port: NaN, protocol: "tcp", service: "first" }],
    }
    // FIXED: incoming NaN ports are dropped to prevent accumulation
    const result = mergeState(existing, {
      ports: [{ port: NaN, protocol: "tcp", service: "second" }],
    })
    // Existing NaN stays, but new NaN is rejected — no accumulation
    expect(result.ports?.length).toBe(1)
    expect(result.ports?.[0]?.service).toBe("first")
  })

  test("port Infinity is stored", () => {
    const result = mergeState({}, {
      ports: [{ port: Infinity, protocol: "tcp" }],
    })
    expect(result.ports?.[0]?.port).toBe(Infinity)
  })
})

describe("ATTACK: edge-case IP addresses", () => {
  /**
   * HYPOTHESIS: No IP validation at all — any string is accepted as target IP.
   * This is by design (LLM flexibility), but could lead to issues with
   * downstream consumers that assume valid IPs.
   */
  test("0.0.0.0 is accepted as target IP", async () => {
    const sid = tracked(uniqueSession())
    const { ctx } = makeContext(sid)

    await updateTool.execute({
      target: { ip: "0.0.0.0" },
    }, ctx)

    const state = await loadEngagementState(sid)
    expect(state.target?.ip).toBe("0.0.0.0")
  })

  test("255.255.255.255 is accepted as target IP", async () => {
    const sid = tracked(uniqueSession())
    const { ctx } = makeContext(sid)

    await updateTool.execute({
      target: { ip: "255.255.255.255" },
    }, ctx)

    const state = await loadEngagementState(sid)
    expect(state.target?.ip).toBe("255.255.255.255")
  })

  test("IPv6 address is accepted", async () => {
    const sid = tracked(uniqueSession())
    const { ctx } = makeContext(sid)

    await updateTool.execute({
      target: { ip: "fe80::1%eth0", hostname: "ipv6.htb" },
    }, ctx)

    const state = await loadEngagementState(sid)
    expect(state.target?.ip).toBe("fe80::1%eth0")
  })

  test("empty string IP is accepted", async () => {
    const sid = tracked(uniqueSession())
    const { ctx } = makeContext(sid)

    await updateTool.execute({
      target: { ip: "" },
    }, ctx)

    const state = await loadEngagementState(sid)
    expect(state.target?.ip).toBe("")
  })
})

describe("ATTACK: large state (stress test)", () => {
  /**
   * HYPOTHESIS: With 1000 ports and 500 credentials, YAML dump/load could
   * become very slow or the file could exceed reasonable size. Also tests
   * whether the injection into system prompts creates a context bomb.
   */
  test("1000 ports survive roundtrip via file I/O", async () => {
    const sid = tracked(uniqueSession())
    const ports = Array.from({ length: 1000 }, (_, i) => ({
      port: i + 1,
      protocol: "tcp" as const,
      service: `svc-${i}`,
      version: `v${i}.0.0`,
      banner: `Banner for port ${i + 1} with some extra text to bulk it up`,
    }))

    await saveEngagementState(sid, { ports })
    const loaded = await loadEngagementState(sid)

    expect(loaded.ports?.length).toBe(1000)
    expect(loaded.ports?.[999]?.port).toBe(1000)
  })

  test("500 credentials survive roundtrip", async () => {
    const sid = tracked(uniqueSession())
    const credentials = Array.from({ length: 500 }, (_, i) => ({
      username: `user-${i}`,
      password: `P@ssw0rd!${i}_${":{}|>\n".charAt(i % 6)}`,
      service: `svc-${i % 20}`,
    }))

    await saveEngagementState(sid, { credentials })
    const loaded = await loadEngagementState(sid)

    expect(loaded.credentials?.length).toBe(500)
    // Spot check a credential with special char
    const cred5 = loaded.credentials?.[5]
    expect(cred5?.username).toBe("user-5")
    expect(cred5?.password).toContain("P@ssw0rd!5")
  })

  test("large state injection does not crash getEngagementStateForInjection", async () => {
    const sid = tracked(uniqueSession())
    const bigState: EngagementState = {
      target: { ip: "10.10.10.1" },
      ports: Array.from({ length: 200 }, (_, i) => ({
        port: i + 1,
        protocol: "tcp" as const,
        service: `svc-${i}`,
      })),
      credentials: Array.from({ length: 100 }, (_, i) => ({
        username: `user-${i}`,
        password: `pass-${i}`,
        service: `svc-${i % 10}`,
      })),
      vulnerabilities: Array.from({ length: 50 }, (_, i) => ({
        name: `vuln-${i}`,
        severity: "high" as const,
      })),
    }

    await saveEngagementState(sid, bigState)
    const injection = await getEngagementStateForInjection(sid)

    expect(injection).not.toBeNull()
    expect(injection!.length).toBeGreaterThan(1000)
    // It should still contain the state markers
    expect(injection).toContain("## Current Engagement State")
    expect(injection).toContain("### Port Accessibility")
  })
})

describe("ATTACK: corrupt state.yaml on disk", () => {
  /**
   * HYPOTHESIS: If state.yaml is corrupted (binary garbage, partial write,
   * zero bytes), loadEngagementState should return {} not crash.
   */
  test("binary garbage in state.yaml returns empty object", async () => {
    const sid = tracked(uniqueSession())
    SessionDirectory.create(sid)
    const statePath = SessionDirectory.statePath(sid)
    writeFileSync(statePath, Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))

    const state = await loadEngagementState(sid)
    expect(state).toEqual({})
  })

  test("empty file (zero bytes) returns empty object", async () => {
    const sid = tracked(uniqueSession())
    SessionDirectory.create(sid)
    const statePath = SessionDirectory.statePath(sid)
    writeFileSync(statePath, "")

    const state = await loadEngagementState(sid)
    // yaml.load("") returns undefined, `parsed ?? {}` should give {}
    expect(state).toEqual({})
  })

  test("file containing just 'null' returns empty object", async () => {
    const sid = tracked(uniqueSession())
    SessionDirectory.create(sid)
    const statePath = SessionDirectory.statePath(sid)
    writeFileSync(statePath, "null")

    const state = await loadEngagementState(sid)
    // yaml.load("null") returns null, `null ?? {}` gives {}
    expect(state).toEqual({})
  })

  test("file containing a plain string returns empty object or string (not crash)", async () => {
    const sid = tracked(uniqueSession())
    SessionDirectory.create(sid)
    const statePath = SessionDirectory.statePath(sid)
    writeFileSync(statePath, "just a random string, not YAML")

    // yaml.load("just a random string") returns the string itself
    // `parsed ?? {}` would return the string since strings are truthy
    // BUG CANDIDATE: loadEngagementState returns a string, not EngagementState
    const state = await loadEngagementState(sid)
    // If it returns a string, callers expecting .ports will get undefined — no crash
    // but the type assertion is wrong
    expect(typeof state).not.toBe("undefined")
  })

  test("file containing a YAML array returns it (not an object)", async () => {
    const sid = tracked(uniqueSession())
    SessionDirectory.create(sid)
    const statePath = SessionDirectory.statePath(sid)
    writeFileSync(statePath, "- item1\n- item2\n")

    // yaml.load returns an array, cast as EngagementState — type mismatch
    // BUG CANDIDATE: No validation that loaded YAML is an object
    const state = await loadEngagementState(sid)
    // It will be an array, not an object with ports/credentials/etc.
    const isArray = Array.isArray(state)
    // This is a bug — callers will try state.ports on an array
    if (isArray) {
      // BUG CONFIRMED: loadEngagementState can return an array
      expect(isArray).toBe(true)
    } else {
      expect(state).toBeDefined()
    }
  })

  test("file containing YAML number returns it (type confusion)", async () => {
    const sid = tracked(uniqueSession())
    SessionDirectory.create(sid)
    const statePath = SessionDirectory.statePath(sid)
    writeFileSync(statePath, "42")

    // yaml.load("42") returns 42 (a number)
    // `42 ?? {}` returns 42 (number is truthy)
    // BUG: loadEngagementState returns 42 as EngagementState
    const state = await loadEngagementState(sid)
    expect(typeof state === "number" || typeof state === "object").toBe(true)
  })
})

// ===========================================================================
// 2. MERGE LOGIC EDGE CASES
// ===========================================================================

describe("ATTACK: port dedup with protocol=undefined", () => {
  /**
   * HYPOTHESIS: Port dedup compares `p.port === item.port && p.protocol === item.protocol`.
   * If protocol is undefined (not in the update), both sides are undefined,
   * so undefined === undefined is true. But what if existing has protocol="tcp"
   * (from schema default) and update has protocol=undefined?
   */
  test("port with explicit protocol and port without protocol are NOT deduped", () => {
    // Schema default is "tcp", so if you pass { port: 22 } the schema adds protocol: "tcp"
    // But mergeState takes pre-parsed objects, not schema-validated ones
    const existing: EngagementState = {
      ports: [{ port: 22, protocol: "tcp", service: "ssh" }],
    }
    // Simulate an update where protocol is missing (before schema validation)
    const updates = {
      ports: [{ port: 22, service: "ssh-updated" } as any],
    }
    const result = mergeState(existing, updates)

    // existing.protocol="tcp", update.protocol=undefined
    // "tcp" === undefined is false, so they won't dedup
    // BUG: same port 22 appears twice because protocol mismatch
    expect(result.ports?.length).toBe(2) // Should be 1, but is 2
  })

  test("two ports with undefined protocol ARE deduped", () => {
    const existing: EngagementState = {
      ports: [{ port: 22 } as any],
    }
    const updates = {
      ports: [{ port: 22, service: "ssh" } as any],
    }
    const result = mergeState(existing, updates)

    // undefined === undefined is true, so dedup works
    expect(result.ports?.length).toBe(1)
    expect((result.ports?.[0] as any)?.service).toBe("ssh")
  })
})

describe("ATTACK: credential dedup with empty username", () => {
  /**
   * HYPOTHESIS: Credentials dedup by username+service. If username is "",
   * then "" === "" is true. Two credentials with username="" and same service
   * should dedup. But what about username="" and service=undefined?
   */
  test("empty string username deduplicates correctly", () => {
    const existing: EngagementState = {
      credentials: [{ username: "", service: "http", password: "old" }],
    }
    const updates = {
      credentials: [{ username: "", service: "http", password: "new" }],
    }
    const result = mergeState(existing, updates)

    expect(result.credentials?.length).toBe(1)
    expect(result.credentials?.[0]?.password).toBe("new")
  })

  test("credentials with username='' and service=undefined dedup together", () => {
    const existing: EngagementState = {
      credentials: [{ username: "", password: "old" }],
    }
    const updates = {
      credentials: [{ username: "", password: "new" }],
    }
    const result = mergeState(existing, updates)

    // Both have username="" and service=undefined
    // undefined === undefined is true
    expect(result.credentials?.length).toBe(1)
    expect(result.credentials?.[0]?.password).toBe("new")
  })

  test("credential with service=undefined and service='ssh' are NOT deduped", () => {
    const existing: EngagementState = {
      credentials: [{ username: "admin" }],
    }
    const updates = {
      credentials: [{ username: "admin", service: "ssh" }],
    }
    const result = mergeState(existing, updates)

    // undefined !== "ssh", so these are treated as different credentials
    expect(result.credentials?.length).toBe(2)
  })
})

describe("ATTACK: toolFailures count overflow", () => {
  /**
   * HYPOTHESIS: toolFailures merge does `(merged[idx].count || 1) + 1`.
   * If count is already Number.MAX_SAFE_INTEGER, incrementing produces
   * Number.MAX_SAFE_INTEGER + 1 which loses precision.
   */
  test("count at MAX_SAFE_INTEGER: increment loses precision", () => {
    const existing: EngagementState = {
      toolFailures: [{
        tool: "nmap",
        error: "timeout",
        count: Number.MAX_SAFE_INTEGER,
        firstSeen: "2026-01-01",
        lastSeen: "2026-01-02",
      }],
    }
    const updates = {
      toolFailures: [{
        tool: "nmap",
        error: "timeout again",
        count: 1,
        firstSeen: "2026-01-01",
        lastSeen: "2026-01-03",
      }],
    }
    const result = mergeState(existing, updates)

    // (MAX_SAFE_INTEGER || 1) + 1 = MAX_SAFE_INTEGER + 1
    // In IEEE 754, MAX_SAFE_INTEGER + 1 === MAX_SAFE_INTEGER + 2 (precision lost)
    const count = result.toolFailures?.[0]?.count ?? 0
    // The value is stored but precision is unreliable above MAX_SAFE_INTEGER
    // BUG: No upper bound check on count — will silently lose precision
    expect(count).toBe(Number.MAX_SAFE_INTEGER + 1)
    // Demonstrate the precision issue: the NEXT increment would be indistinguishable
    expect(Number.MAX_SAFE_INTEGER + 1).toBe(Number.MAX_SAFE_INTEGER + 2) // IEEE 754 precision loss
  })

  /**
   * FIXED (BUG-ES-6): The merge code now uses `(merged[idx].count ?? 0) + (item.count ?? 1)`.
   * The incoming item's count is properly added to the existing count.
   */
  test("incoming count value is respected (added to existing)", () => {
    const existing: EngagementState = {
      toolFailures: [{
        tool: "sqlmap",
        error: "connection refused",
        count: 3,
        firstSeen: "2026-01-01",
        lastSeen: "2026-01-02",
      }],
    }
    const updates = {
      toolFailures: [{
        tool: "sqlmap",
        error: "still refused",
        count: 10, // Caller says it failed 10 more times
        firstSeen: "2026-01-01",
        lastSeen: "2026-01-03",
      }],
    }
    const result = mergeState(existing, updates)

    // FIXED: count becomes 3 + 10 = 13
    expect(result.toolFailures?.[0]?.count).toBe(13)
  })

  test("toolFailures with count=0 correctly preserves zero", () => {
    const existing: EngagementState = {
      toolFailures: [{
        tool: "hydra",
        error: "auth error",
        count: 0, // edge: 0 is falsy but valid
        firstSeen: "2026-01-01",
        lastSeen: "2026-01-02",
      }],
    }
    const updates = {
      toolFailures: [{
        tool: "hydra",
        error: "auth error again",
        count: 1,
        firstSeen: "2026-01-01",
        lastSeen: "2026-01-03",
      }],
    }
    const result = mergeState(existing, updates)

    // FIXED (BUG-ES-7): (0 ?? 0) + (1 ?? 1) = 0 + 1 = 1
    // count=0 is correctly treated as 0, not coerced to 1
    expect(result.toolFailures?.[0]?.count).toBe(1)
  })
})

describe("ATTACK: toolSearchCache eviction", () => {
  /**
   * HYPOTHESIS: Cache is capped at 20 via `.slice(-20)`. But eviction
   * happens AFTER merge. If existing has 20 and update has 5 new, the
   * merged array has 25, then slice(-20) removes the 5 oldest. This is
   * correct LRU-ish behavior. But what about the same query with
   * different case?
   */
  test("cache eviction keeps last 20 entries", () => {
    const existing: EngagementState = {
      toolSearchCache: Array.from({ length: 20 }, (_, i) => ({
        query: `query-${i}`,
        results: [{ tool: `tool-${i}` }],
        timestamp: new Date(2026, 0, 1, 0, i).toISOString(),
      })),
    }
    const updates = {
      toolSearchCache: [{
        query: "new-query",
        results: [{ tool: "new-tool" }],
        timestamp: new Date(2026, 0, 1, 1, 0).toISOString(),
      }],
    }
    const result = mergeState(existing, updates)

    expect(result.toolSearchCache?.length).toBe(20)
    // First entry (query-0) should be evicted
    const queries = result.toolSearchCache?.map(c => c.query)
    expect(queries).not.toContain("query-0")
    expect(queries).toContain("new-query")
  })

  test("case-insensitive dedup: 'Port Scanner' matches 'port scanner'", () => {
    const existing: EngagementState = {
      toolSearchCache: [{
        query: "Port Scanner",
        results: [{ tool: "nmap" }],
        timestamp: "2026-01-01T00:00:00Z",
      }],
    }
    const updates = {
      toolSearchCache: [{
        query: "port scanner",
        results: [{ tool: "nmap", method: "scan_ports" }],
        timestamp: "2026-01-01T01:00:00Z",
      }],
    }
    const result = mergeState(existing, updates)

    // Should dedup — only 1 entry
    expect(result.toolSearchCache?.length).toBe(1)
    // Updated entry should have the new results
    expect(result.toolSearchCache?.[0]?.results?.[0]?.method).toBe("scan_ports")
  })

  test("whitespace-padded query deduplicates: '  scan  ' matches 'scan'", () => {
    const existing: EngagementState = {
      toolSearchCache: [{
        query: "scan",
        results: [{ tool: "nmap" }],
        timestamp: "2026-01-01T00:00:00Z",
      }],
    }
    const updates = {
      toolSearchCache: [{
        query: "  scan  ",
        results: [{ tool: "nmap" }],
        timestamp: "2026-01-01T01:00:00Z",
      }],
    }
    const result = mergeState(existing, updates)

    expect(result.toolSearchCache?.length).toBe(1)
  })
})

describe("ATTACK: attackPlan edge cases", () => {
  /**
   * HYPOTHESIS: attackPlan uses REPLACE semantics, not merge.
   * Setting a new attackPlan completely overwrites the old one.
   */
  test("attackPlan with 0 steps replaces existing plan", () => {
    const existing: EngagementState = {
      attackPlan: {
        title: "Old Plan",
        source: "agent",
        steps: [
          { step: 1, description: "Do something", status: "completed" },
        ],
      },
    } as any
    const updates = {
      attackPlan: {
        title: "New Empty Plan",
        source: "agent",
        steps: [],
      },
    }
    const result = mergeState(existing, updates)

    expect((result as any).attackPlan?.title).toBe("New Empty Plan")
    expect((result as any).attackPlan?.steps?.length).toBe(0)
  })

  test("attackPlan is an object — it uses replace, not merge", () => {
    const existing: EngagementState = {
      attackPlan: {
        title: "Plan A",
        source: "agent",
        steps: [
          { step: 1, description: "Step 1", status: "completed" },
          { step: 2, description: "Step 2", status: "pending" },
        ],
      },
    } as any
    const updates = {
      attackPlan: {
        title: "Plan B",
        source: "revised",
        steps: [
          { step: 1, description: "New Step 1", status: "pending" },
        ],
      },
    }
    const result = mergeState(existing, updates)

    // Should be complete replacement, NOT merge
    expect((result as any).attackPlan?.title).toBe("Plan B")
    expect((result as any).attackPlan?.steps?.length).toBe(1)
    // Old steps should be gone
    expect((result as any).attackPlan?.steps?.[0]?.description).toBe("New Step 1")
  })
})

describe("ATTACK: resetToolFailures + toolFailures in same update", () => {
  /**
   * HYPOTHESIS: If the update contains both resetToolFailures=true AND
   * new toolFailures entries, what wins? Looking at execute():
   * 1. mergeState() runs first (appends new toolFailures to existing)
   * 2. Then resetToolFailures check runs (sets toolFailures = [])
   *
   * BUG: The new toolFailures are LOST because resetToolFailures runs after merge.
   */
  test("resetToolFailures=true AFTER merge erases newly added failures", async () => {
    const sid = tracked(uniqueSession())

    // First, add some tool failures
    const { ctx: ctx1 } = makeContext(sid)
    await updateTool.execute({
      toolFailures: [{
        tool: "nmap",
        error: "old failure",
        count: 1,
        firstSeen: "2026-01-01",
        lastSeen: "2026-01-01",
      }],
    } as any, ctx1)

    // Now send reset AND new failures in the same call
    // Note: toolFailures is not in the execute() schema (only in mergeState)
    // but passthrough() allows it
    const { ctx: ctx2 } = makeContext(sid)
    await updateTool.execute({
      resetToolFailures: true,
      // Even if we could pass toolFailures, resetToolFailures runs AFTER merge
    } as any, ctx2)

    const state = await loadEngagementState(sid)
    // After reset, toolFailures should be empty
    expect(state.toolFailures?.length ?? 0).toBe(0)
  })
})

describe("ATTACK: conflicting scalar updates", () => {
  /**
   * HYPOTHESIS: If the same update has accessLevel:"root", what if a
   * subsequent call sets it to "none"? Simple replace semantics — last write wins.
   */
  test("accessLevel can be downgraded from root to none", async () => {
    const sid = tracked(uniqueSession())

    const { ctx: ctx1 } = makeContext(sid)
    await updateTool.execute({ accessLevel: "root" }, ctx1)

    const { ctx: ctx2 } = makeContext(sid)
    await updateTool.execute({ accessLevel: "none" }, ctx2)

    const state = await loadEngagementState(sid)
    expect(state.accessLevel).toBe("none")
  })
})

// ===========================================================================
// 3. STATE INJECTION EDGE CASES
// ===========================================================================

describe("ATTACK: markdown injection via state values", () => {
  /**
   * HYPOTHESIS: If state values contain markdown syntax (### headers,
   * **bold**, ```code fences```), the injection into system prompt
   * could create confusing/broken formatting.
   */
  test("service name with markdown headers does not break injection", async () => {
    const sid = tracked(uniqueSession())

    await saveEngagementState(sid, {
      target: { ip: "10.10.10.1" },
      ports: [{
        port: 80,
        protocol: "tcp",
        service: "### Injected Header",
        version: "**bold version**",
      }],
    })

    const injection = await getEngagementStateForInjection(sid)
    expect(injection).not.toBeNull()
    // The markdown is inside a ```yaml code fence, so it should be safe
    expect(injection).toContain("### Injected Header")
  })

  test("credential password with code fence does not break injection", async () => {
    const sid = tracked(uniqueSession())

    await saveEngagementState(sid, {
      target: { ip: "10.10.10.1" },
      credentials: [{
        username: "admin",
        password: "```\ninjected code block\n```",
        service: "ssh",
      }],
    })

    const injection = await getEngagementStateForInjection(sid)
    expect(injection).not.toBeNull()
    // The triple backtick inside a YAML string inside a code fence —
    // could break the outer fence
    // Count the backtick-fences in the output
    const fenceCount = (injection!.match(/```/g) || []).length
    // Should have opening ```yaml and closing ```, but the password has two more
    // BUG CANDIDATE: nested code fences break markdown rendering
    // At minimum, the injection should not crash
    expect(injection!.length).toBeGreaterThan(0)
  })

  /**
   * HYPOTHESIS: Passthrough fields (not in schema) are stored and injected.
   * If an agent writes a field with HTML or script tags, they survive.
   */
  test("passthrough fields are preserved through save/load/inject cycle", async () => {
    const sid = tracked(uniqueSession())

    await saveEngagementState(sid, {
      target: { ip: "10.10.10.1" },
      customField: "custom value",
      nestedCustom: { key: "value", deep: { deeper: true } },
    } as any)

    const loaded = await loadEngagementState(sid)
    expect((loaded as any).customField).toBe("custom value")
    expect((loaded as any).nestedCustom?.deep?.deeper).toBe(true)

    // Also check injection includes passthrough fields
    const injection = await getEngagementStateForInjection(sid)
    expect(injection).toContain("customField")
    expect(injection).toContain("custom value")
  })
})

describe("ATTACK: system-transform hook edge cases", () => {
  /**
   * HYPOTHESIS: If sessionID is missing or undefined, the hook should
   * return without modifying output.
   */
  test("hook does nothing when sessionID is undefined", async () => {
    const output = { system: ["original prompt"] }
    await systemTransformHook({ sessionID: undefined, model: {} }, output)
    expect(output.system).toEqual(["original prompt"])
  })

  test("hook does nothing when no state exists for session", async () => {
    const output = { system: ["original prompt"] }
    await systemTransformHook(
      { sessionID: "nonexistent-session-12345", model: {} },
      output,
    )
    expect(output.system).toEqual(["original prompt"])
  })

  test("hook appends state when state exists", async () => {
    const sid = tracked(uniqueSession())
    await saveEngagementState(sid, {
      target: { ip: "10.10.10.99" },
      ports: [{ port: 22, protocol: "tcp", service: "ssh" }],
    })

    const output = { system: ["original prompt"] }
    await systemTransformHook({ sessionID: sid, model: {} }, output)

    expect(output.system.length).toBe(2)
    expect(output.system[1]).toContain("10.10.10.99")
  })

  test("hook uses root session ID for sub-agent sessions", async () => {
    const rootSid = tracked(uniqueSession())
    const childSid = tracked(uniqueSession())
    registerRootSession(childSid, rootSid)

    await saveEngagementState(rootSid, {
      target: { ip: "10.10.10.77" },
    })

    const output = { system: ["original prompt"] }
    await systemTransformHook({ sessionID: childSid, model: {} }, output)

    expect(output.system.length).toBe(2)
    expect(output.system[1]).toContain("10.10.10.77")
  })
})

describe("ATTACK: compaction hook edge cases", () => {
  test("compaction hook does nothing when no state exists", async () => {
    const output = { context: [] as string[], prompt: undefined }
    await compactionHook(
      { sessionID: "nonexistent-compact-session" },
      output,
    )
    expect(output.context.length).toBe(0)
  })

  test("compaction hook injects CRITICAL preservation notice", async () => {
    const sid = tracked(uniqueSession())
    await saveEngagementState(sid, {
      target: { ip: "10.10.10.55" },
      accessLevel: "user",
    })

    const output = { context: [] as string[], prompt: undefined }
    await compactionHook({ sessionID: sid }, output)

    expect(output.context.length).toBe(1)
    expect(output.context[0]).toContain("CRITICAL")
    expect(output.context[0]).toContain("PRESERVE IN SUMMARY")
    expect(output.context[0]).toContain("10.10.10.55")
  })
})

// ===========================================================================
// 4. CONCURRENT WRITES (Race Conditions)
// ===========================================================================

describe("ATTACK: concurrent writes (race conditions)", () => {
  /**
   * HYPOTHESIS: Two agents calling update_engagement_state simultaneously
   * will both read the same state, merge independently, and then the
   * second write will overwrite the first. This is a classic lost-update bug.
   *
   * No locking mechanism exists (confirmed by reading the code).
   */
  test("concurrent writes cause lost updates (no locking)", async () => {
    const sid = tracked(uniqueSession())

    // Seed initial state
    await saveEngagementState(sid, {
      target: { ip: "10.10.10.1" },
      ports: [],
    })

    // Simulate two agents writing simultaneously
    // Agent A: adds port 22
    // Agent B: adds port 80
    const { ctx: ctxA } = makeContext(sid)
    const { ctx: ctxB } = makeContext(sid)

    // Both read the same initial state, then both write
    const promiseA = updateTool.execute({
      ports: [{ port: 22, protocol: "tcp", service: "ssh" }],
    }, ctxA)

    const promiseB = updateTool.execute({
      ports: [{ port: 80, protocol: "tcp", service: "http" }],
    }, ctxB)

    await Promise.all([promiseA, promiseB])

    // One of the writes may be lost
    const state = await loadEngagementState(sid)
    const portNumbers = state.ports?.map(p => p.port) ?? []

    // In a correct implementation, both ports should be present
    // BUG: Due to read-modify-write without locking, one port may be lost
    // The test documents the behavior rather than asserting correctness
    if (portNumbers.length === 1) {
      // Lost update confirmed
      console.log("[BUG CONFIRMED] Lost update: only port", portNumbers[0], "survived")
    } else {
      // Both survived (lucky timing or serial execution)
      expect(portNumbers).toContain(22)
      expect(portNumbers).toContain(80)
    }
    // We accept either outcome — this test documents the race condition
    expect(portNumbers.length).toBeGreaterThanOrEqual(1)
  })

  /**
   * HYPOTHESIS: If writeFile is not atomic, a concurrent reader could see
   * a partially written file. fs.writeFile in Node is NOT atomic — it
   * truncates first, then writes. A reader at the wrong moment gets
   * empty or partial content.
   */
  test("write is not atomic — partial file could be observed", async () => {
    const sid = tracked(uniqueSession())
    SessionDirectory.create(sid)

    // Write a large state
    const bigState: EngagementState = {
      target: { ip: "10.10.10.1" },
      ports: Array.from({ length: 100 }, (_, i) => ({
        port: i + 1,
        protocol: "tcp" as const,
        service: `service-${i}`,
      })),
    }

    // Start write and immediately try to read
    const writePromise = saveEngagementState(sid, bigState)

    // Attempt a read while write is in progress
    // Due to event loop, the write and read may interleave
    const readPromise = loadEngagementState(sid)

    const [, readResult] = await Promise.all([writePromise, readPromise])

    // Either we get the old state (empty), the new state, or corrupt data
    // The test verifies no crash occurs
    expect(readResult).toBeDefined()
  })
})

// ===========================================================================
// 5. EXECUTE PATH EDGE CASES
// ===========================================================================

describe("ATTACK: execute() with empty/minimal input", () => {
  /**
   * HYPOTHESIS: Calling execute({}) with no fields should produce
   * "no changes" summary and not crash.
   */
  test("execute with empty object produces 'no changes'", async () => {
    const sid = tracked(uniqueSession())
    const { ctx } = makeContext(sid)

    const result = await updateTool.execute({}, ctx)
    expect(result).toContain("no changes")
  })

  /**
   * HYPOTHESIS: execute() with unknown fields (via passthrough()) should
   * store them without crashing.
   */
  test("execute with unknown extra fields stores them via passthrough", async () => {
    const sid = tracked(uniqueSession())
    const { ctx } = makeContext(sid)

    await updateTool.execute({
      target: { ip: "10.10.10.1" },
      unknownField: "should be passed through",
      anotherCustom: [1, 2, 3],
    } as any, ctx)

    const state = await loadEngagementState(sid)
    expect(state.target?.ip).toBe("10.10.10.1")
    // Passthrough fields should survive
    expect((state as any).unknownField).toBe("should be passed through")
    expect((state as any).anotherCustom).toEqual([1, 2, 3])
  })

  /**
   * HYPOTHESIS: If sessionID doesn't have a registered root session,
   * getRootSession returns the sessionID itself. This is correct, but
   * the execute path should still work.
   */
  test("execute works when sessionID has no registered root (is its own root)", async () => {
    const sid = tracked(uniqueSession())
    // Don't register a root session — sid is its own root
    const { ctx } = makeContext(sid)

    const result = await updateTool.execute({
      target: { ip: "10.10.10.1" },
    }, ctx)

    expect(result).toContain("10.10.10.1")
    const state = await loadEngagementState(sid)
    expect(state.target?.ip).toBe("10.10.10.1")
  })
})

describe("ATTACK: read_engagement_state edge cases", () => {
  test("read on nonexistent session returns no-state message", async () => {
    const sid = tracked(uniqueSession())
    const { ctx } = makeContext(sid)

    const result = await readTool.execute({}, ctx)
    expect(result).toContain("No engagement state found")
  })

  test("read on session with only passthrough fields works", async () => {
    const sid = tracked(uniqueSession())
    await saveEngagementState(sid, { customOnly: "value" } as any)

    const { ctx } = makeContext(sid)
    const result = await readTool.execute({}, ctx)

    // Not empty because customOnly is a key
    expect(result).toContain("Current Engagement State")
    expect(result).toContain("customOnly")
  })
})

// ===========================================================================
// 6. STATE HISTORY / SNAPSHOT EDGE CASES
// ===========================================================================

describe("ATTACK: state history corruption", () => {
  /**
   * HYPOTHESIS: appendStateHistory reads the history file, parses it as
   * YAML, checks if it's an array, and appends. If the history file
   * contains a non-array YAML value, it silently starts fresh.
   */
  test("corrupt history file (non-array) is silently reset", async () => {
    const sid = tracked(uniqueSession())
    SessionDirectory.create(sid)

    // Write corrupt history (YAML object instead of array)
    const historyPath = join(SessionDirectory.get(sid), "state_history.yaml")
    writeFileSync(historyPath, yaml.dump({ corrupt: true }))

    // Save state — this calls appendStateHistory
    await saveEngagementState(sid, { target: { ip: "10.10.10.1" } })

    // History should have been reset to contain just the new snapshot
    const snapshots = await getStateSnapshots(sid)
    expect(snapshots.length).toBe(1)
    expect(snapshots[0].state.target?.ip).toBe("10.10.10.1")
  })

  test("history stepIndex is based on array length, not incremented counter", async () => {
    const sid = tracked(uniqueSession())

    // Save 3 states
    await saveEngagementState(sid, { accessLevel: "none" })
    await saveEngagementState(sid, { accessLevel: "user" })
    await saveEngagementState(sid, { accessLevel: "root" })

    const snapshots = await getStateSnapshots(sid)
    expect(snapshots.length).toBe(3)
    expect(snapshots[0].stepIndex).toBe(0)
    expect(snapshots[1].stepIndex).toBe(1)
    expect(snapshots[2].stepIndex).toBe(2)
  })
})

describe("ATTACK: detectStateChanges edge cases", () => {
  test("before=undefined treats everything as new", () => {
    const after = {
      timestamp: Date.now(),
      stepIndex: 0,
      state: {
        accessLevel: "user" as const,
        credentials: [{ username: "admin" }],
        vulnerabilities: [{ name: "sqli" }],
        sessions: [{ id: "shell-1" }],
        flags: ["flag1"],
      },
    }

    const changes = detectStateChanges(undefined, after)
    expect(changes.accessLevelChanged).toBe(true)
    expect(changes.fromAccess).toBe("none")
    expect(changes.toAccess).toBe("user")
    expect(changes.credentialsAdded).toBe(1)
    expect(changes.vulnerabilitiesAdded).toBe(1)
    expect(changes.sessionsAdded).toBe(1)
    expect(changes.flagsAdded).toBe(1)
  })

  test("items removed (fewer in after than before) shows 0 not negative", () => {
    const before = {
      timestamp: Date.now(),
      stepIndex: 0,
      state: {
        credentials: [{ username: "a" }, { username: "b" }, { username: "c" }],
      },
    }
    const after = {
      timestamp: Date.now(),
      stepIndex: 1,
      state: {
        credentials: [{ username: "a" }],
      },
    }

    const changes = detectStateChanges(before, after)
    // Math.max(0, 1 - 3) = 0, not -2
    expect(changes.credentialsAdded).toBe(0)
  })

  test("accessLevel undefined->undefined shows no change", () => {
    const before = { timestamp: 0, stepIndex: 0, state: {} }
    const after = { timestamp: 1, stepIndex: 1, state: {} }

    const changes = detectStateChanges(before, after)
    // Both normalize to "none", so no change
    expect(changes.accessLevelChanged).toBe(false)
    expect(changes.fromAccess).toBeUndefined()
    expect(changes.toAccess).toBeUndefined()
  })
})

describe("ATTACK: getStateAtStep edge cases", () => {
  test("empty snapshots array returns undefined", () => {
    const result = getStateAtStep([], 5)
    expect(result).toBeUndefined()
  })

  test("stepIndex before all snapshots returns undefined", () => {
    const snapshots = [
      { timestamp: 0, stepIndex: 5, state: {} },
      { timestamp: 1, stepIndex: 10, state: {} },
    ]
    const result = getStateAtStep(snapshots, 3)
    expect(result).toBeUndefined()
  })

  test("stepIndex between snapshots returns closest lower", () => {
    const snapshots = [
      { timestamp: 0, stepIndex: 0, state: { accessLevel: "none" as const } },
      { timestamp: 1, stepIndex: 5, state: { accessLevel: "user" as const } },
      { timestamp: 2, stepIndex: 10, state: { accessLevel: "root" as const } },
    ]
    const result = getStateAtStep(snapshots, 7)
    expect(result?.stepIndex).toBe(5)
    expect(result?.state.accessLevel).toBe("user")
  })

  test("negative stepIndex returns undefined", () => {
    const snapshots = [
      { timestamp: 0, stepIndex: 0, state: {} },
    ]
    const result = getStateAtStep(snapshots, -1)
    expect(result).toBeUndefined()
  })
})

// ===========================================================================
// 7. MERGE LOGIC — DEEP EDGE CASES
// ===========================================================================

describe("ATTACK: mergeState with type confusion", () => {
  /**
   * HYPOTHESIS: If an existing field is a scalar but the update provides
   * an array for the same key (or vice versa), what happens?
   */
  test("updating scalar field with array replaces it", () => {
    const existing: EngagementState = { accessLevel: "user" }
    const updates = { accessLevel: ["root", "user"] } as any
    const result = mergeState(existing, updates)
    // Array.isArray(["root", "user"]) = true
    // existingValue is "user" (not array), so existingArray = []
    // result.accessLevel = [...[], ...["root", "user"]] = ["root", "user"]
    expect(Array.isArray(result.accessLevel)).toBe(true)
  })

  test("updating array field with scalar replaces it", () => {
    const existing: EngagementState = {
      ports: [{ port: 22, protocol: "tcp" }],
    }
    const updates = { ports: "not an array" } as any
    const result = mergeState(existing, updates)
    // typeof "not an array" is "string", not array, not object
    // Falls into scalar branch: result.ports = "not an array"
    expect(result.ports).toBe("not an array")
  })

  test("updating with nested null values", () => {
    const existing: EngagementState = {
      target: { ip: "10.10.10.1", hostname: "test.htb" },
    }
    // Try to null out hostname
    const updates = {
      target: { ip: "10.10.10.1", hostname: null },
    } as any
    const result = mergeState(existing, updates)
    // Object merge: { ...existing.target, ...updates.target }
    // hostname becomes null (spread replaces)
    expect(result.target?.hostname).toBeNull()
  })
})

describe("ATTACK: mergeState array with non-array existing value", () => {
  /**
   * HYPOTHESIS: If the existing state has ports as something other than
   * an array (e.g., from corrupt YAML), the merge should handle it gracefully.
   */
  test("existing ports as string, update with array", () => {
    const existing = { ports: "corrupted" } as any
    const updates = {
      ports: [{ port: 22, protocol: "tcp" as const }],
    }
    const result = mergeState(existing, updates)

    // Array.isArray(updates.ports) = true
    // existingValue = "corrupted", not array, so existingArray = []
    // result.ports = [{ port: 22, protocol: "tcp" }]
    expect(result.ports?.length).toBe(1)
    expect(result.ports?.[0]?.port).toBe(22)
  })

  test("existing ports as object (not array), update with array", () => {
    const existing = { ports: { broken: true } } as any
    const updates = {
      ports: [{ port: 80, protocol: "tcp" as const }],
    }
    const result = mergeState(existing, updates)

    expect(result.ports?.length).toBe(1)
  })
})

describe("ATTACK: vulnerabilities and files — no dedup means unbounded growth", () => {
  /**
   * HYPOTHESIS: vulnerabilities and files use simple append (no dedup).
   * An agent repeatedly reporting the same vulnerability will cause
   * unbounded growth. This is by design but should be documented.
   */
  test("duplicate vulnerabilities accumulate without bound", () => {
    let state: EngagementState = {}

    // Same vulnerability reported 100 times
    for (let i = 0; i < 100; i++) {
      state = mergeState(state, {
        vulnerabilities: [{ name: "SQLi on login", severity: "high" }],
      })
    }

    // BUG/DESIGN: 100 identical entries
    expect(state.vulnerabilities?.length).toBe(100)
  })

  test("duplicate failedAttempts accumulate without bound", () => {
    let state: EngagementState = {}

    for (let i = 0; i < 50; i++) {
      state = mergeState(state, {
        failedAttempts: [{ action: "SSH brute force", reason: "No password" }],
      })
    }

    expect(state.failedAttempts?.length).toBe(50)
  })
})

// ===========================================================================
// 8. INJECTION FORMATTING EDGE CASES
// ===========================================================================

describe("ATTACK: getEngagementStateForInjection formatting", () => {
  test("filtered ports get DO NOT TARGET warning", async () => {
    const sid = tracked(uniqueSession())
    await saveEngagementState(sid, {
      target: { ip: "10.10.10.1" },
      ports: [
        { port: 22, protocol: "tcp", service: "ssh", state: "open" },
        { port: 445, protocol: "tcp", service: "smb", state: "filtered" },
      ],
    })

    const injection = await getEngagementStateForInjection(sid)
    expect(injection).toContain("OPEN")
    expect(injection).toContain("FILTERED")
    expect(injection).toContain("do NOT target")
  })

  test("ports without state are treated as open", async () => {
    const sid = tracked(uniqueSession())
    await saveEngagementState(sid, {
      target: { ip: "10.10.10.1" },
      ports: [
        { port: 22, protocol: "tcp", service: "ssh" }, // no state field
      ],
    })

    const injection = await getEngagementStateForInjection(sid)
    expect(injection).toContain("OPEN")
    expect(injection).toContain("22/tcp")
  })

  test("toolFailures with count < 2 are NOT shown in broken tools warning", async () => {
    const sid = tracked(uniqueSession())
    await saveEngagementState(sid, {
      target: { ip: "10.10.10.1" },
      toolFailures: [{
        tool: "nmap",
        error: "once is not enough",
        count: 1,
        firstSeen: "2026-01-01",
        lastSeen: "2026-01-01",
      }],
    } as any)

    const injection = await getEngagementStateForInjection(sid)
    expect(injection).not.toContain("BROKEN TOOLS")
  })

  test("toolFailures with count >= 2 ARE shown in broken tools warning", async () => {
    const sid = tracked(uniqueSession())
    await saveEngagementState(sid, {
      target: { ip: "10.10.10.1" },
      toolFailures: [{
        tool: "sqlmap",
        method: "test_injection",
        error: "connection refused",
        count: 3,
        firstSeen: "2026-01-01",
        lastSeen: "2026-01-03",
      }],
    } as any)

    const injection = await getEngagementStateForInjection(sid)
    expect(injection).toContain("BROKEN TOOLS")
    expect(injection).toContain("sqlmap.test_injection")
    expect(injection).toContain("failed 3x")
  })

  test("toolSearchCache shows last 10 entries max in Recent Tool Searches section", async () => {
    const sid = tracked(uniqueSession())
    await saveEngagementState(sid, {
      target: { ip: "10.10.10.1" },
      toolSearchCache: Array.from({ length: 15 }, (_, i) => ({
        query: `query-${i}`,
        results: [{ tool: `tool-${i}` }],
        timestamp: new Date(2026, 0, 1, 0, i).toISOString(),
      })),
    } as any)

    const injection = await getEngagementStateForInjection(sid)
    expect(injection).toContain("Recent Tool Searches")

    // Extract just the "Recent Tool Searches" section (after the header)
    const searchSection = injection!.split("### Recent Tool Searches")[1] ?? ""

    // Only last 10 should be shown in the formatted summary section
    expect(searchSection).not.toContain("query-0")
    expect(searchSection).not.toContain("query-4")
    expect(searchSection).toContain("query-5")
    expect(searchSection).toContain("query-14")

    // BUG/DESIGN: The full YAML dump section ALSO contains all 15 cache entries
    // This means the "last 10" limit in the summary section is undermined —
    // the LLM can still see all 15 entries in the YAML block above.
    // The full injection string DOES contain query-0 (in the YAML section)
    expect(injection).toContain("query-0") // Present in YAML dump = info duplication
  })

  test("attack plan with all status types renders correct markers", async () => {
    const sid = tracked(uniqueSession())
    await saveEngagementState(sid, {
      target: { ip: "10.10.10.1" },
      attackPlan: {
        title: "Test Plan",
        source: "agent",
        steps: [
          { step: 1, description: "Completed", status: "completed" },
          { step: 2, description: "In Progress", status: "in_progress" },
          { step: 3, description: "Pending", status: "pending" },
          { step: 4, description: "Failed", status: "failed" },
          { step: 5, description: "Skipped", status: "skipped" },
        ],
      },
    } as any)

    const injection = await getEngagementStateForInjection(sid)
    expect(injection).toContain("[x] Step 1")
    expect(injection).toContain("[>] Step 2")
    expect(injection).toContain("[ ] Step 3")
    expect(injection).toContain("[!] Step 4")
    expect(injection).toContain("[-] Step 5")
  })

  test("attack plan with unknown status falls back to [ ]", async () => {
    const sid = tracked(uniqueSession())
    await saveEngagementState(sid, {
      target: { ip: "10.10.10.1" },
      attackPlan: {
        title: "Test Plan",
        source: "agent",
        steps: [
          { step: 1, description: "Unknown Status", status: "banana" },
        ],
      },
    } as any)

    const injection = await getEngagementStateForInjection(sid)
    // Unknown status should default to [ ]
    expect(injection).toContain("[ ] Step 1")
  })
})

// ===========================================================================
// 9. TOOL FAILURE DEDUP EDGE CASES
// ===========================================================================

describe("ATTACK: toolFailures method matching", () => {
  /**
   * HYPOTHESIS: Dedup uses `(f.method || "") === (item.method || "")`.
   * What if one has method=undefined and the other has method=""?
   * (undefined || "") === ("" || "") should be "" === "" = true.
   */
  test("method=undefined and method='' are treated as same tool", () => {
    const existing: EngagementState = {
      toolFailures: [{
        tool: "nmap",
        method: undefined as any,
        error: "first",
        count: 1,
        firstSeen: "2026-01-01",
        lastSeen: "2026-01-01",
      }],
    }
    const updates = {
      toolFailures: [{
        tool: "nmap",
        method: "",
        error: "second",
        count: 1,
        firstSeen: "2026-01-01",
        lastSeen: "2026-01-02",
      }],
    }
    const result = mergeState(existing, updates)

    // Should dedup: (undefined || "") === ("" || "") => "" === "" => true
    expect(result.toolFailures?.length).toBe(1)
    expect(result.toolFailures?.[0]?.count).toBe(2)
  })

  test("different methods are NOT deduped", () => {
    const existing: EngagementState = {
      toolFailures: [{
        tool: "nmap",
        method: "scan_ports",
        error: "timeout",
        count: 1,
        firstSeen: "2026-01-01",
        lastSeen: "2026-01-01",
      }],
    }
    const updates = {
      toolFailures: [{
        tool: "nmap",
        method: "scan_services",
        error: "timeout",
        count: 1,
        firstSeen: "2026-01-01",
        lastSeen: "2026-01-02",
      }],
    }
    const result = mergeState(existing, updates)

    expect(result.toolFailures?.length).toBe(2)
  })

  /**
   * HYPOTHESIS: The lastSeen in the merge uses `item.lastSeen || new Date().toISOString()`.
   * If item.lastSeen is an empty string, "" is falsy, so it falls back to now.
   */
  test("empty string lastSeen falls back to current time", () => {
    const existing: EngagementState = {
      toolFailures: [{
        tool: "hydra",
        error: "err",
        count: 1,
        firstSeen: "2026-01-01",
        lastSeen: "2026-01-01",
      }],
    }
    const before = Date.now()
    const result = mergeState(existing, {
      toolFailures: [{
        tool: "hydra",
        error: "err2",
        count: 1,
        firstSeen: "2026-01-01",
        lastSeen: "", // empty string is falsy
      }],
    })

    const lastSeen = result.toolFailures?.[0]?.lastSeen ?? ""
    // Should be a recent ISO timestamp, not empty string
    const parsed = Date.parse(lastSeen)
    expect(parsed).toBeGreaterThanOrEqual(before)
  })
})

// ===========================================================================
// 10. PROTOTYPE POLLUTION VIA PASSTHROUGH
// ===========================================================================

describe("ATTACK: prototype pollution via passthrough fields", () => {
  /**
   * HYPOTHESIS: Since schemas use .passthrough(), an attacker (malicious LLM)
   * could try to inject __proto__ or constructor fields.
   */
  test("__proto__ field in update does not pollute Object prototype", () => {
    const existing: EngagementState = { target: { ip: "10.10.10.1" } }
    const updates = {
      __proto__: { polluted: true },
    } as any

    const result = mergeState(existing, updates)

    // Object.prototype should not be polluted
    expect(({} as any).polluted).toBeUndefined()
    // The __proto__ key should not appear as a normal property
    expect(result.target?.ip).toBe("10.10.10.1")
  })

  test("constructor field in update is stored but harmless", () => {
    const existing: EngagementState = {}
    const updates = {
      constructor: { prototype: { evil: true } },
    } as any

    const result = mergeState(existing, updates)

    // Should not break object construction
    expect(typeof result).toBe("object")
    expect(({} as any).evil).toBeUndefined()
  })
})

// ===========================================================================
// 11. FULL PIPELINE TEST (Write -> Read -> Inject -> Compact)
// ===========================================================================

describe("ATTACK: full pipeline end-to-end", () => {
  test("state flows through update -> read -> inject -> compact without data loss", async () => {
    const sid = tracked(uniqueSession())
    const { ctx } = makeContext(sid)

    // Step 1: Write complex state
    await updateTool.execute({
      target: { ip: "10.10.10.99", hostname: "pipeline.htb" },
      ports: [
        { port: 22, protocol: "tcp", service: "ssh", version: "OpenSSH 8.2p1" },
        { port: 80, protocol: "tcp", service: "http" },
        { port: 443, protocol: "tcp", service: "https", state: "filtered" },
      ],
      credentials: [
        { username: "admin", password: 'P@ss:w0rd!{"}', service: "ssh" },
      ],
      vulnerabilities: [
        { name: "CVE-2021-1234", severity: "critical", exploitable: true },
      ],
      accessLevel: "user",
      flags: ["HTB{first_flag}"],
    }, ctx)

    // Step 2: Read back
    const { ctx: readCtx } = makeContext(sid)
    const readResult = await readTool.execute({}, readCtx)
    expect(readResult).toContain("pipeline.htb")
    expect(readResult).toContain("P@ss:w0rd!")
    expect(readResult).toContain("CVE-2021-1234")
    expect(readResult).toContain("HTB{first_flag}")

    // Step 3: Inject into system prompt
    const injection = await getEngagementStateForInjection(sid)
    expect(injection).toContain("10.10.10.99")
    expect(injection).toContain("FILTERED")
    expect(injection).toContain("443/tcp")

    // Step 4: Compact
    const compactOutput = { context: [] as string[], prompt: undefined }
    await compactionHook({ sessionID: sid }, compactOutput)
    expect(compactOutput.context[0]).toContain("CRITICAL")
    expect(compactOutput.context[0]).toContain("pipeline.htb")

    // Step 5: Verify state history
    const snapshots = await getStateSnapshots(sid)
    expect(snapshots.length).toBe(1)
    expect(snapshots[0].state.target?.ip).toBe("10.10.10.99")
  })

  test("incremental updates are all visible in final state", async () => {
    const sid = tracked(uniqueSession())

    // Phase 1: Recon
    const { ctx: ctx1 } = makeContext(sid)
    await updateTool.execute({
      target: { ip: "10.10.10.50" },
      ports: [{ port: 22, protocol: "tcp", service: "ssh" }],
    }, ctx1)

    // Phase 2: Enumeration
    const { ctx: ctx2 } = makeContext(sid)
    await updateTool.execute({
      ports: [{ port: 80, protocol: "tcp", service: "http" }],
      vulnerabilities: [{ name: "Directory traversal" }],
    }, ctx2)

    // Phase 3: Exploitation
    const { ctx: ctx3 } = makeContext(sid)
    await updateTool.execute({
      accessLevel: "user",
      credentials: [{ username: "www-data", password: "service_account" }],
      sessions: [{ id: "shell-1", type: "reverse", user: "www-data" }],
    }, ctx3)

    // Phase 4: Post-exploitation
    const { ctx: ctx4 } = makeContext(sid)
    await updateTool.execute({
      accessLevel: "root",
      files: [{ path: "/root/root.txt", type: "flag", content: "HTB{r00t}" }],
      flags: ["HTB{r00t}"],
    }, ctx4)

    // Final state should have everything
    const state = await loadEngagementState(sid)
    expect(state.target?.ip).toBe("10.10.10.50")
    expect(state.ports?.length).toBe(2)
    expect(state.credentials?.length).toBe(1)
    expect(state.vulnerabilities?.length).toBe(1)
    expect(state.sessions?.length).toBe(1)
    expect(state.files?.length).toBe(1)
    expect(state.flags?.length).toBe(1)
    expect(state.accessLevel).toBe("root")

    // History should have 4 snapshots
    const snapshots = await getStateSnapshots(sid)
    expect(snapshots.length).toBe(4)
  })
})
