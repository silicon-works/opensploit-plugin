/**
 * ADVERSARIAL TESTS for Trajectory Recording, Event Hook, Session Directory, Session Hierarchy
 *
 * Source files under attack:
 * - src/training/trajectory.ts (~137 lines)
 * - src/hooks/event.ts (~393 lines)
 * - src/session/directory.ts (~203 lines)
 * - src/session/hierarchy.ts (~83 lines)
 *
 * Every test has a HYPOTHESIS about what might be wrong.
 * If the test fails, we found a bug. If it passes, the hypothesis was wrong.
 *
 * =========================================================================
 * BUGS FOUND (confirmed by tests):
 * =========================================================================
 *
 * BUG 1 [HIGH] Path traversal in rootSessionID (trajectory.ts) — CONFIRMED
 *   - appendEntry("../../tmp/evil", entry) creates dirs outside ~/.opensploit/sessions/
 *   - ensureSessionDir does path.join(SESSIONS_DIR, sessionID) with no validation
 *   - Same vector as output-store BUG 1b
 *   - Impact: Arbitrary directory creation + file writes outside sessions/
 *
 * BUG 2 [MEDIUM] Newlines in text fields break JSONL format — CONFIRMED
 *   - JSON.stringify preserves newlines as \n escape sequences in the JSON string
 *   - This is actually SAFE — JSON.stringify escapes embedded newlines to \n
 *   - The literal newline appended after each entry is the only line separator
 *   - NOT A BUG: JSON.stringify handles this correctly
 *   (Kept as documentation that this was tested)
 *
 * BUG 3 [MEDIUM] Circular references in entry crash appendEntry — CONFIRMED
 *   - JSON.stringify throws TypeError on circular structures
 *   - appendEntry has try/catch, so it logs error and swallows
 *   - But the entry is silently LOST — no indication to caller
 *   - Impact: Tool entries with circular data silently dropped
 *
 * BUG 4 [HIGH] Path traversal in sessionID (directory.ts) — CONFIRMED
 *   - create("../../tmp/X") -> path.join("/tmp","opensploit-session-../../tmp/X") -> "/tmp/tmp/X"
 *   - path.join normalizes ../ and escapes the opensploit-session- namespace entirely
 *   - Directory created outside the session prefix with full subdirectory structure
 *   - Impact: Directory creation outside session namespace via crafted session IDs
 *
 * BUG 5 [LOW] messageCache and writtenParts grow without bound (event.ts) — CONFIRMED
 *   - No eviction policy on either Map
 *   - Long-running process with many sessions leaks memory
 *   - Impact: Unbounded memory growth proportional to total messages processed
 *
 * BUG 6 [MEDIUM] writeSessionMeta with null fields writes "null" to JSON — CONFIRMED
 *   - JSON.stringify(null) = "null", JSON.stringify({field: null}) includes it
 *   - Not a crash, but downstream consumers may not expect null in typed fields
 *
 * BUG 7 [LOW] registerRootSession silently overwrites — CONFIRMED
 *   - Calling registerRootSession("child", "root-A") then ("child", "root-B")
 *   - Second call wins silently — no warning, no error
 *   - Impact: Mis-routed permissions if session re-registered with wrong root
 *
 * BUG 8 [MEDIUM] unregisterTree leaves orphaned grandchildren from chains — CONFIRMED
 *   - If A->B registered and B->C registered (B as root of C),
 *     unregisterTree(A) removes B's entry but NOT C's (C points to B, not A)
 *   - After unregisterTree(A), C still maps to B (now-deleted session)
 *   - Impact: Stale hierarchy entries after tree cleanup
 *
 * BUG 9 [MEDIUM] translateSessionPath with null bytes — CONFIRMED
 *   - No sanitization of null bytes in path
 *   - Node.js fs functions throw on null bytes in paths
 *   - translateSessionPath itself doesn't crash, but downstream fs calls will
 *
 * BUG 10 [LOW] Tool part with empty tool name recorded as-is — CONFIRMED
 *   - Part with tool: "" produces entry with tool: ""
 *   - No validation on tool name
 *
 * BUG 11 [HIGH] sessionID "../" in event.ts flows through to file writes — CONFIRMED
 *   - handlePartUpdated uses getRootSession(sessionID) which returns
 *     the raw sessionID if unregistered — then passes to appendEntry
 *   - No sanitization at any layer
 *   - Same root cause as BUG 1 and BUG 4
 *
 * =========================================================================
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import {
  mkdirSync,
  writeFileSync,
  readFileSync,
  rmSync,
  existsSync,
  appendFileSync,
  readdirSync,
  symlinkSync,
  lstatSync,
  statSync,
} from "fs"
import { join, resolve } from "path"
import { tmpdir } from "os"
import { randomBytes } from "crypto"

// === Source imports ===

import {
  ensureSessionDir,
  appendEntry,
  writeSessionMeta,
  type TrajectoryEntry,
  type SessionMeta,
} from "../../src/training/trajectory"

import { eventHook } from "../../src/hooks/event"

import * as SessionDirectory from "../../src/session/directory"

import {
  registerRootSession,
  getRootSession,
  hasParent,
  unregister,
  getChildren,
  unregisterTree,
} from "../../src/session/hierarchy"

// ============================================================================
// Helpers
// ============================================================================

const HOME = process.env.HOME ?? "/tmp"
const SESSIONS_DIR = join(HOME, ".opensploit", "sessions")

function testSessionId(): string {
  return `test-adv-trajsess-${randomBytes(8).toString("hex")}`
}

function strOfLen(n: number, char = "x"): string {
  return char.repeat(n)
}

function makeEntry(overrides: Partial<TrajectoryEntry> = {}): TrajectoryEntry {
  return {
    sessionID: overrides.sessionID ?? "test-session",
    messageID: overrides.messageID ?? "msg-001",
    partID: overrides.partID ?? "part-001",
    agentName: overrides.agentName ?? "master",
    role: overrides.role ?? "assistant",
    modelID: overrides.modelID ?? "claude-sonnet-4",
    providerID: overrides.providerID ?? "anthropic",
    timestamp: overrides.timestamp ?? new Date().toISOString(),
    type: overrides.type ?? "text",
    text: overrides.text ?? "hello world",
    ...overrides,
  }
}

function readTrajectory(sessionId: string): TrajectoryEntry[] {
  const filePath = join(SESSIONS_DIR, sessionId, "trajectory.jsonl")
  if (!existsSync(filePath)) return []
  const lines = readFileSync(filePath, "utf-8").split("\n").filter(Boolean)
  return lines.map((l) => JSON.parse(l))
}

function cleanupTestSession(sessionId: string): void {
  const dir = join(SESSIONS_DIR, sessionId)
  if (existsSync(dir)) {
    rmSync(dir, { recursive: true, force: true })
  }
}

// Track sessions for cleanup
const sessionsToClean: string[] = []
// Track hierarchy registrations for cleanup
const hierarchyToClean: string[] = []
// Track session directories for cleanup
const sessionDirsToClean: string[] = []

afterEach(() => {
  for (const sid of sessionsToClean) {
    cleanupTestSession(sid)
  }
  sessionsToClean.length = 0

  for (const sid of hierarchyToClean) {
    unregister(sid)
  }
  hierarchyToClean.length = 0

  for (const sid of sessionDirsToClean) {
    SessionDirectory.cleanup(sid)
  }
  sessionDirsToClean.length = 0
})

// ============================================================================
// 1. TRAJECTORY RECORDING — appendEntry
// ============================================================================

describe("Trajectory: appendEntry adversarial", () => {
  test("1MB text field — should write without crash", () => {
    // HYPOTHESIS: Very large entries might cause issues with sync writes or JSON.stringify
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const bigText = strOfLen(1_000_000) // 1MB
    const entry = makeEntry({ text: bigText })

    // Should not throw
    appendEntry(sid, entry)

    const entries = readTrajectory(sid)
    expect(entries.length).toBe(1)
    expect(entries[0].text!.length).toBe(1_000_000)
  })

  test("Entry with newlines in text — JSONL integrity preserved", () => {
    // HYPOTHESIS: Newlines in text fields might break JSONL (one-line-per-entry)
    // RESULT: JSON.stringify escapes \n to \\n, so JSONL is safe.
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const textWithNewlines = "line1\nline2\nline3\n\n\n"
    appendEntry(sid, makeEntry({ text: textWithNewlines, partID: "p1" }))
    appendEntry(sid, makeEntry({ text: "clean text", partID: "p2" }))

    // Read raw file and verify exactly 2 lines
    const filePath = join(SESSIONS_DIR, sid, "trajectory.jsonl")
    const raw = readFileSync(filePath, "utf-8")
    const lines = raw.split("\n").filter(Boolean)
    expect(lines.length).toBe(2)

    // Both should parse correctly
    const e1 = JSON.parse(lines[0])
    const e2 = JSON.parse(lines[1])
    expect(e1.text).toBe(textWithNewlines)
    expect(e2.text).toBe("clean text")
  })

  test("BUG 3: Entry with circular references — silently lost", () => {
    // HYPOTHESIS: JSON.stringify crashes on circular refs, appendEntry catches it
    // RESULT: appendEntry has try/catch, logs error, entry is silently DROPPED
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const circular: any = { a: 1 }
    circular.self = circular

    const entry = makeEntry({ toolInput: circular, type: "tool", tool: "test" })

    // Should not throw (try/catch in appendEntry)
    appendEntry(sid, entry)

    // But the entry was NOT written
    const entries = readTrajectory(sid)
    expect(entries.length).toBe(0) // Entry silently lost — BUG 3 confirmed
  })

  test("BUG 1 FIXED: rootSessionID with path traversal — blocked by validation", () => {
    // HYPOTHESIS (original): No sanitization on rootSessionID
    // FIX: ensureSessionDir now validates sessionID and throws internally.
    // appendEntry catches the error (best-effort recording), so it does NOT throw
    // to the caller — but the file is NOT written outside sessions/.
    const escapeSuffix = `adv-traj-escape-${randomBytes(4).toString("hex")}`
    const maliciousID = `../../tmp/${escapeSuffix}`

    // appendEntry catches the validation error internally (no throw to caller)
    appendEntry(maliciousID, makeEntry({ text: "escaped!" }))

    // Verify file was NOT written outside sessions/
    const escapedDir = resolve(SESSIONS_DIR, maliciousID)
    const escapedFile = join(escapedDir, "trajectory.jsonl")
    expect(existsSync(escapedFile)).toBe(false)
  })

  test("Rapid sequential writes — ordering preserved", () => {
    // HYPOTHESIS: appendFileSync is synchronous, so ordering should be fine
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const count = 100
    for (let i = 0; i < count; i++) {
      appendEntry(sid, makeEntry({ partID: `part-${i}`, text: `entry-${i}` }))
    }

    const entries = readTrajectory(sid)
    expect(entries.length).toBe(count)

    // Verify order
    for (let i = 0; i < count; i++) {
      expect(entries[i].partID).toBe(`part-${i}`)
    }
  })

  test("Trailing incomplete line from simulated crash — new entries still valid", () => {
    // HYPOTHESIS: If a previous crash left a partial line, the next appendEntry
    // starts a new line, but the partial line corrupts the file
    const sid = testSessionId()
    sessionsToClean.push(sid)

    // Manually create a trajectory with a corrupted trailing line
    const dir = ensureSessionDir(sid)
    const filePath = join(dir, "trajectory.jsonl")
    const goodLine = JSON.stringify(makeEntry({ partID: "good" }))
    writeFileSync(filePath, goodLine + "\n{broken json here", "utf-8")

    // Now append a new entry
    appendEntry(sid, makeEntry({ partID: "new-after-crash" }))

    // Read raw and check
    const raw = readFileSync(filePath, "utf-8")
    const lines = raw.split("\n").filter(Boolean)

    // There should be 3 "lines":
    // 1. good JSON
    // 2. {broken json here (corrupted)
    // 3. new valid JSON appended after the broken line
    // BUT — the broken line has no trailing \n, so appendEntry appends
    // directly after it: "{broken json here{"sessionID":..."
    // This means the new entry is concatenated onto the broken line!
    expect(lines.length).toBe(2) // Only 2 lines, not 3!

    // First line is good
    const e1 = JSON.parse(lines[0])
    expect(e1.partID).toBe("good")

    // Second "line" is the broken line + new entry concatenated — UNPARSEABLE
    // This documents the corruption behavior
    expect(() => JSON.parse(lines[1])).toThrow()
  })

  test("Entry with special JSON characters in text", () => {
    // HYPOTHESIS: Quotes, backslashes, unicode — might break JSON
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const nastyText = `He said "hello\\" and then \u0000\u001f\t\r\n done`
    appendEntry(sid, makeEntry({ text: nastyText }))

    const entries = readTrajectory(sid)
    expect(entries.length).toBe(1)
    expect(entries[0].text).toBe(nastyText)
  })

  test("Empty string sessionID FIXED — blocked by validation", () => {
    // HYPOTHESIS (original): path.join(SESSIONS_DIR, "") = SESSIONS_DIR itself
    // FIX: ensureSessionDir now rejects empty string sessionID.
    // appendEntry catches the error internally (no throw to caller).
    const entry = makeEntry({ text: "empty sid" })

    // appendEntry catches the validation error internally (no throw to caller)
    appendEntry("", entry)

    // Verify trajectory.jsonl was NOT written to SESSIONS_DIR itself
    const filePath = join(SESSIONS_DIR, "trajectory.jsonl")
    expect(existsSync(filePath)).toBe(false)
  })
})

// ============================================================================
// 2. TRAJECTORY RECORDING — writeSessionMeta
// ============================================================================

describe("Trajectory: writeSessionMeta adversarial", () => {
  test("BUG 6: Null/undefined fields in SessionMeta", () => {
    // HYPOTHESIS: null values get serialized as "null" in JSON
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const meta: SessionMeta = {
      sessionID: sid,
      model: null as any,
      providerID: undefined as any,
      startTime: "2026-01-01T00:00:00.000Z",
      title: null as any,
    }

    writeSessionMeta(sid, meta)

    const filePath = join(SESSIONS_DIR, sid, "session.json")
    const content = readFileSync(filePath, "utf-8")
    const parsed = JSON.parse(content)

    // null is preserved, undefined is stripped by JSON.stringify
    expect(parsed.model).toBeNull() // Written as null — BUG 6
    expect(parsed.providerID).toBeUndefined() // undefined stripped
    expect(parsed.title).toBeNull()
  })

  test("writeSessionMeta overwrites previous meta", () => {
    // HYPOTHESIS: writeFileSync overwrites — so second call replaces first
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const meta1: SessionMeta = {
      sessionID: sid,
      model: "model-1",
      providerID: "provider-1",
      startTime: "2026-01-01T00:00:00.000Z",
      title: "First",
    }
    writeSessionMeta(sid, meta1)

    const meta2: SessionMeta = {
      sessionID: sid,
      model: "model-2",
      providerID: "provider-2",
      startTime: "2026-01-02T00:00:00.000Z",
    }
    writeSessionMeta(sid, meta2)

    const filePath = join(SESSIONS_DIR, sid, "session.json")
    const parsed = JSON.parse(readFileSync(filePath, "utf-8"))

    // Second write wins — title from first write is gone
    expect(parsed.model).toBe("model-2")
    expect(parsed.title).toBeUndefined()
  })
})

// ============================================================================
// 3. EVENT HOOK
// ============================================================================

describe("Event hook: adversarial", () => {
  test("message.updated with no info.id — no crash", async () => {
    // HYPOTHESIS: Missing messageID causes crash in handleMessageUpdated
    await expect(
      eventHook({
        event: {
          type: "message.updated",
          properties: { info: { sessionID: "s1", role: "assistant" } },
        },
      }),
    ).resolves.toBeUndefined()
  })

  test("message.updated with no properties — no crash", async () => {
    await expect(
      eventHook({
        event: { type: "message.updated" },
      }),
    ).resolves.toBeUndefined()
  })

  test("message.part.updated with no sessionID — no crash", async () => {
    // HYPOTHESIS: Missing sessionID in part might cause crash
    await expect(
      eventHook({
        event: {
          type: "message.part.updated",
          properties: {
            part: {
              id: "p1",
              messageID: "m1",
              // sessionID is missing
              type: "text",
              text: "hello",
            },
          },
        },
      }),
    ).resolves.toBeUndefined()
  })

  test("message.part.updated with no part — no crash", async () => {
    await expect(
      eventHook({
        event: {
          type: "message.part.updated",
          properties: {},
        },
      }),
    ).resolves.toBeUndefined()
  })

  test("Unknown event type — silent pass-through", async () => {
    // HYPOTHESIS: Event types not in the switch statement should be silently ignored
    await expect(
      eventHook({
        event: { type: "session.deleted", properties: {} },
      }),
    ).resolves.toBeUndefined()

    await expect(
      eventHook({
        event: { type: "completely.made.up.event" },
      }),
    ).resolves.toBeUndefined()
  })

  test("Tool part in 'running' state — NOT recorded", async () => {
    // HYPOTHESIS: Only "completed" and "error" tool states are recorded
    const sid = testSessionId()
    sessionsToClean.push(sid)

    // Register session in hierarchy so getRootSession returns it
    registerRootSession(sid, sid)
    hierarchyToClean.push(sid)

    // First, cache the message
    await eventHook({
      event: {
        type: "message.updated",
        properties: {
          info: {
            id: "msg-running-test",
            sessionID: sid,
            role: "assistant",
            modelID: "test",
            providerID: "test",
            agent: "master",
          },
        },
      },
    })

    // Send tool part in "running" state
    await eventHook({
      event: {
        type: "message.part.updated",
        properties: {
          part: {
            id: "tool-running-1",
            messageID: "msg-running-test",
            sessionID: sid,
            type: "tool",
            tool: "nmap",
            callID: "call-1",
            state: {
              status: "running",
              input: { target: "10.10.10.1" },
            },
          },
        },
      },
    })

    // No entry should have been written
    const entries = readTrajectory(sid)
    expect(entries.length).toBe(0)
  })

  test("Tool part transitions running -> completed — single entry", async () => {
    // HYPOTHESIS: The writtenParts map prevents duplicate writes
    const sid = testSessionId()
    sessionsToClean.push(sid)
    registerRootSession(sid, sid)
    hierarchyToClean.push(sid)

    // Cache the message
    await eventHook({
      event: {
        type: "message.updated",
        properties: {
          info: {
            id: "msg-transition-test",
            sessionID: sid,
            role: "assistant",
            modelID: "test-model",
            providerID: "test-provider",
            agent: "master",
          },
        },
      },
    })

    const partBase = {
      id: "tool-transition-1",
      messageID: "msg-transition-test",
      sessionID: sid,
      type: "tool",
      tool: "nmap",
      callID: "call-t1",
    }

    // Send pending
    await eventHook({
      event: {
        type: "message.part.updated",
        properties: {
          part: { ...partBase, state: { status: "pending", input: { target: "10.10.10.1" } } },
        },
      },
    })

    // Send running
    await eventHook({
      event: {
        type: "message.part.updated",
        properties: {
          part: { ...partBase, state: { status: "running", input: { target: "10.10.10.1" } } },
        },
      },
    })

    // Send completed
    await eventHook({
      event: {
        type: "message.part.updated",
        properties: {
          part: {
            ...partBase,
            state: {
              status: "completed",
              input: { target: "10.10.10.1" },
              output: "22/tcp open ssh",
              time: { start: 1000, end: 2000 },
            },
          },
        },
      },
    })

    const entries = readTrajectory(sid)
    expect(entries.length).toBe(1)
    expect(entries[0].toolSuccess).toBe(true)
    expect(entries[0].toolOutput).toBe("22/tcp open ssh")
    expect(entries[0].toolDuration).toBe(1000)
  })

  test("Duplicate completed tool part — only written once", async () => {
    // HYPOTHESIS: writtenParts prevents duplicate completed writes
    const sid = testSessionId()
    sessionsToClean.push(sid)
    registerRootSession(sid, sid)
    hierarchyToClean.push(sid)

    await eventHook({
      event: {
        type: "message.updated",
        properties: {
          info: {
            id: "msg-dup-test",
            sessionID: sid,
            role: "assistant",
            modelID: "test",
            providerID: "test",
            agent: "master",
          },
        },
      },
    })

    const toolPart = {
      id: "tool-dup-1",
      messageID: "msg-dup-test",
      sessionID: sid,
      type: "tool",
      tool: "sqlmap",
      callID: "call-d1",
      state: {
        status: "completed",
        input: { url: "http://target/vuln" },
        output: "injectable!",
        time: { start: 100, end: 200 },
      },
    }

    // Send completed twice
    await eventHook({ event: { type: "message.part.updated", properties: { part: toolPart } } })
    await eventHook({ event: { type: "message.part.updated", properties: { part: toolPart } } })

    const entries = readTrajectory(sid)
    expect(entries.length).toBe(1)
  })

  test("Text part with empty text — NOT recorded", async () => {
    // HYPOTHESIS: Empty text parts are skipped (line 222: if !part.text return)
    const sid = testSessionId()
    sessionsToClean.push(sid)
    registerRootSession(sid, sid)
    hierarchyToClean.push(sid)

    await eventHook({
      event: {
        type: "message.updated",
        properties: {
          info: {
            id: "msg-empty-text",
            sessionID: sid,
            role: "assistant",
            modelID: "test",
            providerID: "test",
            agent: "master",
          },
        },
      },
    })

    await eventHook({
      event: {
        type: "message.part.updated",
        properties: {
          part: {
            id: "text-empty-1",
            messageID: "msg-empty-text",
            sessionID: sid,
            type: "text",
            text: "", // empty
          },
        },
      },
    })

    const entries = readTrajectory(sid)
    expect(entries.length).toBe(0)
  })

  test("Synthetic text part — NOT recorded", async () => {
    // HYPOTHESIS: synthetic flag causes skip (line 226)
    const sid = testSessionId()
    sessionsToClean.push(sid)
    registerRootSession(sid, sid)
    hierarchyToClean.push(sid)

    await eventHook({
      event: {
        type: "message.updated",
        properties: {
          info: {
            id: "msg-synthetic",
            sessionID: sid,
            role: "assistant",
            modelID: "test",
            providerID: "test",
            agent: "master",
          },
        },
      },
    })

    await eventHook({
      event: {
        type: "message.part.updated",
        properties: {
          part: {
            id: "text-synthetic-1",
            messageID: "msg-synthetic",
            sessionID: sid,
            type: "text",
            text: "This is synthetic",
            synthetic: true,
          },
        },
      },
    })

    const entries = readTrajectory(sid)
    expect(entries.length).toBe(0)
  })

  test("TVAR part with no thought — NOT recorded", async () => {
    // HYPOTHESIS: Empty thought causes skip (line 223: if !part.thought return)
    const sid = testSessionId()
    sessionsToClean.push(sid)
    registerRootSession(sid, sid)
    hierarchyToClean.push(sid)

    await eventHook({
      event: {
        type: "message.updated",
        properties: {
          info: {
            id: "msg-tvar-nothought",
            sessionID: sid,
            role: "assistant",
            modelID: "test",
            providerID: "test",
            agent: "master",
          },
        },
      },
    })

    await eventHook({
      event: {
        type: "message.part.updated",
        properties: {
          part: {
            id: "tvar-nothought-1",
            messageID: "msg-tvar-nothought",
            sessionID: sid,
            type: "tvar",
            // thought is missing
            verify: "check it",
          },
        },
      },
    })

    const entries = readTrajectory(sid)
    expect(entries.length).toBe(0)
  })

  test("BUG 10: Tool part with empty tool name — recorded with empty string", () => {
    // HYPOTHESIS: No validation on tool field name
    const sid = testSessionId()
    sessionsToClean.push(sid)
    registerRootSession(sid, sid)
    hierarchyToClean.push(sid)

    // Synchronous test via direct appendEntry since event hook is async
    const entry = makeEntry({
      type: "tool",
      tool: "",
      callID: "call-empty",
      toolInput: { x: 1 },
      toolSuccess: true,
    })

    appendEntry(sid, entry)
    const entries = readTrajectory(sid)
    expect(entries.length).toBe(1)
    expect(entries[0].tool).toBe("") // Empty tool name — BUG 10
  })

  test("BUG 11 FIXED: sessionID with path traversal — event hook catches validation error gracefully", async () => {
    // HYPOTHESIS (original): getRootSession returns raw sessionID if not registered,
    // and that flows directly into appendEntry with no sanitization.
    // FIX: appendEntry now throws on traversal, and the event hook's try/catch
    // catches it — no crash, no escaped file.
    const escapeSuffix = `adv-evt-escape-${randomBytes(4).toString("hex")}`
    const maliciousSID = `../../tmp/${escapeSuffix}`

    // DO NOT register in hierarchy — getRootSession will return raw malicious ID

    // Cache the message (use normal-looking messageID)
    await eventHook({
      event: {
        type: "message.updated",
        properties: {
          info: {
            id: "msg-path-traversal",
            sessionID: maliciousSID,
            role: "assistant",
            modelID: "test",
            providerID: "test",
            agent: "master",
          },
        },
      },
    })

    // Send a text part — event hook should NOT throw (try/catch handles it)
    await expect(
      eventHook({
        event: {
          type: "message.part.updated",
          properties: {
            part: {
              id: `text-traversal-${escapeSuffix}`,
              messageID: "msg-path-traversal",
              sessionID: maliciousSID,
              type: "text",
              text: "I escaped the sessions directory!",
            },
          },
        },
      }),
    ).resolves.toBeUndefined()

    // Verify file was NOT written outside sessions/
    const escapedDir = resolve(SESSIONS_DIR, maliciousSID)
    const escapedFile = join(escapedDir, "trajectory.jsonl")
    expect(existsSync(escapedFile)).toBe(false)
  })

  test("session.created with parentID — session.json NOT written", async () => {
    // HYPOTHESIS: handleSessionCreated skips sessions with parentID (line 101)
    const sid = testSessionId()
    sessionsToClean.push(sid)

    await eventHook({
      event: {
        type: "session.created",
        properties: {
          info: {
            id: sid,
            parentID: "some-parent", // has parent — should skip
            time: { created: Date.now() },
            title: "Should not be written",
          },
        },
      },
    })

    const filePath = join(SESSIONS_DIR, sid, "session.json")
    expect(existsSync(filePath)).toBe(false)
  })

  test("session.created for root session — writes session.json", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    await eventHook({
      event: {
        type: "session.created",
        properties: {
          info: {
            id: sid,
            // no parentID — this is a root session
            time: { created: 1700000000000 },
            title: "Test Pentest",
          },
        },
      },
    })

    const filePath = join(SESSIONS_DIR, sid, "session.json")
    expect(existsSync(filePath)).toBe(true)

    const parsed = JSON.parse(readFileSync(filePath, "utf-8"))
    expect(parsed.sessionID).toBe(sid)
    expect(parsed.title).toBe("Test Pentest")
    expect(parsed.model).toBe("unknown")
  })

  test("Part for unknown message — still recorded with defaults", async () => {
    // HYPOTHESIS: If messageCache doesn't have the messageID, the hook
    // should still record with fallback values
    const sid = testSessionId()
    sessionsToClean.push(sid)
    registerRootSession(sid, sid)
    hierarchyToClean.push(sid)

    // Send part WITHOUT preceding message.updated
    await eventHook({
      event: {
        type: "message.part.updated",
        properties: {
          part: {
            id: "orphan-part-1",
            messageID: "msg-never-seen",
            sessionID: sid,
            type: "text",
            text: "I have no message",
          },
        },
      },
    })

    const entries = readTrajectory(sid)
    expect(entries.length).toBe(1)
    expect(entries[0].role).toBe("assistant") // default
    expect(entries[0].modelID).toBe("unknown") // default
    expect(entries[0].agentName).toBe("master") // default
  })

  test("resolveAgentName maps 'pentest' and 'build' to 'master'", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)
    registerRootSession(sid, sid)
    hierarchyToClean.push(sid)

    // Send message with agent: "pentest"
    await eventHook({
      event: {
        type: "message.updated",
        properties: {
          info: {
            id: "msg-agent-map",
            sessionID: sid,
            role: "assistant",
            modelID: "test",
            providerID: "test",
            agent: "pentest",
          },
        },
      },
    })

    await eventHook({
      event: {
        type: "message.part.updated",
        properties: {
          part: {
            id: "part-agent-map",
            messageID: "msg-agent-map",
            sessionID: sid,
            type: "text",
            text: "agent mapping test",
          },
        },
      },
    })

    const entries = readTrajectory(sid)
    expect(entries.length).toBe(1)
    expect(entries[0].agentName).toBe("master") // "pentest" mapped to "master"
  })

  test("Tool error part — recorded with toolSuccess=false", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)
    registerRootSession(sid, sid)
    hierarchyToClean.push(sid)

    await eventHook({
      event: {
        type: "message.updated",
        properties: {
          info: {
            id: "msg-tool-error",
            sessionID: sid,
            role: "assistant",
            modelID: "test",
            providerID: "test",
            agent: "master",
          },
        },
      },
    })

    await eventHook({
      event: {
        type: "message.part.updated",
        properties: {
          part: {
            id: "tool-error-1",
            messageID: "msg-tool-error",
            sessionID: sid,
            type: "tool",
            tool: "nmap",
            callID: "call-err",
            state: {
              status: "error",
              input: { target: "10.10.10.1" },
              error: "Connection refused",
              time: { start: 1000, end: 1500 },
            },
          },
        },
      },
    })

    const entries = readTrajectory(sid)
    expect(entries.length).toBe(1)
    expect(entries[0].toolSuccess).toBe(false)
    expect(entries[0].toolError).toBe("Connection refused")
    expect(entries[0].toolDuration).toBe(500)
  })
})

// ============================================================================
// 4. SESSION DIRECTORY
// ============================================================================

describe("Session directory: adversarial", () => {
  test("BUG 4 FIXED: create() with path traversal sessionID — throws on invalid sessionID", () => {
    // HYPOTHESIS (original): create("../../tmp/X") collapses ../ in path.join, escaping
    // the opensploit-session- prefix entirely.
    // FIX: create() now validates sessionID and throws on traversal sequences.
    const escapeSuffix = `adv-dir-escape-${randomBytes(4).toString("hex")}`
    const maliciousID = `../../tmp/${escapeSuffix}`

    expect(() => SessionDirectory.create(maliciousID)).toThrow("Invalid sessionID")

    // Verify directory was NOT created outside session namespace
    const escapedDir = resolve(join(tmpdir(), `opensploit-session-${maliciousID}`))
    expect(existsSync(escapedDir)).toBe(false)
  })

  test("create() with empty string sessionID FIXED — throws on invalid sessionID", () => {
    // HYPOTHESIS (original): path.join(tmpdir(), "opensploit-session-") is the dir
    // FIX: create() now rejects empty string sessionID
    expect(() => SessionDirectory.create("")).toThrow("Invalid sessionID")

    // Verify no directory was created with trailing dash
    const badDir = join(tmpdir(), "opensploit-session-")
    expect(existsSync(badDir)).toBe(false)
  })

  test("create() is idempotent — second call does not recreate subdirs", () => {
    const sid = testSessionId()
    sessionDirsToClean.push(sid)

    const dir1 = SessionDirectory.create(sid)

    // Write a file in findings
    writeFileSync(join(dir1, "findings", "test.txt"), "hello")

    // Call create again
    const dir2 = SessionDirectory.create(sid)

    expect(dir1).toBe(dir2)
    // File should still be there (not destroyed by re-creation)
    expect(readFileSync(join(dir2, "findings", "test.txt"), "utf-8")).toBe("hello")
  })

  test("cleanup() while files exist — removes everything", () => {
    const sid = testSessionId()

    const dir = SessionDirectory.create(sid)

    // Write files in various locations
    writeFileSync(join(dir, "findings", "recon.md"), "# Recon findings")
    writeFileSync(join(dir, "artifacts", "loot", "passwords.txt"), "admin:admin")
    writeFileSync(join(dir, "state.yaml"), "target: 10.10.10.1")

    SessionDirectory.cleanup(sid)

    expect(existsSync(dir)).toBe(false)
  })

  test("BUG 9: translateSessionPath with null bytes — no validation", () => {
    // HYPOTHESIS: Null bytes in path are not sanitized.
    // Node.js fs throws on null bytes in paths, but Bun silently accepts them.
    // Either way, translateSessionPath does no sanitization itself.
    const sid = testSessionId()
    sessionDirsToClean.push(sid)

    const result = SessionDirectory.translateSessionPath("/session/findings/re\x00con.md", sid)

    // The function returns a path containing the null byte — no validation
    expect(typeof result).toBe("string")
    expect(result).toContain("\x00") // Null byte passes through unsanitized

    // In Bun, existsSync does not throw on null bytes (returns false).
    // In Node.js, it throws TypeError. Either way, the path is corrupted.
    // The function should reject or sanitize null bytes.
    // BUG 9: No input validation at all — null bytes pass through to callers.
  })

  test("translateSessionPath with non-session path — returns as-is", () => {
    const result = SessionDirectory.translateSessionPath("/etc/passwd", "some-session")
    expect(result).toBe("/etc/passwd")
  })

  test("translateSessionPath with /session/ prefix — resolves to root session", () => {
    const rootSid = testSessionId()
    const childSid = testSessionId()
    sessionDirsToClean.push(rootSid)
    registerRootSession(childSid, rootSid)
    hierarchyToClean.push(childSid)

    // Create the root session dir
    SessionDirectory.create(rootSid)

    const result = SessionDirectory.translateSessionPath("/session/findings/recon.md", childSid)
    const expected = join(SessionDirectory.get(rootSid), "findings", "recon.md")
    expect(result).toBe(expected)
  })

  test("writeFinding with path traversal in phase name", () => {
    // HYPOTHESIS: phase = "../../../tmp/evil" could escape findings/
    const sid = testSessionId()
    sessionDirsToClean.push(sid)
    SessionDirectory.create(sid)

    const maliciousPhase = "../escape-test"
    SessionDirectory.writeFinding(sid, maliciousPhase, "pwned!")

    // Check where the file actually ended up
    const dir = SessionDirectory.get(sid)
    // path.join(findingsDir, "../escape-test.md") = session-dir/escape-test.md
    const escapedPath = join(dir, "escape-test.md")
    const written = existsSync(escapedPath)

    // The file escapes from findings/ into the session dir root
    expect(written).toBe(true)
  })

  test("readFinding with path traversal in phase name", () => {
    // HYPOTHESIS: phase = "../state" reads state.yaml as a finding
    const sid = testSessionId()
    sessionDirsToClean.push(sid)
    SessionDirectory.create(sid)

    // Write a state.yaml in session dir
    const dir = SessionDirectory.get(sid)
    writeFileSync(join(dir, "state.yaml"), "target: 10.10.10.1")

    // Attempt to read it via phase traversal
    // readFinding joins: findingsDir + "../state.yaml" -> sessionDir/state.yaml? No:
    // join(findingsDir, "../state.yaml".md) — wait, readFinding does `${phase}.md`
    // So the actual file would be "../state.md" which is sessionDir/state.md
    // That file doesn't exist, so this specific attack doesn't work for .yaml
    // But for .md files in the parent dir it would
    writeFileSync(join(dir, "secret.md"), "top secret data")

    const content = SessionDirectory.readFinding(sid, "../secret")
    // phase="../secret" -> file = findingsDir + "/../secret.md" = sessionDir/secret.md
    expect(content).toBe("top secret data")
  })

  test("Symlink attack — session dir is a symlink", () => {
    // HYPOTHESIS: If someone pre-creates a symlink at the session path,
    // create() would follow it and write into the target
    const sid = testSessionId()
    const targetDir = join(tmpdir(), `adv-symlink-target-${randomBytes(4).toString("hex")}`)

    const sessionPath = SessionDirectory.get(sid)

    try {
      // Create symlink target
      mkdirSync(targetDir, { recursive: true })

      // Pre-create symlink at session path
      symlinkSync(targetDir, sessionPath)

      // Now call create — existsSync returns true for symlinks
      const dir = SessionDirectory.create(sid)

      // create() sees dir exists and skips — returns the symlink path
      expect(dir).toBe(sessionPath)

      // But the subdirectories were NOT created because existsSync returned true
      // for the symlink itself, so the function returned early
      expect(existsSync(join(dir, "findings"))).toBe(false)
    } finally {
      // Clean up
      if (lstatSync(sessionPath).isSymbolicLink()) {
        rmSync(sessionPath) // remove symlink
      } else if (existsSync(sessionPath)) {
        rmSync(sessionPath, { recursive: true, force: true })
      }
      if (existsSync(targetDir)) {
        rmSync(targetDir, { recursive: true, force: true })
      }
    }
  })
})

// ============================================================================
// 5. SESSION HIERARCHY
// ============================================================================

describe("Session hierarchy: adversarial", () => {
  test("getRootSession with unregistered session — returns self", () => {
    // HYPOTHESIS: Known behavior, but documents the fallback
    expect(getRootSession("never-registered")).toBe("never-registered")
  })

  test("BUG 7: registerRootSession called twice with different roots — silent overwrite", () => {
    // HYPOTHESIS: Second registration silently overwrites the first
    const child = `child-overwrite-${randomBytes(4).toString("hex")}`
    hierarchyToClean.push(child)

    registerRootSession(child, "root-A")
    expect(getRootSession(child)).toBe("root-A")

    registerRootSession(child, "root-B")
    expect(getRootSession(child)).toBe("root-B") // Silently changed — BUG 7

    // No warning, no error — the first root is just gone
  })

  test("Cycle: A->B and B->A registered", () => {
    // HYPOTHESIS: The system doesn't detect cycles
    const a = `cycle-a-${randomBytes(4).toString("hex")}`
    const b = `cycle-b-${randomBytes(4).toString("hex")}`
    hierarchyToClean.push(a, b)

    registerRootSession(a, b)
    registerRootSession(b, a)

    // getRootSession is a single lookup (not recursive), so no infinite loop
    expect(getRootSession(a)).toBe(b)
    expect(getRootSession(b)).toBe(a)

    // But logically this is inconsistent — neither is actually a root
    // getChildren sees cross-references
    expect(getChildren(a)).toContain(b)
    expect(getChildren(b)).toContain(a)
  })

  test("Self-registration: session mapped to itself", () => {
    // HYPOTHESIS: registerRootSession("X", "X") — hasParent should still be false
    const sid = `self-${randomBytes(4).toString("hex")}`
    hierarchyToClean.push(sid)

    registerRootSession(sid, sid)

    // hasParent checks: root !== undefined && root !== sessionID
    expect(hasParent(sid)).toBe(false) // Correct — self is not a parent
    expect(getRootSession(sid)).toBe(sid)
    expect(getChildren(sid)).toEqual([]) // Self-reference excluded by childID !== rootSessionID check
  })

  test("BUG 8: unregisterTree misses grandchildren from chains", () => {
    // HYPOTHESIS: If we have A->root-X and B->A (B's root is A, not root-X),
    // then unregisterTree(root-X) only removes A, not B.
    const rootX = `root-chain-${randomBytes(4).toString("hex")}`
    const childA = `child-chain-a-${randomBytes(4).toString("hex")}`
    const childB = `child-chain-b-${randomBytes(4).toString("hex")}`
    hierarchyToClean.push(rootX, childA, childB)

    // A is child of rootX
    registerRootSession(childA, rootX)
    // B is registered with A as its root (not rootX)
    registerRootSession(childB, childA)

    // Before cleanup
    expect(getRootSession(childA)).toBe(rootX)
    expect(getRootSession(childB)).toBe(childA)
    expect(getChildren(rootX)).toContain(childA)

    // Unregister tree for rootX
    unregisterTree(rootX)

    // childA is cleaned up (was child of rootX)
    expect(getRootSession(childA)).toBe(childA) // Falls back to self

    // BUG 8: childB still points to childA (which was removed)
    expect(getRootSession(childB)).toBe(childA) // Stale reference!
    // childB is now an orphan pointing to a deleted session
  })

  test("unregister for non-existent session — no crash", () => {
    // HYPOTHESIS: Deleting a non-existent key from Map is safe
    unregister("never-existed")
    expect(getRootSession("never-existed")).toBe("never-existed")
  })

  test("unregisterTree for root that has no children — safe", () => {
    const sid = `lone-root-${randomBytes(4).toString("hex")}`
    hierarchyToClean.push(sid)

    registerRootSession(sid, sid)
    unregisterTree(sid)

    expect(getRootSession(sid)).toBe(sid)
  })

  test("Large hierarchy — 100 children under one root", () => {
    // HYPOTHESIS: Performance/correctness with many children
    const root = `root-large-${randomBytes(4).toString("hex")}`
    const children: string[] = []

    for (let i = 0; i < 100; i++) {
      const child = `child-large-${i}-${randomBytes(4).toString("hex")}`
      children.push(child)
      hierarchyToClean.push(child)
      registerRootSession(child, root)
    }
    hierarchyToClean.push(root)

    const foundChildren = getChildren(root)
    expect(foundChildren.length).toBe(100)

    // Cleanup
    unregisterTree(root)
    expect(getChildren(root)).toEqual([])
  })

  test("unregister root that other sessions point to — orphans left behind", () => {
    // HYPOTHESIS: unregister (not unregisterTree) only removes one entry
    const root = `root-orphan-${randomBytes(4).toString("hex")}`
    const child1 = `child-orphan-1-${randomBytes(4).toString("hex")}`
    const child2 = `child-orphan-2-${randomBytes(4).toString("hex")}`
    hierarchyToClean.push(root, child1, child2)

    registerRootSession(child1, root)
    registerRootSession(child2, root)

    // Only unregister the root's own entry (if it exists) — children are not touched
    unregister(root)

    // Children still point to now-unregistered root
    expect(getRootSession(child1)).toBe(root) // Stale — root is gone but children still reference it
    expect(getRootSession(child2)).toBe(root)
  })
})

// ============================================================================
// 6. MEMORY LEAK SIMULATION (BUG 5)
// ============================================================================

describe("Event hook: memory leak vectors", () => {
  test("BUG 5: messageCache grows without bound", async () => {
    // HYPOTHESIS: Each message.updated adds to messageCache with no eviction
    // After many messages, memory grows unbounded

    // We'll send many unique messages and verify the cache doesn't evict
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const messageCount = 500
    for (let i = 0; i < messageCount; i++) {
      await eventHook({
        event: {
          type: "message.updated",
          properties: {
            info: {
              id: `leak-msg-${i}`,
              sessionID: sid,
              role: "assistant",
              modelID: "test",
              providerID: "test",
              agent: "master",
            },
          },
        },
      })
    }

    // We can't directly inspect messageCache since it's not exported,
    // but we can verify that earlier messages are still accessible
    // by sending a part referencing the first message
    registerRootSession(sid, sid)
    hierarchyToClean.push(sid)

    await eventHook({
      event: {
        type: "message.part.updated",
        properties: {
          part: {
            id: "leak-test-part",
            messageID: "leak-msg-0", // First message, 500 messages ago
            sessionID: sid,
            type: "text",
            text: "Still cached?",
          },
        },
      },
    })

    const entries = readTrajectory(sid)
    expect(entries.length).toBe(1)
    // If the first message is still cached, modelID should be "test" not "unknown"
    expect(entries[0].modelID).toBe("test") // BUG 5: all 500 messages still in memory
  })

  test("writtenParts grows without eviction — tool never completed", async () => {
    // HYPOTHESIS: writtenParts never cleans up tool entries that were recorded
    // Even after session ends, the entries linger in the Map
    const sid = testSessionId()
    sessionsToClean.push(sid)
    registerRootSession(sid, sid)
    hierarchyToClean.push(sid)

    await eventHook({
      event: {
        type: "message.updated",
        properties: {
          info: {
            id: "leak-tool-msg",
            sessionID: sid,
            role: "assistant",
            modelID: "test",
            providerID: "test",
            agent: "master",
          },
        },
      },
    })

    // Record 200 completed tool parts
    for (let i = 0; i < 200; i++) {
      await eventHook({
        event: {
          type: "message.part.updated",
          properties: {
            part: {
              id: `leak-tool-${i}`,
              messageID: "leak-tool-msg",
              sessionID: sid,
              type: "tool",
              tool: "nmap",
              callID: `call-leak-${i}`,
              state: {
                status: "completed",
                input: { target: "10.10.10.1" },
                output: `port ${i} open`,
                time: { start: i * 100, end: i * 100 + 50 },
              },
            },
          },
        },
      })
    }

    const entries = readTrajectory(sid)
    expect(entries.length).toBe(200)

    // All 200 partIDs are now in writtenParts Map forever
    // Send them again — they should be deduped (proving they're still in the map)
    for (let i = 0; i < 5; i++) {
      await eventHook({
        event: {
          type: "message.part.updated",
          properties: {
            part: {
              id: `leak-tool-${i}`, // Same partID
              messageID: "leak-tool-msg",
              sessionID: sid,
              type: "tool",
              tool: "nmap",
              callID: `call-leak-${i}`,
              state: {
                status: "completed",
                input: { target: "10.10.10.1" },
                output: `port ${i} open again`,
                time: { start: i * 100, end: i * 100 + 50 },
              },
            },
          },
        },
      })
    }

    // Still 200 — dedup works, proving entries persist in memory
    const entriesAfter = readTrajectory(sid)
    expect(entriesAfter.length).toBe(200)
  })
})

// ============================================================================
// 7. CROSS-MODULE INTEGRATION
// ============================================================================

describe("Cross-module: trajectory + hierarchy + directory", () => {
  test("Sub-agent writes to root session trajectory via hierarchy", async () => {
    const rootSid = testSessionId()
    const childSid = testSessionId()
    sessionsToClean.push(rootSid)
    registerRootSession(childSid, rootSid)
    hierarchyToClean.push(childSid)

    // Cache message for child session
    await eventHook({
      event: {
        type: "message.updated",
        properties: {
          info: {
            id: "child-msg-1",
            sessionID: childSid,
            role: "assistant",
            modelID: "test",
            providerID: "test",
            agent: "pentest/recon",
          },
        },
      },
    })

    // Send part from child session
    await eventHook({
      event: {
        type: "message.part.updated",
        properties: {
          part: {
            id: "child-part-1",
            messageID: "child-msg-1",
            sessionID: childSid,
            type: "text",
            text: "Found open ports: 22, 80, 443",
          },
        },
      },
    })

    // Entry should be in ROOT session's trajectory (not child)
    const rootEntries = readTrajectory(rootSid)
    expect(rootEntries.length).toBe(1)
    expect(rootEntries[0].sessionID).toBe(childSid) // Original sessionID preserved
    expect(rootEntries[0].agentName).toBe("pentest/recon") // Not remapped

    // Child session should NOT have its own trajectory file
    const childEntries = readTrajectory(childSid)
    expect(childEntries.length).toBe(0)
  })

  test("translateSessionPath resolves through hierarchy for sub-agent", () => {
    const rootSid = testSessionId()
    const childSid = testSessionId()
    sessionDirsToClean.push(rootSid)
    registerRootSession(childSid, rootSid)
    hierarchyToClean.push(childSid)

    // Create root session directory
    SessionDirectory.create(rootSid)

    // Child session translates /session/ path
    const translated = SessionDirectory.translateSessionPath("/session/findings/recon.md", childSid)
    const expected = join(SessionDirectory.get(rootSid), "findings", "recon.md")
    expect(translated).toBe(expected)
  })

  test("Complete engagement flow: session.created -> messages -> parts -> cleanup", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)
    sessionDirsToClean.push(sid)

    // 1. Create session directory
    SessionDirectory.create(sid)
    expect(SessionDirectory.exists(sid)).toBe(true)

    // 2. Session created event
    await eventHook({
      event: {
        type: "session.created",
        properties: {
          info: {
            id: sid,
            time: { created: Date.now() },
            title: "HTB Box Test",
          },
        },
      },
    })

    // 3. Message event
    await eventHook({
      event: {
        type: "message.updated",
        properties: {
          info: {
            id: "eng-msg-1",
            sessionID: sid,
            role: "assistant",
            modelID: "claude-sonnet-4",
            providerID: "anthropic",
            agent: "pentest",
            tokens: {
              input: 1000,
              output: 500,
              reasoning: 200,
              cache: { read: 100, write: 50 },
            },
            cost: 0.003,
          },
        },
      },
    })

    // 4. Text part
    await eventHook({
      event: {
        type: "message.part.updated",
        properties: {
          part: {
            id: "eng-text-1",
            messageID: "eng-msg-1",
            sessionID: sid,
            type: "text",
            text: "Starting reconnaissance on target 10.10.10.1",
          },
        },
      },
    })

    // 5. Tool part
    await eventHook({
      event: {
        type: "message.part.updated",
        properties: {
          part: {
            id: "eng-tool-1",
            messageID: "eng-msg-1",
            sessionID: sid,
            type: "tool",
            tool: "nmap",
            callID: "call-eng-1",
            state: {
              status: "completed",
              input: { target: "10.10.10.1", flags: "-sV -sC" },
              output: "22/tcp open ssh OpenSSH 8.9p1\n80/tcp open http Apache 2.4.52",
              time: { start: 1000, end: 5000 },
            },
          },
        },
      },
    })

    // 6. Verify trajectory
    const entries = readTrajectory(sid)
    expect(entries.length).toBe(2)

    expect(entries[0].type).toBe("text")
    expect(entries[0].agentName).toBe("master") // "pentest" -> "master"
    expect(entries[0].tokens!.input).toBe(1000)
    expect(entries[0].cost).toBe(0.003)

    expect(entries[1].type).toBe("tool")
    expect(entries[1].tool).toBe("nmap")
    expect(entries[1].toolDuration).toBe(4000)
    expect(entries[1].toolSuccess).toBe(true)

    // 7. Session.json exists
    const sessionJson = join(SESSIONS_DIR, sid, "session.json")
    expect(existsSync(sessionJson)).toBe(true)

    // 8. Write findings via session directory
    SessionDirectory.writeFinding(sid, "recon", "# Recon\n\nPorts: 22, 80")
    expect(SessionDirectory.readFinding(sid, "recon")).toContain("Ports: 22, 80")

    // 9. Cleanup
    SessionDirectory.cleanup(sid)
    expect(SessionDirectory.exists(sid)).toBe(false)
  })
})
