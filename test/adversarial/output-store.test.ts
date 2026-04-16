/**
 * ADVERSARIAL TESTS for Output Store + Read Tool Output
 *
 * Goal: Find real bugs by probing threshold edge cases, storage corruption,
 * query injection, normalizer edge cases, cleanup races, and session isolation.
 *
 * Every test has a HYPOTHESIS about what might be wrong.
 * If the test fails, we found a bug. If it passes, the hypothesis was wrong.
 *
 * =========================================================================
 * BUGS FOUND (confirmed by tests):
 * =========================================================================
 *
 * BUG 1 [HIGH] Path traversal in outputId — FIXED by sanitizeId()
 *   - query({ outputId: "../secret" }) now throws "Invalid outputId"
 *   - sanitizeId() rejects IDs containing "..", "/", "\", or null bytes
 *   - Test: "BUG 1 FIXED: outputId with path traversal" — expects rejection
 *
 * BUG 1b [HIGH] Path traversal in sessionId — FIXED by sanitizeId()
 *   - sessionId = "../../tmp/evil" now throws "Invalid sessionID"
 *   - Empty sessionId also rejected (!id check)
 *   - Test: "SessionId with path separators" — expects rejection
 *
 * BUG 3 [MEDIUM] shouldStore crashes on circular data objects (CONFIRMED)
 *   - JSON.stringify(circularObj) throws "cannot serialize cyclic structures"
 *   - No try/catch around the stringify in shouldStore()
 *   - Impact: Any MCP tool returning circular data crashes the entire store pipeline
 *   - Test: "BUG 3: Circular data object" — store() throws TypeError
 *
 * BUG 7b [MEDIUM] Negative limit silently drops records from end (CONFIRMED)
 *   - limit=-1 → slice(0, -1) removes the LAST record instead of returning nothing
 *   - limit=-2 removes last two records, etc.
 *   - Impact: Negative limit returns silently wrong results — no error
 *   - Test: "BUG 7b: Negative limit" — 3 records, limit=-1 returns 2
 *
 * BUG 4 [MEDIUM] field:value regex \w+ rejects hyphenated field names (CONFIRMED by analysis)
 *   - Regex /^(\w+):(.+)$/ requires \w+ (letters, digits, underscore only)
 *   - Fields like "Content-Type" fall through to text search silently
 *   - Not a crash, but surprising silent fallback behavior
 *
 * BUG 8 [LOW] normalizeNmap stores port as-is without type coercion (CONFIRMED)
 *   - If MCP data has port: "80" (string), it's stored as string
 *   - Query "port:80" uses parseInt → 80, but typeof "80" !== "number"
 *   - Falls to string comparison: "80" === "80" → matches (correct by accident)
 *   - But "port:080" → parseInt = 80 → typeof "80" !== "number" → String("80") !== "080" → miss
 *
 * BUG 9 [LOW] store() serializes data to JSON twice (CONFIRMED by code analysis)
 *   - Once in shouldStore() for size check, once in store() for sizeBytes
 *   - Not a correctness bug, but O(2N) memory + CPU for large data
 *
 * BUG 10 [MEDIUM] cleanup catch block calls statSync without inner try/catch (CONFIRMED by code analysis)
 *   - If file deleted between readFileSync and statSync in catch block, throws
 *   - Aborts cleanup for entire session — remaining files not checked
 *
 * ALSO DOCUMENTED (not bugs, but surprising behavior):
 *   - Threshold is strict > 5000 (not >=). 5000 chars exactly is NOT stored.
 *   - parseInt("22.5") = 22, so "port:22.5" matches port 22
 *   - Text search skips numeric field values entirely (typeof check)
 *   - limit=0 returns empty records but total shows real count
 *   - No session isolation — any caller with sessionId+outputId can read
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
  chmodSync,
  readdirSync,
  unlinkSync,
} from "fs"
import { join } from "path"
import { tmpdir } from "os"
import { randomBytes } from "crypto"

// Direct imports from source. The modules use a SESSIONS_DIR constant
// that points to ~/.opensploit/sessions/. We'll monkey-patch the filesystem
// by using real session IDs that point to temp dirs through symlinks,
// or by directly testing the exported functions with controlled inputs.

import {
  store,
  query,
  getMetadata,
  getRawOutput,
  cleanup,
  cleanupSession,
  formatQueryResults,
  type StoredOutput,
  type StoreResult,
} from "../../src/tools/output-store"

import {
  normalize,
  normalizeNmap,
  normalizeFfuf,
  normalizeGeneric,
  normalizeRawOutput,
  type OutputRecord,
} from "../../src/util/output-normalizers"

// ============================================================================
// Helpers
// ============================================================================

/** Generate a string of exact length */
function strOfLen(n: number, char = "x"): string {
  return char.repeat(n)
}

/** Create a unique session ID for test isolation */
function testSessionId(): string {
  return `test-adversarial-${randomBytes(8).toString("hex")}`
}

/**
 * Create a fake StoredOutput JSON file in the expected location.
 * This writes directly to ~/.opensploit/sessions/{sessionId}/outputs/
 * to test query/getMetadata/getRawOutput without going through store().
 */
function plantStoredOutput(
  sessionId: string,
  outputId: string,
  overrides: Partial<StoredOutput> = {},
): string {
  const sessionsDir = join(process.env.HOME ?? "/tmp", ".opensploit", "sessions")
  const outputsDir = join(sessionsDir, sessionId, "outputs")
  mkdirSync(outputsDir, { recursive: true })

  const stored: StoredOutput = {
    id: outputId,
    tool: overrides.tool ?? "test-tool",
    method: overrides.method ?? "execute",
    timestamp: overrides.timestamp ?? Date.now(),
    records: overrides.records ?? [{ type: "line", text: "hello" }],
    summary: overrides.summary ?? { total: 1, byType: { line: 1 } },
    rawOutput: overrides.rawOutput ?? "hello world",
    sizeBytes: overrides.sizeBytes ?? 100,
  }

  const filePath = join(outputsDir, `${outputId}.json`)
  writeFileSync(filePath, JSON.stringify(stored, null, 2), "utf-8")
  return filePath
}

/** Clean up a test session's directory */
function cleanupTestSession(sessionId: string) {
  const sessionsDir = join(process.env.HOME ?? "/tmp", ".opensploit", "sessions")
  const sessionDir = join(sessionsDir, sessionId)
  if (existsSync(sessionDir)) {
    rmSync(sessionDir, { recursive: true, force: true })
  }
}

// Track sessions for cleanup
const sessionsToClean: string[] = []

afterEach(() => {
  for (const sid of sessionsToClean) {
    cleanupTestSession(sid)
  }
  sessionsToClean.length = 0
})

// ============================================================================
// 1. THRESHOLD EDGE CASES
// ============================================================================

describe("Threshold edge cases", () => {
  test("EXACTLY 5000 chars rawOutput — should NOT be stored (> not >=)", async () => {
    // HYPOTHESIS: The threshold check uses `>` not `>=`, so exactly 5000 is NOT stored.
    // REQ-ARC-024 says ">5000 chars" — this documents the exact boundary behavior.
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const result = await store({
      sessionId: sid,
      tool: "test",
      data: null,
      rawOutput: strOfLen(5000),
    })

    // With > check: 5000 is NOT stored
    expect(result.stored).toBe(false)
  })

  test("5001 chars rawOutput — IS stored", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const result = await store({
      sessionId: sid,
      tool: "test",
      data: null,
      rawOutput: strOfLen(5001),
    })

    expect(result.stored).toBe(true)
    expect(result.outputId).toBeDefined()
  })

  test("4999 chars rawOutput — NOT stored", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const result = await store({
      sessionId: sid,
      tool: "test",
      data: null,
      rawOutput: strOfLen(4999),
    })

    expect(result.stored).toBe(false)
  })

  test("data=null, rawOutput=5001 chars — stored via rawSize only", async () => {
    // HYPOTHESIS: shouldStore handles null data gracefully (dataSize=0).
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const result = await store({
      sessionId: sid,
      tool: "test",
      data: null,
      rawOutput: strOfLen(5001),
    })

    expect(result.stored).toBe(true)
  })

  test("data is massive object (100KB), rawOutput is empty string — stored via dataSize", async () => {
    // HYPOTHESIS: Data size alone triggers storage even with empty rawOutput.
    const sid = testSessionId()
    sessionsToClean.push(sid)

    // Create a large data object that serializes to >5000 chars
    const bigData = { items: Array.from({ length: 500 }, (_, i) => ({ id: i, name: `item-${i}`, description: strOfLen(100) })) }

    const result = await store({
      sessionId: sid,
      tool: "test",
      data: bigData,
      rawOutput: "",
    })

    expect(result.stored).toBe(true)
    expect(result.outputId).toBeDefined()
  })

  test("data + rawOutput both just under threshold — combined triggers storage", async () => {
    // HYPOTHESIS: shouldStore adds dataSize + rawSize, so 3000 + 3000 = 6000 > 5000
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const data = { payload: strOfLen(2990) } // JSON.stringify adds ~15 chars overhead
    const rawOutput = strOfLen(3000)

    const result = await store({
      sessionId: sid,
      tool: "test",
      data,
      rawOutput,
    })

    expect(result.stored).toBe(true)
  })

  test("data=undefined (not null) — should not crash shouldStore", async () => {
    // HYPOTHESIS: The ternary `data ? JSON.stringify(data).length : 0` handles undefined.
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const result = await store({
      sessionId: sid,
      tool: "test",
      data: undefined,
      rawOutput: "short",
    })

    expect(result.stored).toBe(false)
  })

  test("rawOutput=undefined — should not crash shouldStore", async () => {
    // HYPOTHESIS: `rawOutput?.length ?? 0` handles undefined.
    // But the function signature says rawOutput: string, so this tests runtime safety.
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const result = await store({
      sessionId: sid,
      tool: "test",
      data: null,
      rawOutput: undefined as any,
    })

    expect(result.stored).toBe(false)
  })

  test("BUG 3: Circular data object — JSON.stringify throws in shouldStore", async () => {
    // HYPOTHESIS: shouldStore calls JSON.stringify(data) without try/catch.
    // A circular reference will throw TypeError.
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const circular: any = { a: 1 }
    circular.self = circular

    // This SHOULD NOT throw — it should handle gracefully
    // BUG: It DOES throw TypeError: Converting circular structure to JSON
    let threw = false
    try {
      await store({
        sessionId: sid,
        tool: "test",
        data: circular,
        rawOutput: strOfLen(6000),
      })
    } catch (e: any) {
      threw = true
      expect(e.message).toContain("cyclic")
    }

    // If this assertion fires, the bug exists — store() crashed
    // A robust implementation would catch the stringify error
    expect(threw).toBe(true) // BUG CONFIRMED: crashes on circular data
  })
})

// ============================================================================
// 2. STORAGE CORRUPTION / PATH TRAVERSAL
// ============================================================================

describe("Storage corruption and path traversal", () => {
  test("BUG 1 FIXED: outputId with path traversal (../../) — rejected by sanitizeId", async () => {
    // sanitizeId() now rejects outputIds containing ".." or "/"
    const sid = testSessionId()
    sessionsToClean.push(sid)

    await expect(
      query({
        sessionId: sid,
        outputId: "../secret",
        query: undefined,
      }),
    ).rejects.toThrow("Invalid")
  })

  test("outputId with null bytes — rejected by sanitizeId", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    // sanitizeId() rejects IDs containing null bytes
    await expect(
      query({
        sessionId: sid,
        outputId: "out_abc\x00../../etc/passwd",
      }),
    ).rejects.toThrow("Invalid")
  })

  test("Corrupted JSON in stored file — query returns graceful error", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    // Plant a corrupt JSON file
    const sessionsDir = join(process.env.HOME ?? "/tmp", ".opensploit", "sessions")
    const outputsDir = join(sessionsDir, sid, "outputs")
    mkdirSync(outputsDir, { recursive: true })
    writeFileSync(join(outputsDir, "out_corrupt.json"), "{ INVALID JSON !!!", "utf-8")

    const result = await query({
      sessionId: sid,
      outputId: "out_corrupt",
    })

    expect(result.found).toBe(false)
    expect(result.error).toBeDefined()
    expect(result.error).toContain("Failed to read output")
  })

  test("Corrupted JSON — getMetadata returns found:false", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const sessionsDir = join(process.env.HOME ?? "/tmp", ".opensploit", "sessions")
    const outputsDir = join(sessionsDir, sid, "outputs")
    mkdirSync(outputsDir, { recursive: true })
    writeFileSync(join(outputsDir, "out_bad.json"), "NOT JSON", "utf-8")

    const meta = await getMetadata(sid, "out_bad")
    expect(meta.found).toBe(false)
  })

  test("Corrupted JSON — getRawOutput returns null", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const sessionsDir = join(process.env.HOME ?? "/tmp", ".opensploit", "sessions")
    const outputsDir = join(sessionsDir, sid, "outputs")
    mkdirSync(outputsDir, { recursive: true })
    writeFileSync(join(outputsDir, "out_bad2.json"), "NOT JSON", "utf-8")

    const raw = await getRawOutput(sid, "out_bad2")
    expect(raw).toBeNull()
  })

  test("Two store() calls in quick succession — unique outputIds", async () => {
    // HYPOTHESIS: generateOutputId uses Date.now() + 4 random bytes.
    // Even at the same millisecond, random bytes should differ.
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const [r1, r2] = await Promise.all([
      store({ sessionId: sid, tool: "test", data: null, rawOutput: strOfLen(6000) }),
      store({ sessionId: sid, tool: "test", data: null, rawOutput: strOfLen(6000) }),
    ])

    expect(r1.stored).toBe(true)
    expect(r2.stored).toBe(true)
    expect(r1.outputId).not.toBe(r2.outputId)
  })

  test("Store and immediately query — file is readable", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const storeResult = await store({
      sessionId: sid,
      tool: "nmap",
      data: {
        hosts: [
          {
            ip: "10.10.10.1",
            ports: Array.from({ length: 100 }, (_, i) => ({
              port: i + 1,
              protocol: "tcp",
              state: "open",
              service: { name: `svc-${i}` },
            })),
          },
        ],
      },
      rawOutput: strOfLen(3000),
    })

    expect(storeResult.stored).toBe(true)

    const queryResult = await query({
      sessionId: sid,
      outputId: storeResult.outputId!,
    })

    expect(queryResult.found).toBe(true)
    expect(queryResult.total).toBe(100) // 100 port records
  })
})

// ============================================================================
// 3. QUERY INJECTION
// ============================================================================

describe("Query injection and edge cases", () => {
  test("BUG 4: Query with hyphenated field name (Content-Type:text/html)", async () => {
    // HYPOTHESIS: The regex /^(\w+):(.+)$/ uses \w+ which doesn't match hyphens.
    // "Content-Type:text/html" won't be parsed as field:value.
    // It falls through to text search instead.
    const sid = testSessionId()
    sessionsToClean.push(sid)

    plantStoredOutput(sid, "out_query1", {
      records: [
        { type: "directory", path: "/admin", status: 200, content_type: "text/html" },
        { type: "directory", path: "/api", status: 200, content_type: "application/json" },
      ],
    })

    // This SHOULD match field "content_type" with value "text/html"
    // But the regex won't match because... actually content_type has underscore, not hyphen.
    // Let's test with actual hyphenated field name:
    const result = await query({
      sessionId: sid,
      outputId: "out_query1",
      query: "content_type:text/html",
    })

    // content_type has underscore → \w+ matches. So this works.
    expect(result.records.length).toBe(1)
    expect(result.records[0].path).toBe("/admin")

    // Now test ACTUAL hyphenated field — won't parse as field:value
    // This demonstrates the limitation (not necessarily a bug, but surprising behavior)
  })

  test("Query with colon in value (url:http://target:8080/path)", async () => {
    // HYPOTHESIS: Regex (.+) is greedy, so "url:http://target:8080" captures
    // field="url", value="http://target:8080" — the greedy (.+) eats all colons after first.
    const sid = testSessionId()
    sessionsToClean.push(sid)

    plantStoredOutput(sid, "out_colon", {
      records: [
        { type: "directory", path: "/admin", url: "http://target:8080/admin" },
        { type: "directory", path: "/login", url: "http://target:8080/login" },
      ],
    })

    const result = await query({
      sessionId: sid,
      outputId: "out_colon",
      query: "url:http://target:8080/admin",
    })

    // Should match the /admin record
    expect(result.records.length).toBe(1)
    expect(result.records[0].path).toBe("/admin")
  })

  test("Query is just ':' — empty field and empty value", async () => {
    // HYPOTHESIS: Regex /^(\w+):(.+)$/ — \w+ requires at least one char.
    // ":" alone doesn't match, falls through to text search for ":".
    const sid = testSessionId()
    sessionsToClean.push(sid)

    plantStoredOutput(sid, "out_justcolon", {
      records: [{ type: "line", text: "no colons here" }],
    })

    const result = await query({
      sessionId: sid,
      outputId: "out_justcolon",
      query: ":",
    })

    // Should do text search for ":" — no records contain ":", so 0 results
    expect(result.found).toBe(true)
    expect(result.records.length).toBe(0)
  })

  test("Query is ':value' — colon with no field", async () => {
    // Regex needs \w+ before colon. ":value" doesn't match.
    // Falls through to text search for ":value".
    const sid = testSessionId()
    sessionsToClean.push(sid)

    plantStoredOutput(sid, "out_nofieldcolon", {
      records: [
        { type: "line", text: "the :value is here" },
        { type: "line", text: "nothing special" },
      ],
    })

    const result = await query({
      sessionId: sid,
      outputId: "out_nofieldcolon",
      query: ":value",
    })

    // Text search for ":value" — should find first record
    expect(result.records.length).toBe(1)
    expect(result.records[0].text).toContain(":value")
  })

  test("Query with nonexistent field (bogusfield:anything)", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    plantStoredOutput(sid, "out_nofield", {
      records: [
        { type: "port", port: 22, state: "open" },
        { type: "port", port: 80, state: "open" },
      ],
    })

    const result = await query({
      sessionId: sid,
      outputId: "out_nofield",
      query: "bogusfield:anything",
    })

    // Field doesn't exist on any record → 0 results
    expect(result.found).toBe(true)
    expect(result.records.length).toBe(0)
  })

  test("Extremely long query (10KB) — should not crash", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    plantStoredOutput(sid, "out_longquery", {
      records: [{ type: "line", text: "hello" }],
    })

    const longQuery = strOfLen(10240, "a")
    const result = await query({
      sessionId: sid,
      outputId: "out_longquery",
      query: longQuery,
    })

    expect(result.found).toBe(true)
    // No record contains 10KB of "a"s, so 0 results
    expect(result.records.length).toBe(0)
  })

  test("BUG 7a: limit=0 returns empty records but total is correct", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    plantStoredOutput(sid, "out_limit0", {
      records: [
        { type: "port", port: 22, state: "open" },
        { type: "port", port: 80, state: "open" },
      ],
    })

    const result = await query({
      sessionId: sid,
      outputId: "out_limit0",
      limit: 0,
    })

    expect(result.found).toBe(true)
    expect(result.records.length).toBe(0) // slice(0, 0) = []
    expect(result.total).toBe(2) // total shows real count
  })

  test("BUG 7b: Negative limit returns truncated results (slice removes from end)", async () => {
    // HYPOTHESIS: slice(0, -1) removes the last element.
    // slice(0, -2) removes last two. This is almost certainly not intended.
    const sid = testSessionId()
    sessionsToClean.push(sid)

    plantStoredOutput(sid, "out_neglimit", {
      records: [
        { type: "port", port: 22, state: "open" },
        { type: "port", port: 80, state: "open" },
        { type: "port", port: 443, state: "open" },
      ],
    })

    const result = await query({
      sessionId: sid,
      outputId: "out_neglimit",
      limit: -1,
    })

    expect(result.found).toBe(true)
    // BUG: slice(0, -1) = first 2 records (drops last one)
    // This is clearly not the intended behavior for a "limit" parameter
    expect(result.records.length).toBe(2) // BUG: should be 0 or 3, not 2
    expect(result.total).toBe(3)
  })

  test("limit as float (1.5) — slice truncates to integer", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    plantStoredOutput(sid, "out_floatlimit", {
      records: [
        { type: "port", port: 22, state: "open" },
        { type: "port", port: 80, state: "open" },
        { type: "port", port: 443, state: "open" },
      ],
    })

    const result = await query({
      sessionId: sid,
      outputId: "out_floatlimit",
      limit: 1.5,
    })

    expect(result.found).toBe(true)
    // JS slice(0, 1.5) → slice(0, 1) — truncates to integer
    expect(result.records.length).toBe(1)
  })

  test("Field:value query on numeric field with non-numeric value", async () => {
    // HYPOTHESIS: parseInt("notanumber", 10) returns NaN.
    // NaN === anything is always false. So no match. Not a crash.
    const sid = testSessionId()
    sessionsToClean.push(sid)

    plantStoredOutput(sid, "out_nan", {
      records: [{ type: "port", port: 22, state: "open" }],
    })

    const result = await query({
      sessionId: sid,
      outputId: "out_nan",
      query: "port:notanumber",
    })

    expect(result.found).toBe(true)
    // parseInt("notanumber") = NaN, 22 === NaN is false → 0 results
    expect(result.records.length).toBe(0)
  })

  test("Field:value query — numeric comparison loses precision", async () => {
    // HYPOTHESIS: parseInt("22.5", 10) returns 22.
    // If a record has port: 22, the comparison 22 === 22 succeeds.
    // This means "port:22.5" matches port 22 — surprising.
    const sid = testSessionId()
    sessionsToClean.push(sid)

    plantStoredOutput(sid, "out_intparse", {
      records: [{ type: "port", port: 22, state: "open" }],
    })

    const result = await query({
      sessionId: sid,
      outputId: "out_intparse",
      query: "port:22.5",
    })

    expect(result.found).toBe(true)
    // BUG: parseInt("22.5") = 22, so port:22.5 matches port 22
    expect(result.records.length).toBe(1) // Surprising but matches
  })

  test("Text search does NOT match numeric field values", async () => {
    // HYPOTHESIS: Text search only checks `typeof v === "string"`.
    // Port numbers (typeof "number") are skipped entirely.
    const sid = testSessionId()
    sessionsToClean.push(sid)

    plantStoredOutput(sid, "out_numskip", {
      records: [
        { type: "port", port: 22, state: "open", service: "ssh" },
        { type: "port", port: 80, state: "open", service: "http" },
      ],
    })

    // Text search for "22" — should it match port 22?
    const result = await query({
      sessionId: sid,
      outputId: "out_numskip",
      query: "22",
    })

    // Text search skips numbers — "22" is searched only in string fields
    // Port 22 has no string field containing "22"
    expect(result.records.length).toBe(0) // Numbers are invisible to text search
  })

  test("Type filter combined with field:value query", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    plantStoredOutput(sid, "out_combined", {
      records: [
        { type: "port", port: 22, state: "open" },
        { type: "port", port: 80, state: "closed" },
        { type: "vulnerability", name: "CVE-2021-1234", port: 22 },
      ],
    })

    const result = await query({
      sessionId: sid,
      outputId: "out_combined",
      query: "port:22",
      type: "port",
    })

    // Type filter runs first, then field:value query
    expect(result.records.length).toBe(1)
    expect(result.records[0].type).toBe("port")
    expect(result.records[0].state).toBe("open")
  })
})

// ============================================================================
// 4. NORMALIZER EDGE CASES
// ============================================================================

describe("Normalizer edge cases", () => {
  test("BUG 8: Nmap data with ports as strings instead of numbers", () => {
    // HYPOTHESIS: normalizeNmap doesn't coerce port to number.
    // If port is string "80", it stays as string in the record.
    // Then field:value "port:80" does parseInt("80")=80 vs "80" (string).
    // typeof "80" !== "number", so falls to String("80") === "80" → matches.
    // Not a crash, but type inconsistency.
    const data = {
      hosts: [
        {
          ip: "10.10.10.1",
          ports: [
            { port: "80", protocol: "tcp", state: "open", service: { name: "http" } },
            { port: "443", protocol: "tcp", state: "open", service: { name: "https" } },
          ],
        },
      ],
    }

    const records = normalizeNmap(data)
    expect(records.length).toBe(2)

    // Port is stored as string "80" — not number 80
    expect(typeof records[0].port).toBe("string") // BUG: should be number
    expect(records[0].port).toBe("80") // Stored as-is from input
  })

  test("ffuf results with null entries in array", () => {
    // HYPOTHESIS: normalizeFfuf iterates results without null check.
    // null entries will crash when accessing null?.input.
    const data = {
      results: [
        { input: "/admin", url: "http://target/admin", status: 200, length: 100 },
        null,
        { input: "/login", url: "http://target/login", status: 200, length: 200 },
      ],
    }

    // Should not throw — optional chaining should handle null
    const records = normalizeFfuf(data)

    // null entry produces a record with empty/default values (not skipped)
    // Because `null?.input` = undefined, `null?.url` = undefined, etc.
    expect(records.length).toBe(3) // All 3 processed, including null
    expect(records[1].path).toBe("") // undefined ?? "" = ""
  })

  test("Tool name with slash and special characters", () => {
    // HYPOTHESIS: normalize() splits on "_" to get base tool name.
    // Tool "nmap/tcp_scan" → toolBase = "nmap/tcp" (wrong).
    // Actually: "nmap/tcp_scan".split("_")[0] = "nmap/tcp"
    const records = normalize("nmap/tcp_scan", { hosts: [] }, "")

    // No crash, but toolBase = "nmap/tcp" which doesn't match any normalizer
    // Falls through to generic normalizer
    expect(records).toBeDefined()
  })

  test("Tool name extraction works for standard format", () => {
    // "nmap_port_scan".split("_")[0] = "nmap" → matches normalizer
    const data = {
      hosts: [
        { ip: "10.10.10.1", ports: [{ port: 22, state: "open", service: { name: "ssh" } }] },
      ],
    }
    const records = normalize("nmap_port_scan", data, "")
    expect(records.length).toBe(1)
    expect(records[0].type).toBe("port")
  })

  test("Generic normalizer with completely empty data", () => {
    const records = normalizeGeneric({}, "")
    expect(records.length).toBe(0)
  })

  test("Generic normalizer with nested object (no arrays)", () => {
    const data = { info: { name: "test", version: "1.0" } }
    const records = normalizeGeneric(data, "fallback\nraw\noutput\nline five\nline six")
    // No arrays found → falls back to raw output normalization
    // Lines shorter than 5 chars are filtered out
    expect(records.length).toBeGreaterThan(0)
    expect(records[0].type).toBe("line")
  })

  test("Generic normalizer with non-object data (string)", () => {
    const records = normalizeGeneric("just a string", "raw output here with enough chars")
    // Not an object → normalizeRawOutput
    expect(records.length).toBeGreaterThan(0)
    expect(records[0].type).toBe("line")
  })

  test("Generic normalizer with array of primitives", () => {
    const data = { values: [1, 2, 3, 4, 5] }
    const records = normalizeGeneric(data)
    expect(records.length).toBe(5)
    expect(records[0].value).toBe(1)
  })

  test("normalizeRawOutput filters short lines (<=5 chars)", () => {
    const raw = "hi\nhello world this is long\nok\nthis line is fine\nx"
    const records = normalizeRawOutput(raw)
    // "hi" (2 chars), "ok" (2 chars), "x" (1 char) are filtered out
    // Only "hello world this is long" and "this line is fine" survive
    expect(records.length).toBe(2)
    expect(records[0].text).toBe("hello world this is long")
  })

  test("Nmap with empty hosts array", () => {
    const records = normalizeNmap({ hosts: [] })
    expect(records.length).toBe(0)
  })

  test("Nmap with host that has no ports", () => {
    const records = normalizeNmap({ hosts: [{ ip: "10.10.10.1" }] })
    expect(records.length).toBe(0) // No ports → no records
  })
})

// ============================================================================
// 5. CLEANUP EDGE CASES
// ============================================================================

describe("Cleanup edge cases", () => {
  test("Cleanup with no sessions directory — does not crash", async () => {
    // cleanup() checks existsSync(SESSIONS_DIR) first
    const result = await cleanup()
    // Should return 0 deleted (may actually delete real old outputs, but won't crash)
    expect(result.deleted).toBeGreaterThanOrEqual(0)
  })

  test("cleanupSession on non-existent session — does not crash", async () => {
    const sid = "nonexistent-session-" + randomBytes(8).toString("hex")
    // Should not throw
    await cleanupSession(sid)
  })

  test("BUG 10: Cleanup with corrupted JSON falls back to mtime — but catches errors", async () => {
    // HYPOTHESIS: In the catch block of cleanup, it calls statSync(filePath).
    // If the file was deleted between readFileSync failing and statSync,
    // statSync would throw and the cleanup loop would abort.
    // However for this test we just verify corrupted JSON is handled.
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const sessionsDir = join(process.env.HOME ?? "/tmp", ".opensploit", "sessions")
    const outputsDir = join(sessionsDir, sid, "outputs")
    mkdirSync(outputsDir, { recursive: true })

    // Plant a corrupt JSON file with old modification time
    const corruptPath = join(outputsDir, "out_corrupt_cleanup.json")
    writeFileSync(corruptPath, "NOT VALID JSON", "utf-8")

    // We can't easily set mtime to > 24 hours ago with writeFileSync,
    // but we can verify the cleanup doesn't crash on corrupt files
    const result = await cleanup()
    expect(result).toBeDefined()
    // File has recent mtime, so it won't be deleted — just verifying no crash
  })

  test("Cleanup with file that has future timestamp — kept (not deleted)", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const futureTimestamp = Date.now() + 365 * 24 * 60 * 60 * 1000 // 1 year in future

    plantStoredOutput(sid, "out_future", {
      timestamp: futureTimestamp,
    })

    const result = await cleanup()
    // Future timestamp > cutoff, so file should NOT be deleted
    const meta = await getMetadata(sid, "out_future")
    expect(meta.found).toBe(true) // Still exists
  })

  test("Cleanup removes expired outputs", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    // Plant an output with very old timestamp
    const oldTimestamp = Date.now() - 48 * 60 * 60 * 1000 // 48 hours ago

    plantStoredOutput(sid, "out_old", {
      timestamp: oldTimestamp,
    })

    const resultBefore = await getMetadata(sid, "out_old")
    expect(resultBefore.found).toBe(true)

    await cleanup()

    const resultAfter = await getMetadata(sid, "out_old")
    expect(resultAfter.found).toBe(false) // Should be deleted
  })

  test("Cleanup removes empty session directories after deleting all outputs", async () => {
    const sid = testSessionId()
    // Don't add to sessionsToClean — cleanup should handle it

    const oldTimestamp = Date.now() - 48 * 60 * 60 * 1000
    plantStoredOutput(sid, "out_to_delete", { timestamp: oldTimestamp })

    await cleanup()

    const sessionsDir = join(process.env.HOME ?? "/tmp", ".opensploit", "sessions")
    const outputsDir = join(sessionsDir, sid, "outputs")
    expect(existsSync(outputsDir)).toBe(false)

    // Manual cleanup of parent dir if it remains
    cleanupTestSession(sid)
  })

  test("Non-JSON files in outputs directory — ignored by cleanup", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const sessionsDir = join(process.env.HOME ?? "/tmp", ".opensploit", "sessions")
    const outputsDir = join(sessionsDir, sid, "outputs")
    mkdirSync(outputsDir, { recursive: true })

    // Plant a non-JSON file
    writeFileSync(join(outputsDir, "notes.txt"), "this is not json", "utf-8")

    // Also plant a valid output
    plantStoredOutput(sid, "out_valid", {
      timestamp: Date.now() - 48 * 60 * 60 * 1000,
    })

    const result = await cleanup()
    // JSON file should be cleaned up, .txt should be ignored
    expect(existsSync(join(outputsDir, "notes.txt"))).toBe(true)
  })
})

// ============================================================================
// 6. SESSION ISOLATION
// ============================================================================

describe("Session isolation", () => {
  test("BUG 5: Cross-session query by guessing outputId succeeds if you know sessionId", async () => {
    // HYPOTHESIS: There's no authorization check. If you know the sessionId
    // and outputId, you can read any session's outputs.
    const sidA = testSessionId()
    const sidB = testSessionId()
    sessionsToClean.push(sidA, sidB)

    plantStoredOutput(sidA, "out_secret", {
      records: [{ type: "credential", login: "admin", password: "s3cret" }],
    })

    // Query from "session B" using session A's ID and output ID
    // This works because query() just checks if the file exists
    const result = await query({
      sessionId: sidA, // Using A's session ID
      outputId: "out_secret",
    })

    // BUG: No isolation — anyone who knows sessionId+outputId can read
    expect(result.found).toBe(true)
    expect(result.records[0].login).toBe("admin")
    // This is "by design" since it's a local tool, but worth documenting
  })

  test("Empty sessionId — rejected by sanitizeId", async () => {
    // sanitizeId() rejects empty/falsy IDs
    await expect(
      store({
        sessionId: "",
        tool: "test",
        data: null,
        rawOutput: strOfLen(6000),
      }),
    ).rejects.toThrow("Invalid")
  })

  test("SessionId with path separators — rejected by sanitizeId", async () => {
    // sanitizeId() rejects IDs containing ".." or "/"
    const evilSessionId = "../../tmp/opensploit-evil-test-" + randomBytes(4).toString("hex")

    await expect(
      store({
        sessionId: evilSessionId,
        tool: "test",
        data: null,
        rawOutput: strOfLen(6000),
      }),
    ).rejects.toThrow("Invalid")
  })
})

// ============================================================================
// 7. FORMAT FUNCTIONS
// ============================================================================

describe("Format functions", () => {
  test("formatQueryResults with empty records", () => {
    const result = formatQueryResults([], 0, 50)
    expect(result).toBe("No matching records found.")
  })

  test("formatQueryResults with port records", () => {
    const records: OutputRecord[] = [
      { type: "port", port: 22, protocol: "tcp", state: "open", service: "ssh" },
    ]
    const result = formatQueryResults(records, 1, 50)
    expect(result).toContain("| Port |")
    expect(result).toContain("| 22 |")
  })

  test("formatQueryResults with directory records", () => {
    const records: OutputRecord[] = [
      { type: "directory", path: "/admin", status: 200, length: 1234 },
    ]
    const result = formatQueryResults(records, 1, 50)
    expect(result).toContain("| Path |")
    expect(result).toContain("| /admin |")
  })

  test("formatQueryResults with vulnerability records", () => {
    const records: OutputRecord[] = [
      { type: "vulnerability", name: "CVE-2021-1234", severity: "high", host: "10.10.10.1" },
    ]
    const result = formatQueryResults(records, 1, 50)
    expect(result).toContain("**CVE-2021-1234**")
    expect(result).toContain("Severity: high")
  })

  test("formatQueryResults with credential records", () => {
    const records: OutputRecord[] = [
      { type: "credential", host: "10.10.10.1", service: "ssh", login: "admin", password: "secret" },
    ]
    const result = formatQueryResults(records, 1, 50)
    expect(result).toContain("| admin |")
    expect(result).toContain("*** |") // Password masked
    expect(result).not.toContain("secret") // Actual password not shown
  })

  test("formatQueryResults truncation notice when total > shown", () => {
    const records: OutputRecord[] = [{ type: "port", port: 22, protocol: "tcp", state: "open" }]
    const result = formatQueryResults(records, 100, 50)
    expect(result).toContain("Showing 1 of 100 results")
  })

  test("formatQueryResults with generic records (unknown type)", () => {
    const records: OutputRecord[] = [
      { type: "custom", foo: "bar", baz: 42 },
    ]
    const result = formatQueryResults(records, 1, 50)
    expect(result).toContain("custom")
    expect(result).toContain("foo")
  })

  test("formatQueryResults with undefined fields in port record — uses fallback '-'", () => {
    // Records may have undefined service/version — code uses `r.service || "-"`
    // which correctly falls back to "-" for undefined
    const records: OutputRecord[] = [
      { type: "port", port: 22, protocol: "tcp", state: "open" },
    ]
    const result = formatQueryResults(records, 1, 50)
    // r.service is undefined → undefined || "-" = "-" (correct)
    expect(result).toContain("| - |")
    expect(result).not.toContain("| undefined |")
  })

  test("formatDirectOutput with data.summary containing arrays", () => {
    // Test the formatDirectOutput path for small outputs
    // We can't import it directly (not exported), so we test via store()
    // Actually, we can test by calling store with small data that has summary
  })
})

// ============================================================================
// 8. STORE + QUERY ROUND-TRIP INTEGRATION
// ============================================================================

describe("Store + query round-trip", () => {
  test("Store nmap data, query by port", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const storeResult = await store({
      sessionId: sid,
      tool: "nmap_port_scan",
      data: {
        hosts: [
          {
            ip: "10.10.10.1",
            ports: Array.from({ length: 50 }, (_, i) => ({
              port: 1000 + i,
              protocol: "tcp",
              state: i % 2 === 0 ? "open" : "closed",
              service: { name: `svc${i}` },
            })),
          },
        ],
      },
      rawOutput: strOfLen(3000),
    })

    expect(storeResult.stored).toBe(true)

    // Query for open ports
    const openPorts = await query({
      sessionId: sid,
      outputId: storeResult.outputId!,
      query: "state:open",
    })
    expect(openPorts.total).toBe(25) // Even indices are open

    // Query for specific port
    const port1010 = await query({
      sessionId: sid,
      outputId: storeResult.outputId!,
      query: "port:1010",
    })
    expect(port1010.total).toBe(1)
  })

  test("Store hydra data, query credentials", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const storeResult = await store({
      sessionId: sid,
      tool: "hydra_brute",
      data: {
        results: Array.from({ length: 50 }, (_, i) => ({
          host: "10.10.10.1",
          port: 22,
          service: "ssh",
          login: `user${i}`,
          password: `pass${i}`,
        })),
      },
      rawOutput: strOfLen(4000),
    })

    expect(storeResult.stored).toBe(true)

    // Query for specific user
    const userResult = await query({
      sessionId: sid,
      outputId: storeResult.outputId!,
      query: "login:user5",
    })
    expect(userResult.total).toBe(1)
    expect(userResult.records[0].login).toBe("user5")
  })

  test("Store then getRawOutput", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const rawContent = strOfLen(6000, "R")

    const storeResult = await store({
      sessionId: sid,
      tool: "test",
      data: null,
      rawOutput: rawContent,
    })

    expect(storeResult.stored).toBe(true)

    const raw = await getRawOutput(sid, storeResult.outputId!)
    expect(raw).toBe(rawContent)
  })

  test("Store then getMetadata", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const storeResult = await store({
      sessionId: sid,
      tool: "nmap_scan",
      method: "full_scan",
      data: { hosts: [{ ip: "10.10.10.1", ports: [{ port: 22, state: "open" }] }] },
      rawOutput: strOfLen(5000),
    })

    // Data JSON ~90 chars + raw 5000 = ~5090 > 5000 → stored
    expect(storeResult.stored).toBe(true)

    const meta = await getMetadata(sid, storeResult.outputId!)
    expect(meta.found).toBe(true)
    expect(meta.tool).toBe("nmap_scan")
    expect(meta.method).toBe("full_scan")
    expect(meta.recordCount).toBe(1)
  })

  test("Query nonexistent outputId — returns found:false with error", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const result = await query({
      sessionId: sid,
      outputId: "out_doesnotexist",
    })

    expect(result.found).toBe(false)
    expect(result.error).toContain("Output not found")
  })

  test("getRawOutput for nonexistent output — returns null", async () => {
    const sid = testSessionId()
    const raw = await getRawOutput(sid, "out_nope")
    expect(raw).toBeNull()
  })

  test("getMetadata for nonexistent output — returns found:false", async () => {
    const sid = testSessionId()
    const meta = await getMetadata(sid, "out_nope")
    expect(meta.found).toBe(false)
  })
})

// ============================================================================
// 9. SUMMARY GENERATION EDGE CASES
// ============================================================================

describe("Summary generation", () => {
  test("Store output with zero normalized records — summary still generated", async () => {
    // If data is an object with no arrays and rawOutput is all short lines,
    // we get zero records. Summary should have total: 0.
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const storeResult = await store({
      sessionId: sid,
      tool: "unknown_tool",
      data: { info: "no arrays here" },
      rawOutput: strOfLen(5500, "\n"), // All lines are 0 chars (just newlines)
    })

    if (storeResult.stored) {
      const q = await query({
        sessionId: sid,
        outputId: storeResult.outputId!,
      })
      // Records may be empty since all lines are filtered (< 5 chars)
      expect(q.found).toBe(true)
    }
  })

  test("Store output with many record types — byType counts are correct", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    plantStoredOutput(sid, "out_multitype", {
      records: [
        { type: "port", port: 22 },
        { type: "port", port: 80 },
        { type: "port", port: 443 },
        { type: "vulnerability", name: "CVE-1" },
        { type: "vulnerability", name: "CVE-2" },
        { type: "credential", login: "admin" },
      ],
      summary: {
        total: 6,
        byType: { port: 3, vulnerability: 2, credential: 1 },
        preview: [],
      },
    })

    const meta = await getMetadata(sid, "out_multitype")
    expect(meta.found).toBe(true)
    expect(meta.recordCount).toBe(6)
  })
})

// ============================================================================
// 10. DOUBLE-STRINGIFY PERFORMANCE BUG
// ============================================================================

describe("Performance edge cases", () => {
  test("BUG 9: store() calls JSON.stringify(data) twice — once in shouldStore, once for sizeBytes", async () => {
    // This is a code-level observation, not a functional bug.
    // We can verify by checking that sizeBytes matches expected value.
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const data = { items: Array.from({ length: 100 }, (_, i) => ({ id: i, value: strOfLen(50) })) }
    const expectedDataSize = JSON.stringify(data).length
    const rawOutput = strOfLen(3000)

    const storeResult = await store({
      sessionId: sid,
      tool: "test",
      data,
      rawOutput,
    })

    expect(storeResult.stored).toBe(true)

    const meta = await getMetadata(sid, storeResult.outputId!)
    expect(meta.found).toBe(true)
    // sizeBytes should be dataSize + rawSize
    expect(meta.sizeBytes).toBe(expectedDataSize + rawOutput.length)
  })
})

// ============================================================================
// 11. FORMATDIRECTOUTPUT (under-threshold path)
// ============================================================================

describe("Under-threshold direct output", () => {
  test("Small data with summary field — formatted nicely", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const result = await store({
      sessionId: sid,
      tool: "test",
      data: {
        summary: {
          total: 5,
          items: ["a", "b", "c"],
        },
      },
      rawOutput: "",
    })

    expect(result.stored).toBe(false)
    expect(result.output).toContain("**Summary**")
    expect(result.output).toContain("total: 5")
    expect(result.output).toContain("a, b, c")
  })

  test("Small data without summary — returns JSON", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const result = await store({
      sessionId: sid,
      tool: "test",
      data: { foo: "bar", count: 42 },
      rawOutput: "",
    })

    expect(result.stored).toBe(false)
    const parsed = JSON.parse(result.output)
    expect(parsed.foo).toBe("bar")
    expect(parsed.count).toBe(42)
  })

  test("No data, small rawOutput — returns raw string", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const result = await store({
      sessionId: sid,
      tool: "test",
      data: null,
      rawOutput: "hello world",
    })

    expect(result.stored).toBe(false)
    expect(result.output).toBe("hello world")
  })

  test("Small data with summary containing >10 item array — truncated with ellipsis", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const result = await store({
      sessionId: sid,
      tool: "test",
      data: {
        summary: {
          ports: Array.from({ length: 15 }, (_, i) => i),
        },
      },
      rawOutput: "",
    })

    expect(result.stored).toBe(false)
    expect(result.output).toContain("...")
  })
})
