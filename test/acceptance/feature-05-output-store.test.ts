/**
 * Feature 05: Output Store -- Acceptance Tests
 *
 * Each test maps to a specific REQ-* from:
 *   opensploit-vault/requirements/05-output-store.md
 *
 * EXISTING COVERAGE (76 tests in test/tools/output-store.test.ts):
 *   - REQ-ARC-024: Threshold logic (5 tests) -- small/large/combined/boundary/null
 *   - REQ-ARC-025: Summary generation (4 tests) + file I/O (4 tests) -- type breakdown, preview, ID format
 *   - REQ-ARC-027: Query interface (9 tests) -- field:value, text, type filter, limit, not-found, combined
 *   - REQ-ARC-028: Session scoping (implicit in all store/query calls, cleanupSession)
 *   - REQ-ARC-029: Cleanup (5 tests) -- delete old, preserve new, remove empty dirs, malformed JSON, safe
 *   - Normalizers: 30+ tests for nmap/ffuf/nikto/gobuster/sqlmap/nuclei/hydra/generic/raw/dispatch
 *   - Formatting: 7 tests for formatQueryResults (port/directory/vuln/credential/unknown/truncation/empty)
 *
 * THIS FILE covers gaps:
 *   - REQ-ARC-026: executeReadToolOutput() tool entry point (header formatting, not-found, session resolution)
 *   - REQ-ARC-028: Explicit cross-session isolation (output stored in session A not visible from session B)
 *   - REQ-ARC-025: Round-trip (outputId from summary is usable to query back)
 */

import { describe, test, expect, afterEach } from "bun:test"
import { existsSync, rmSync } from "fs"
import { join } from "path"
import os from "os"

import {
  store,
  query,
  cleanupSession,
} from "../../src/tools/output-store"

import {
  executeReadToolOutput,
} from "../../src/tools/read-tool-output"

import {
  registerRootSession,
  unregister,
  unregisterTree,
} from "../../src/session/hierarchy"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SESSIONS_DIR = join(os.homedir(), ".opensploit", "sessions")

function testSessionId(label: string): string {
  return `f05-${label}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
}

function bigString(len: number, char = "x"): string {
  return char.repeat(len)
}

function nmapData(portCount: number) {
  const ports = Array.from({ length: portCount }, (_, i) => ({
    port: 1000 + i,
    protocol: "tcp",
    state: i % 2 === 0 ? "open" : "closed",
    service: { name: i === 0 ? "http" : `svc-${i}`, version: `1.${i}` },
  }))
  return { hosts: [{ ip: "10.10.10.1", hostname: "target.htb", ports }] }
}

// ---------------------------------------------------------------------------
// Track sessions for cleanup
// ---------------------------------------------------------------------------

const sessionsToClean: string[] = []
const hierarchyToClean: string[] = []

afterEach(() => {
  for (const sid of sessionsToClean) {
    const dir = join(SESSIONS_DIR, sid)
    if (existsSync(dir)) {
      rmSync(dir, { recursive: true, force: true })
    }
  }
  sessionsToClean.length = 0

  for (const sid of hierarchyToClean) {
    unregisterTree(sid)
    unregister(sid)
  }
  hierarchyToClean.length = 0
})

// ===========================================================================
// REQ-ARC-026: read_tool_output built-in tool
// ===========================================================================

describe("REQ-ARC-026: read_tool_output tool entry point", () => {
  test("REQ-ARC-026: executeReadToolOutput returns formatted header with tool and query info", async () => {
    const sid = testSessionId("026-header")
    sessionsToClean.push(sid)

    const storeResult = await store({
      sessionId: sid,
      tool: "nmap",
      method: "port_scan",
      data: nmapData(10),
      rawOutput: bigString(6000),
    })
    expect(storeResult.stored).toBe(true)

    const result = await executeReadToolOutput(
      { id: storeResult.outputId!, query: "state:open", limit: 50 },
      sid,
    )

    expect(result.title).toBe(`read_tool_output: ${storeResult.outputId}`)
    expect(result.output).toContain(`**Output ID**: ${storeResult.outputId}`)
    expect(result.output).toContain("**Tool**: nmap.port_scan")
    expect(result.output).toContain('**Query**: state:open')
    expect(result.output).toContain("**Results**:")
    // Should contain the actual table data
    expect(result.output).toContain("| Port |")
  })

  test("REQ-ARC-026: executeReadToolOutput returns helpful message for expired/missing output", async () => {
    const sid = testSessionId("026-notfound")
    sessionsToClean.push(sid)

    const result = await executeReadToolOutput(
      { id: "out_nonexistent_00000000", limit: 50 },
      sid,
    )

    expect(result.title).toBe("read_tool_output: not found")
    expect(result.output).toContain("Output not found")
    expect(result.output).toContain("24 hour retention")
    expect(result.output).toContain("Troubleshooting")
  })

  test("REQ-ARC-026: executeReadToolOutput resolves sub-agent session to root session", async () => {
    const rootSid = testSessionId("026-root")
    const childSid = testSessionId("026-child")
    sessionsToClean.push(rootSid)
    hierarchyToClean.push(rootSid)

    // Register hierarchy: childSid -> rootSid
    registerRootSession(childSid, rootSid)

    // Store output under the root session
    const storeResult = await store({
      sessionId: rootSid,
      tool: "nmap",
      method: "port_scan",
      data: nmapData(5),
      rawOutput: bigString(6000),
    })
    expect(storeResult.stored).toBe(true)

    // Query from child session -- should resolve to root and find the output
    const result = await executeReadToolOutput(
      { id: storeResult.outputId!, limit: 50 },
      childSid,
    )

    expect(result.output).toContain("**Tool**: nmap.port_scan")
    expect(result.output).toContain("**Results**:")
    // Should NOT say "not found"
    expect(result.output).not.toContain("Output not found")
  })

  test("REQ-ARC-026: executeReadToolOutput passes type filter to query", async () => {
    const sid = testSessionId("026-type")
    sessionsToClean.push(sid)

    // nmap data with ports + OS match
    const data = {
      hosts: [{
        ip: "10.10.10.1",
        ports: [{ port: 22, state: "open", protocol: "tcp" }],
        os_matches: [{ name: "Linux 5.4", accuracy: 95 }],
      }],
    }
    const storeResult = await store({
      sessionId: sid,
      tool: "nmap",
      method: "port_scan",
      data,
      rawOutput: bigString(6000),
    })
    expect(storeResult.stored).toBe(true)

    const result = await executeReadToolOutput(
      { id: storeResult.outputId!, type: "os", limit: 50 },
      sid,
    )

    expect(result.output).toContain("**Type Filter**: os")
    expect(result.output).toContain("**Results**: 1 of 1")
  })

  test("REQ-ARC-026: executeReadToolOutput with no query returns all records", async () => {
    const sid = testSessionId("026-all")
    sessionsToClean.push(sid)

    const storeResult = await store({
      sessionId: sid,
      tool: "nmap",
      data: nmapData(5),
      rawOutput: bigString(6000),
    })
    expect(storeResult.stored).toBe(true)

    const result = await executeReadToolOutput(
      { id: storeResult.outputId!, limit: 50 },
      sid,
    )

    expect(result.output).toContain("**Query**: (all records)")
    expect(result.output).toContain("**Results**: 5 of 5")
  })
})

// ===========================================================================
// REQ-ARC-028: Cross-session isolation
// ===========================================================================

describe("REQ-ARC-028: outputs scoped to sessions (isolation)", () => {
  test("REQ-ARC-028: output stored in session A is NOT accessible from session B", async () => {
    const sidA = testSessionId("028-A")
    const sidB = testSessionId("028-B")
    sessionsToClean.push(sidA, sidB)

    const storeResult = await store({
      sessionId: sidA,
      tool: "nmap",
      data: nmapData(10),
      rawOutput: bigString(6000),
    })
    expect(storeResult.stored).toBe(true)

    // Query from session A -- should work
    const resultA = await query({ sessionId: sidA, outputId: storeResult.outputId! })
    expect(resultA.found).toBe(true)
    expect(resultA.records.length).toBe(10)

    // Query from session B -- should NOT find it
    const resultB = await query({ sessionId: sidB, outputId: storeResult.outputId! })
    expect(resultB.found).toBe(false)
    expect(resultB.error).toContain("not found")
  })

  test("REQ-ARC-028: cleanupSession only removes targeted session outputs", async () => {
    const sidA = testSessionId("028-cleanup-A")
    const sidB = testSessionId("028-cleanup-B")
    sessionsToClean.push(sidA, sidB)

    const resultA = await store({
      sessionId: sidA,
      tool: "nmap",
      data: nmapData(5),
      rawOutput: bigString(6000),
    })
    const resultB = await store({
      sessionId: sidB,
      tool: "ffuf",
      data: { results: Array.from({ length: 10 }, (_, i) => ({ input: `/p${i}`, status: 200, length: 100 })) },
      rawOutput: bigString(6000),
    })

    expect(resultA.stored).toBe(true)
    expect(resultB.stored).toBe(true)

    // Clean up session A only
    await cleanupSession(sidA)

    // A should be gone
    const queryA = await query({ sessionId: sidA, outputId: resultA.outputId! })
    expect(queryA.found).toBe(false)

    // B should still exist
    const queryB = await query({ sessionId: sidB, outputId: resultB.outputId! })
    expect(queryB.found).toBe(true)
    expect(queryB.records.length).toBe(10)
  })
})

// ===========================================================================
// REQ-ARC-025: Round-trip (summary reference ID -> query)
// ===========================================================================

describe("REQ-ARC-025: summary reference ID round-trip", () => {
  test("REQ-ARC-025: outputId from store result can be used to query back records", async () => {
    const sid = testSessionId("025-roundtrip")
    sessionsToClean.push(sid)

    const storeResult = await store({
      sessionId: sid,
      tool: "nmap",
      method: "port_scan",
      data: nmapData(10),
      rawOutput: bigString(6000),
    })
    expect(storeResult.stored).toBe(true)
    expect(storeResult.outputId).toBeDefined()

    // The summary text should contain the output ID as a query hint
    expect(storeResult.output).toContain(`read_tool_output(id="${storeResult.outputId}"`)

    // Use the outputId to query back -- should succeed and return all records
    const queryResult = await query({
      sessionId: sid,
      outputId: storeResult.outputId!,
    })
    expect(queryResult.found).toBe(true)
    expect(queryResult.records.length).toBe(10)
    expect(queryResult.total).toBe(10)
  })

  test("REQ-ARC-025: summary contains type breakdown and record count", async () => {
    const sid = testSessionId("025-summary")
    sessionsToClean.push(sid)

    const data = {
      hosts: [{
        ip: "10.10.10.1",
        ports: [
          { port: 22, state: "open", protocol: "tcp", service: { name: "ssh" } },
          { port: 80, state: "open", protocol: "tcp", service: { name: "http" } },
          { port: 443, state: "closed", protocol: "tcp", service: { name: "https" } },
        ],
        os_matches: [{ name: "Linux 5.4", accuracy: 95 }],
      }],
    }

    const storeResult = await store({
      sessionId: sid,
      tool: "nmap",
      method: "port_scan",
      data,
      rawOutput: bigString(6000),
    })

    expect(storeResult.stored).toBe(true)
    // Summary should contain total records
    expect(storeResult.output).toContain("Total Records")
    // Summary should contain type breakdown
    expect(storeResult.output).toContain("port:")
    expect(storeResult.output).toContain("os:")
    // Summary should contain status breakdown
    expect(storeResult.output).toContain("By Status")
    expect(storeResult.output).toContain("open")
    expect(storeResult.output).toContain("closed")
  })

  test("REQ-ARC-025: summary includes query hint examples", async () => {
    const sid = testSessionId("025-hints")
    sessionsToClean.push(sid)

    const storeResult = await store({
      sessionId: sid,
      tool: "nmap",
      data: nmapData(5),
      rawOutput: bigString(6000),
    })

    expect(storeResult.stored).toBe(true)
    // Summary should include example queries
    expect(storeResult.output).toContain('query="port:22"')
    expect(storeResult.output).toContain('query="status:200"')
    expect(storeResult.output).toContain('query="open"')
  })
})
