import { describe, expect, test, afterEach } from "bun:test"
import { join } from "path"
import { existsSync, readFileSync, mkdirSync, writeFileSync, rmSync, readdirSync, utimesSync } from "fs"
import { tmpdir } from "os"
import os from "os"
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
  normalizeNikto,
  normalizeGobuster,
  normalizeSqlmap,
  normalizeNuclei,
  normalizeHydra,
  normalizeGeneric,
  normalizeRawOutput,
  type OutputRecord,
} from "../../src/util/output-normalizers"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SESSIONS_DIR = join(os.homedir(), ".opensploit", "sessions")

/** Generate a unique session ID to avoid collisions between tests. */
function testSessionId(): string {
  return `test-output-store-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
}

/** Create a string of given length. */
function bigString(len: number, char = "x"): string {
  return char.repeat(len)
}

/** Build a minimal nmap-style data payload. */
function nmapData(portCount: number) {
  const ports = Array.from({ length: portCount }, (_, i) => ({
    port: 1000 + i,
    protocol: "tcp",
    state: i % 2 === 0 ? "open" : "closed",
    service: { name: i === 0 ? "http" : `svc-${i}`, version: `1.${i}` },
  }))
  return { hosts: [{ ip: "10.10.10.1", hostname: "target.htb", ports }] }
}

/** Build a minimal ffuf-style data payload. */
function ffufData(resultCount: number) {
  const results = Array.from({ length: resultCount }, (_, i) => ({
    input: `/path-${i}`,
    url: `http://target.htb/path-${i}`,
    status: i < resultCount / 2 ? 200 : 404,
    length: 100 + i * 10,
    words: 10 + i,
    lines: 5 + i,
  }))
  return { results }
}

// ---------------------------------------------------------------------------
// Track sessions for cleanup
// ---------------------------------------------------------------------------

const sessionsToClean: string[] = []

afterEach(() => {
  for (const sid of sessionsToClean) {
    const dir = join(SESSIONS_DIR, sid)
    if (existsSync(dir)) {
      rmSync(dir, { recursive: true, force: true })
    }
  }
  sessionsToClean.length = 0
})

// ===========================================================================
// Normalizer Unit Tests (pure functions, no I/O)
// ===========================================================================

describe("output-normalizers", () => {
  describe("normalizeNmap", () => {
    test("flattens hosts and ports to port records", () => {
      const data = {
        hosts: [
          {
            ip: "10.10.10.1",
            hostname: "box.htb",
            ports: [
              { port: 22, protocol: "tcp", state: "open", service: { name: "ssh", product: "OpenSSH", version: "8.2" } },
              { port: 80, protocol: "tcp", state: "open", service: { name: "http" } },
            ],
          },
        ],
      }
      const records = normalizeNmap(data)
      expect(records.length).toBe(2)
      expect(records[0].type).toBe("port")
      expect(records[0].host).toBe("10.10.10.1")
      expect(records[0].port).toBe(22)
      expect(records[0].service).toBe("ssh")
      expect(records[0].product).toBe("OpenSSH")
      expect(records[1].port).toBe(80)
    })

    test("extracts OS match records", () => {
      const data = {
        hosts: [
          {
            ip: "10.10.10.1",
            ports: [],
            os_matches: [{ name: "Linux 5.4", accuracy: 95, osfamily: "Linux" }],
          },
        ],
      }
      const records = normalizeNmap(data)
      expect(records.length).toBe(1)
      expect(records[0].type).toBe("os")
      expect(records[0].name).toBe("Linux 5.4")
      expect(records[0].accuracy).toBe(95)
    })

    test("extracts vulnerability records from NSE scripts", () => {
      const data = {
        hosts: [
          {
            ip: "10.10.10.1",
            ports: [
              {
                port: 443,
                protocol: "tcp",
                state: "open",
                scripts: [
                  { id: "ssl-heartbleed", output: "VULNERABLE: Heartbleed bug CVE-2014-0160" },
                  { id: "http-title", output: "Welcome to Apache" }, // not a vuln
                ],
              },
            ],
          },
        ],
      }
      const records = normalizeNmap(data)
      const vulns = records.filter((r) => r.type === "vulnerability")
      expect(vulns.length).toBe(1)
      expect(vulns[0].script).toBe("ssl-heartbleed")
      expect(vulns[0].output).toContain("CVE-2014-0160")
    })

    test("handles empty hosts array", () => {
      expect(normalizeNmap({ hosts: [] })).toEqual([])
    })

    test("handles missing data gracefully", () => {
      expect(normalizeNmap({})).toEqual([])
      expect(normalizeNmap(null)).toEqual([])
    })

    test("uses fallback fields (address instead of ip)", () => {
      const data = {
        hosts: [{ address: "192.168.1.1", ports: [{ portid: 8080, protocol: "tcp", state: "open" }] }],
      }
      const records = normalizeNmap(data)
      expect(records[0].host).toBe("192.168.1.1")
      expect(records[0].port).toBe(8080)
    })
  })

  describe("normalizeFfuf", () => {
    test("flattens results to directory records", () => {
      const data = {
        results: [
          { input: "/admin", url: "http://t.htb/admin", status: 200, length: 1234, words: 50, lines: 20 },
          { input: "/login", url: "http://t.htb/login", status: 302, length: 0, redirect_location: "/dashboard" },
        ],
      }
      const records = normalizeFfuf(data)
      expect(records.length).toBe(2)
      expect(records[0].type).toBe("directory")
      expect(records[0].path).toBe("/admin")
      expect(records[0].status).toBe(200)
      expect(records[1].redirect).toBe("/dashboard")
    })

    test("handles empty results", () => {
      expect(normalizeFfuf({ results: [] })).toEqual([])
      expect(normalizeFfuf({})).toEqual([])
    })

    test("uses FUZZ as fallback for input field", () => {
      const data = { results: [{ FUZZ: "/backup", status: 403 }] }
      const records = normalizeFfuf(data)
      expect(records[0].path).toBe("/backup")
    })
  })

  describe("normalizeNikto", () => {
    test("flattens vulnerabilities", () => {
      const data = {
        vulnerabilities: [
          { id: "OSVDB-3092", uri: "/admin/", method: "GET", description: "Admin page found" },
        ],
      }
      const records = normalizeNikto(data)
      expect(records.length).toBe(1)
      expect(records[0].type).toBe("vulnerability")
      expect(records[0].uri).toBe("/admin/")
    })

    test("includes scan_info record", () => {
      const data = {
        vulnerabilities: [],
        scan_info: { target: "http://t.htb", start_time: "2025-01-01" },
      }
      const records = normalizeNikto(data)
      expect(records.length).toBe(1)
      expect(records[0].type).toBe("scan_info")
      expect(records[0].target).toBe("http://t.htb")
    })

    test("uses alternative field names (findings, items)", () => {
      const data = { findings: [{ id: "123", msg: "Test finding" }] }
      const records = normalizeNikto(data)
      expect(records.length).toBe(1)
      expect(records[0].description).toBe("Test finding")
    })
  })

  describe("normalizeGobuster", () => {
    test("flattens directory results", () => {
      const data = {
        results: [
          { path: "/images", status: 301, size: 0 },
          { path: "/css", status: 301, size: 0 },
        ],
      }
      const records = normalizeGobuster(data)
      expect(records.length).toBe(2)
      expect(records[0].type).toBe("directory")
      expect(records[0].path).toBe("/images")
    })

    test("uses alternative field names", () => {
      const data = { found: [{ url: "/backup", status_code: 200, length: 5000 }] }
      const records = normalizeGobuster(data)
      expect(records[0].path).toBe("/backup")
      expect(records[0].status).toBe(200)
      expect(records[0].size).toBe(5000)
    })
  })

  describe("normalizeSqlmap", () => {
    test("flattens injection points", () => {
      const data = {
        injections: [{ parameter: "id", type: "boolean-blind", title: "AND boolean-based blind", payload: "id=1 AND 1=1" }],
      }
      const records = normalizeSqlmap(data)
      expect(records.length).toBe(1)
      expect(records[0].type).toBe("injection")
      expect(records[0].parameter).toBe("id")
    })

    test("flattens databases and tables", () => {
      const data = {
        databases: ["information_schema", "webapp"],
        tables: [{ name: "users", database: "webapp", columns: ["id", "name"] }],
      }
      const records = normalizeSqlmap(data)
      const dbs = records.filter((r) => r.type === "database")
      const tables = records.filter((r) => r.type === "table")
      expect(dbs.length).toBe(2)
      expect(dbs[0].name).toBe("information_schema")
      expect(tables.length).toBe(1)
      expect(tables[0].columns).toBe(2)
    })

    test("handles database objects with name field", () => {
      const data = {
        databases: [{ name: "mydb", tables: ["t1", "t2"] }],
      }
      const records = normalizeSqlmap(data)
      expect(records[0].name).toBe("mydb")
      expect(records[0].tables).toBe(2)
    })
  })

  describe("normalizeNuclei", () => {
    test("flattens vulnerability findings", () => {
      const data = {
        results: [
          {
            template_id: "cve-2021-44228",
            name: "Log4Shell",
            severity: "critical",
            host: "http://target.htb",
            matched_at: "http://target.htb/api",
          },
        ],
      }
      const records = normalizeNuclei(data)
      expect(records.length).toBe(1)
      expect(records[0].type).toBe("vulnerability")
      expect(records[0].template_id).toBe("cve-2021-44228")
      expect(records[0].severity).toBe("critical")
    })

    test("joins array references to string", () => {
      const data = {
        results: [{ name: "Test", reference: ["https://example.com", "https://cve.org"] }],
      }
      const records = normalizeNuclei(data)
      expect(records[0].reference).toContain("https://example.com")
      expect(records[0].reference).toContain("https://cve.org")
    })
  })

  describe("normalizeHydra", () => {
    test("flattens credential results", () => {
      const data = {
        results: [
          { host: "10.10.10.1", port: 22, service: "ssh", login: "admin", password: "password123" },
        ],
      }
      const records = normalizeHydra(data)
      expect(records.length).toBe(1)
      expect(records[0].type).toBe("credential")
      expect(records[0].login).toBe("admin")
      expect(records[0].host).toBe("10.10.10.1")
    })

    test("uses alternative field names (credentials, target, username)", () => {
      const data = {
        credentials: [{ target: "10.10.10.1", username: "root", password: "toor" }],
      }
      const records = normalizeHydra(data)
      expect(records[0].host).toBe("10.10.10.1")
      expect(records[0].login).toBe("root")
    })
  })

  describe("normalizeGeneric", () => {
    test("flattens first array found in data", () => {
      const data = { items: [{ foo: "bar" }, { foo: "baz" }] }
      const records = normalizeGeneric(data)
      expect(records.length).toBe(2)
      expect(records[0].type).toBe("item") // "items" -> "item"
      expect(records[0].foo).toBe("bar")
    })

    test("handles scalar array values", () => {
      const data = { lines: ["line1", "line2"] }
      const records = normalizeGeneric(data)
      expect(records.length).toBe(2)
      expect(records[0].value).toBe("line1")
    })

    test("falls back to raw output when no arrays found", () => {
      const data = { status: "ok", message: "no arrays here" }
      const records = normalizeGeneric(data, "line one\nline two\nshort\nline four is longer")
      // "short" has length 5, which is NOT >5 so filtered out
      expect(records.length).toBe(3)
      expect(records[0].type).toBe("line")
    })

    test("falls back to raw output for null data", () => {
      const records = normalizeGeneric(null, "raw output line here")
      expect(records.length).toBe(1)
      expect(records[0].text).toBe("raw output line here")
    })
  })

  describe("normalizeRawOutput", () => {
    test("splits text into line records, filters short lines", () => {
      const raw = "PORT   STATE SERVICE\n22/tcp open  ssh\n80/tcp open  http\n\n\nhi"
      const records = normalizeRawOutput(raw)
      // Lines with >5 chars only
      const texts = records.map((r) => r.text)
      expect(texts).toContain("PORT   STATE SERVICE")
      expect(texts).toContain("22/tcp open  ssh")
      // "hi" is only 2 chars, should be filtered
      expect(texts).not.toContain("hi")
    })

    test("returns empty for empty string", () => {
      expect(normalizeRawOutput("")).toEqual([])
    })
  })

  describe("normalize (dispatch)", () => {
    test("routes nmap data to nmap normalizer", () => {
      const data = { hosts: [{ ip: "10.0.0.1", ports: [{ port: 22, state: "open" }] }] }
      const records = normalize("nmap", data)
      expect(records[0].type).toBe("port")
    })

    test("routes nmap_port_scan to nmap normalizer (splits on underscore)", () => {
      const data = { hosts: [{ ip: "10.0.0.1", ports: [{ port: 80, state: "open" }] }] }
      const records = normalize("nmap_port_scan", data)
      expect(records[0].type).toBe("port")
    })

    test("uses generic normalizer for unknown tool", () => {
      const data = { things: [{ a: 1 }, { a: 2 }] }
      const records = normalize("custom_tool", data)
      expect(records.length).toBe(2)
      expect(records[0].type).toBe("thing") // "things" -> "thing"
    })

    test("falls back to generic when known normalizer returns empty", () => {
      // nmap normalizer gets empty hosts -> returns [] -> falls through to generic
      const data = { hosts: [], extra: [{ info: "data" }] }
      const records = normalize("nmap", data)
      // Generic normalizer picks up the "extra" array
      expect(records.length).toBe(1)
      expect(records[0].info).toBe("data")
    })
  })
})

// ===========================================================================
// Output Store: Summary Generation
// ===========================================================================

describe("output-store.summary-generation", () => {
  test("store generates type breakdown for nmap data", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const data = nmapData(20)
    const rawOutput = bigString(6000)

    const result = await store({ sessionId: sid, tool: "nmap", method: "port_scan", data, rawOutput })
    expect(result.stored).toBe(true)
    expect(result.outputId).toBeDefined()
    expect(result.output).toContain("nmap.port_scan Result")
    expect(result.output).toContain("Total Records")
    expect(result.output).toContain("port:")
    expect(result.output).toContain("By Status")
    expect(result.output).toContain("open")
    expect(result.output).toContain("closed")
  })

  test("store generates preview lines for port records", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const data = { hosts: [{ ip: "10.10.10.1", ports: [
      { port: 22, protocol: "tcp", state: "open", service: { name: "ssh" } },
      { port: 80, protocol: "tcp", state: "open", service: { name: "http" } },
    ]}]}
    const rawOutput = bigString(6000)

    const result = await store({ sessionId: sid, tool: "nmap", data, rawOutput })
    expect(result.output).toContain("22/tcp")
    expect(result.output).toContain("80/tcp")
  })

  test("store generates preview for directory records", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const data = ffufData(20)
    const rawOutput = bigString(6000)

    const result = await store({ sessionId: sid, tool: "ffuf", data, rawOutput })
    expect(result.output).toContain("directory:")
    expect(result.output).toContain("/path-0")
  })

  test("store generates preview for credential records", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const data = {
      results: [
        { host: "10.10.10.1", port: 22, service: "ssh", login: "admin", password: "pass123" },
        { host: "10.10.10.1", port: 22, service: "ssh", login: "root", password: "toor" },
      ],
    }
    const rawOutput = bigString(6000)

    const result = await store({ sessionId: sid, tool: "hydra", data, rawOutput })
    expect(result.output).toContain("admin:***@10.10.10.1")
  })
})

// ===========================================================================
// Output Store: Threshold Logic
// ===========================================================================

describe("output-store.threshold", () => {
  test("small output is NOT stored externally", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const data = { hosts: [{ ip: "10.10.10.1", ports: [{ port: 22, state: "open" }] }] }
    const rawOutput = "PORT   STATE SERVICE\n22/tcp open  ssh"

    const result = await store({ sessionId: sid, tool: "nmap", data, rawOutput })
    expect(result.stored).toBe(false)
    expect(result.outputId).toBeUndefined()
    // Output directory should not exist
    const outputDir = join(SESSIONS_DIR, sid, "outputs")
    expect(existsSync(outputDir)).toBe(false)
  })

  test("large output IS stored externally", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const data = nmapData(50)
    const rawOutput = bigString(6000)

    const result = await store({ sessionId: sid, tool: "nmap", data, rawOutput })
    expect(result.stored).toBe(true)
    expect(result.outputId).toBeDefined()
    // Output file should exist on disk
    const outputPath = join(SESSIONS_DIR, sid, "outputs", `${result.outputId}.json`)
    expect(existsSync(outputPath)).toBe(true)
  })

  test("threshold is based on combined data+raw size", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    // Data alone is ~40 chars, raw alone is 4990 chars, combined = ~5030 > 5000
    const data = { small: "data" }
    const rawOutput = bigString(4990)

    const result = await store({ sessionId: sid, tool: "generic", data, rawOutput })
    expect(result.stored).toBe(true)
  })

  test("exactly at threshold is NOT stored", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    // JSON.stringify({}) = "{}" = 2 chars, so we need rawOutput of 4998 to hit exactly 5000
    const data = {}
    const rawOutput = bigString(4998)
    // {} is 2 chars -> 2 + 4998 = 5000 exactly, NOT greater, so should NOT be stored
    const result = await store({ sessionId: sid, tool: "test", data, rawOutput })
    expect(result.stored).toBe(false)
  })

  test("data=null with large raw output is stored", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const result = await store({ sessionId: sid, tool: "custom", data: null, rawOutput: bigString(5100) })
    expect(result.stored).toBe(true)
  })
})

// ===========================================================================
// Output Store: Small Output Formatting
// ===========================================================================

describe("output-store.direct-output", () => {
  test("small output with summary field is formatted nicely", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const data = { summary: { host: "10.10.10.1", open_ports: 3 } }
    const rawOutput = "small output"

    const result = await store({ sessionId: sid, tool: "nmap", data, rawOutput })
    expect(result.stored).toBe(false)
    expect(result.output).toContain("Summary")
    expect(result.output).toContain("host: 10.10.10.1")
    expect(result.output).toContain("open_ports: 3")
  })

  test("small output without summary returns JSON", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const data = { host: "10.10.10.1" }
    const rawOutput = "short"

    const result = await store({ sessionId: sid, tool: "nmap", data, rawOutput })
    expect(result.stored).toBe(false)
    expect(result.output).toContain('"host"')
    expect(result.output).toContain("10.10.10.1")
  })

  test("null data returns raw output directly", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const result = await store({ sessionId: sid, tool: "nmap", data: null, rawOutput: "raw text here" })
    expect(result.stored).toBe(false)
    expect(result.output).toBe("raw text here")
  })

  test("summary with array values truncates long arrays", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const data = {
      summary: {
        ports: Array.from({ length: 15 }, (_, i) => i + 1),
      },
    }

    const result = await store({ sessionId: sid, tool: "nmap", data, rawOutput: "" })
    expect(result.stored).toBe(false)
    expect(result.output).toContain("...")
  })
})

// ===========================================================================
// Output Store: File I/O (store + query + metadata + rawOutput)
// ===========================================================================

describe("output-store.file-io", () => {
  test("stored output file contains valid JSON with expected fields", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const data = nmapData(10)
    const rawOutput = bigString(6000)

    const result = await store({ sessionId: sid, tool: "nmap", method: "port_scan", data, rawOutput })
    expect(result.stored).toBe(true)

    const outputPath = join(SESSIONS_DIR, sid, "outputs", `${result.outputId}.json`)
    const stored: StoredOutput = JSON.parse(readFileSync(outputPath, "utf-8"))

    expect(stored.id).toBe(result.outputId)
    expect(stored.tool).toBe("nmap")
    expect(stored.method).toBe("port_scan")
    expect(stored.records.length).toBe(10)
    expect(stored.summary.total).toBe(10)
    expect(stored.rawOutput).toBe(rawOutput)
    expect(stored.sizeBytes).toBeGreaterThan(5000)
    expect(stored.timestamp).toBeGreaterThan(0)
  })

  test("method defaults to 'execute' when not specified", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const result = await store({ sessionId: sid, tool: "nmap", data: nmapData(10), rawOutput: bigString(6000) })
    const outputPath = join(SESSIONS_DIR, sid, "outputs", `${result.outputId}.json`)
    const stored: StoredOutput = JSON.parse(readFileSync(outputPath, "utf-8"))
    expect(stored.method).toBe("execute")
  })

  test("output IDs are unique across calls", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const r1 = await store({ sessionId: sid, tool: "nmap", data: nmapData(10), rawOutput: bigString(6000) })
    const r2 = await store({ sessionId: sid, tool: "nmap", data: nmapData(10), rawOutput: bigString(6000) })
    expect(r1.outputId).not.toBe(r2.outputId)
  })

  test("output ID format matches expected pattern", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const result = await store({ sessionId: sid, tool: "nmap", data: nmapData(10), rawOutput: bigString(6000) })
    expect(result.outputId).toMatch(/^out_[a-z0-9]+_[a-f0-9]{8}$/)
  })
})

// ===========================================================================
// Output Store: Query Interface
// ===========================================================================

describe("output-store.query", () => {
  test("retrieves all records when no filter specified", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const data = nmapData(5)
    const rawOutput = bigString(6000)
    const storeResult = await store({ sessionId: sid, tool: "nmap", data, rawOutput })

    const result = await query({ sessionId: sid, outputId: storeResult.outputId! })
    expect(result.found).toBe(true)
    expect(result.records.length).toBe(5)
    expect(result.total).toBe(5)
  })

  test("field:value query filters by exact match", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const data = nmapData(10)
    const rawOutput = bigString(6000)
    const storeResult = await store({ sessionId: sid, tool: "nmap", data, rawOutput })

    // Port 1000 + 0 = 1000
    const result = await query({ sessionId: sid, outputId: storeResult.outputId!, query: "port:1000" })
    expect(result.found).toBe(true)
    expect(result.records.length).toBe(1)
    expect(result.records[0].port).toBe(1000)
  })

  test("field:value query is case-insensitive for strings", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const data = nmapData(5)
    const rawOutput = bigString(6000)
    const storeResult = await store({ sessionId: sid, tool: "nmap", data, rawOutput })

    const result = await query({ sessionId: sid, outputId: storeResult.outputId!, query: "state:OPEN" })
    expect(result.found).toBe(true)
    expect(result.records.length).toBeGreaterThan(0)
    // All returned records should have state "open"
    for (const r of result.records) {
      expect(r.state.toLowerCase()).toBe("open")
    }
  })

  test("text search matches across all string fields", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const data = { hosts: [{ ip: "10.10.10.1", ports: [
      { port: 22, state: "open", service: { name: "ssh" } },
      { port: 80, state: "open", service: { name: "http" } },
    ]}]}
    const rawOutput = bigString(6000)
    const storeResult = await store({ sessionId: sid, tool: "nmap", data, rawOutput })

    const result = await query({ sessionId: sid, outputId: storeResult.outputId!, query: "ssh" })
    expect(result.found).toBe(true)
    expect(result.records.length).toBe(1)
    expect(result.records[0].service).toBe("ssh")
  })

  test("type filter limits to specific record type", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const data = {
      hosts: [{
        ip: "10.10.10.1",
        ports: [{ port: 22, state: "open" }],
        os_matches: [{ name: "Linux", accuracy: 90 }],
      }],
    }
    const rawOutput = bigString(6000)
    const storeResult = await store({ sessionId: sid, tool: "nmap", data, rawOutput })

    const result = await query({ sessionId: sid, outputId: storeResult.outputId!, type: "os" })
    expect(result.found).toBe(true)
    expect(result.records.length).toBe(1)
    expect(result.records[0].type).toBe("os")
  })

  test("limit parameter caps returned records", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const data = nmapData(20)
    const rawOutput = bigString(6000)
    const storeResult = await store({ sessionId: sid, tool: "nmap", data, rawOutput })

    const result = await query({ sessionId: sid, outputId: storeResult.outputId!, limit: 3 })
    expect(result.found).toBe(true)
    expect(result.records.length).toBe(3)
    expect(result.total).toBe(20) // total is unaffected by limit
  })

  test("returns not-found for invalid output ID", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const result = await query({ sessionId: sid, outputId: "out_nonexistent_00000000" })
    expect(result.found).toBe(false)
    expect(result.error).toContain("not found")
    expect(result.records).toEqual([])
  })

  test("field:value with non-existent field returns empty", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const data = nmapData(5)
    const rawOutput = bigString(6000)
    const storeResult = await store({ sessionId: sid, tool: "nmap", data, rawOutput })

    const result = await query({ sessionId: sid, outputId: storeResult.outputId!, query: "nonexistent:value" })
    expect(result.found).toBe(true)
    expect(result.records.length).toBe(0)
  })

  test("text search is case-insensitive", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const data = { hosts: [{ ip: "10.10.10.1", ports: [
      { port: 22, state: "open", service: { name: "OpenSSH" } },
    ]}]}
    const rawOutput = bigString(6000)
    const storeResult = await store({ sessionId: sid, tool: "nmap", data, rawOutput })

    const result = await query({ sessionId: sid, outputId: storeResult.outputId!, query: "openssh" })
    expect(result.found).toBe(true)
    expect(result.records.length).toBe(1)
  })

  test("combined type + query filter", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const data = nmapData(10)
    const rawOutput = bigString(6000)
    const storeResult = await store({ sessionId: sid, tool: "nmap", data, rawOutput })

    // Filter by type=port AND state:open
    const result = await query({
      sessionId: sid,
      outputId: storeResult.outputId!,
      type: "port",
      query: "state:open",
    })
    expect(result.found).toBe(true)
    // Even-indexed ports (0,2,4,6,8) are open
    expect(result.records.length).toBe(5)
  })
})

// ===========================================================================
// Output Store: getMetadata
// ===========================================================================

describe("output-store.getMetadata", () => {
  test("returns metadata for stored output", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const data = nmapData(5)
    const rawOutput = bigString(6000)
    const storeResult = await store({ sessionId: sid, tool: "nmap", method: "port_scan", data, rawOutput })

    const meta = await getMetadata(sid, storeResult.outputId!)
    expect(meta.found).toBe(true)
    expect(meta.tool).toBe("nmap")
    expect(meta.method).toBe("port_scan")
    expect(meta.recordCount).toBe(5)
    expect(meta.sizeBytes).toBeGreaterThan(0)
    expect(meta.timestamp).toBeGreaterThan(0)
  })

  test("returns not-found for missing output", async () => {
    const meta = await getMetadata("nonexistent-session", "out_fake_00000000")
    expect(meta.found).toBe(false)
    expect(meta.tool).toBeUndefined()
  })
})

// ===========================================================================
// Output Store: getRawOutput
// ===========================================================================

describe("output-store.getRawOutput", () => {
  test("returns raw output string for stored output", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    const rawOutput = "PORT   STATE SERVICE\n22/tcp open  ssh\n80/tcp open  http" + bigString(5000)
    const data = nmapData(5)
    const storeResult = await store({ sessionId: sid, tool: "nmap", data, rawOutput })

    const raw = await getRawOutput(sid, storeResult.outputId!)
    expect(raw).toBe(rawOutput)
  })

  test("returns null for missing output", async () => {
    const raw = await getRawOutput("nonexistent-session", "out_fake_00000000")
    expect(raw).toBeNull()
  })
})

// ===========================================================================
// Output Store: cleanupSession
// ===========================================================================

describe("output-store.cleanupSession", () => {
  test("removes all outputs for a session", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    await store({ sessionId: sid, tool: "nmap", data: nmapData(10), rawOutput: bigString(6000) })
    await store({ sessionId: sid, tool: "ffuf", data: ffufData(10), rawOutput: bigString(6000) })

    const outputDir = join(SESSIONS_DIR, sid, "outputs")
    expect(existsSync(outputDir)).toBe(true)

    await cleanupSession(sid)
    expect(existsSync(outputDir)).toBe(false)
  })

  test("cleanupSession is safe on non-existent session", async () => {
    // Should not throw
    await cleanupSession("nonexistent-session-xyz")
  })
})

// ===========================================================================
// Output Store: cleanup (REQ-ARC-029 — 24-hour retention)
// ===========================================================================

describe("output-store.cleanup", () => {
  test("deletes outputs older than 24 hours", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    // Store an output
    const result = await store({ sessionId: sid, tool: "nmap", data: nmapData(10), rawOutput: bigString(6000) })
    expect(result.stored).toBe(true)

    // Manually backdate the stored file's timestamp to 25 hours ago
    const outputDir = join(SESSIONS_DIR, sid, "outputs")
    const files = readdirSync(outputDir)
    expect(files.length).toBe(1)

    const filePath = join(outputDir, files[0])
    const content = JSON.parse(readFileSync(filePath, "utf-8"))
    content.timestamp = Date.now() - 25 * 60 * 60 * 1000 // 25 hours ago
    writeFileSync(filePath, JSON.stringify(content))

    const { deleted } = await cleanup()
    expect(deleted).toBe(1)
    expect(existsSync(filePath)).toBe(false)
  })

  test("preserves outputs newer than 24 hours", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    await store({ sessionId: sid, tool: "nmap", data: nmapData(10), rawOutput: bigString(6000) })

    const outputDir = join(SESSIONS_DIR, sid, "outputs")
    const filesBefore = readdirSync(outputDir)

    const { deleted } = await cleanup()
    expect(deleted).toBe(0)

    const filesAfter = readdirSync(outputDir)
    expect(filesAfter.length).toBe(filesBefore.length)
  })

  test("removes empty session output directories after cleanup", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    await store({ sessionId: sid, tool: "nmap", data: nmapData(10), rawOutput: bigString(6000) })

    // Backdate to trigger deletion
    const outputDir = join(SESSIONS_DIR, sid, "outputs")
    const files = readdirSync(outputDir)
    const filePath = join(outputDir, files[0])
    const content = JSON.parse(readFileSync(filePath, "utf-8"))
    content.timestamp = Date.now() - 25 * 60 * 60 * 1000
    writeFileSync(filePath, JSON.stringify(content))

    await cleanup()
    expect(existsSync(outputDir)).toBe(false) // empty dir removed
  })

  test("handles malformed JSON by falling back to file mtime", async () => {
    const sid = testSessionId()
    sessionsToClean.push(sid)

    // Create a valid output first to get the directory
    await store({ sessionId: sid, tool: "nmap", data: nmapData(10), rawOutput: bigString(6000) })

    const outputDir = join(SESSIONS_DIR, sid, "outputs")
    // Write a malformed JSON file with old mtime
    const badFile = join(outputDir, "out_bad_12345678.json")
    writeFileSync(badFile, "not valid json{{{")
    // Touch the file to make it old
    const oldTime = new Date(Date.now() - 25 * 60 * 60 * 1000)
    utimesSync(badFile, oldTime, oldTime)

    const { deleted } = await cleanup()
    expect(deleted).toBeGreaterThanOrEqual(1)
    expect(existsSync(badFile)).toBe(false)
  })

  test("safe when SESSIONS_DIR does not exist", async () => {
    // cleanup() should not throw even if the sessions directory doesn't exist
    // This is already handled by the existsSync check
    const { deleted } = await cleanup()
    // deleted could be 0 or more depending on other test state, but should not throw
    expect(typeof deleted).toBe("number")
  })
})

// ===========================================================================
// Output Store: formatQueryResults
// ===========================================================================

describe("output-store.formatQueryResults", () => {
  test("formats port records as a table", () => {
    const records: OutputRecord[] = [
      { type: "port", port: 22, protocol: "tcp", state: "open", service: "ssh", version: "8.2" },
      { type: "port", port: 80, protocol: "tcp", state: "open", service: "http", version: "" },
    ]
    const output = formatQueryResults(records, 2, 50)
    expect(output).toContain("| Port |")
    expect(output).toContain("| 22 |")
    expect(output).toContain("| 80 |")
  })

  test("formats directory records as a table", () => {
    const records: OutputRecord[] = [
      { type: "directory", path: "/admin", status: 200, length: 1234 },
      { type: "directory", path: "/login", status: 302, size: 0 },
    ]
    const output = formatQueryResults(records, 2, 50)
    expect(output).toContain("| Path |")
    expect(output).toContain("| /admin |")
  })

  test("formats vulnerability records as a list", () => {
    const records: OutputRecord[] = [
      { type: "vulnerability", name: "Log4Shell", severity: "critical", host: "target.htb", port: 8080, description: "Remote code execution via JNDI" },
    ]
    const output = formatQueryResults(records, 1, 50)
    expect(output).toContain("**Log4Shell**")
    expect(output).toContain("Severity: critical")
    expect(output).toContain("target.htb:8080")
  })

  test("formats credential records with hidden passwords", () => {
    const records: OutputRecord[] = [
      { type: "credential", host: "10.10.10.1", service: "ssh", login: "admin", password: "secret" },
    ]
    const output = formatQueryResults(records, 1, 50)
    expect(output).toContain("| admin |")
    expect(output).toContain("*** |") // password hidden
    expect(output).not.toContain("secret")
  })

  test("formats unknown record types as JSON", () => {
    const records: OutputRecord[] = [
      { type: "custom", foo: "bar", num: 42 },
    ]
    const output = formatQueryResults(records, 1, 50)
    expect(output).toContain("foo")
    expect(output).toContain("bar")
  })

  test("shows truncation notice when total exceeds displayed", () => {
    const records: OutputRecord[] = [
      { type: "port", port: 22, protocol: "tcp", state: "open" },
    ]
    const output = formatQueryResults(records, 100, 50)
    expect(output).toContain("Showing 1 of 100")
  })

  test("returns no-match message for empty results", () => {
    const output = formatQueryResults([], 0, 50)
    expect(output).toBe("No matching records found.")
  })
})
