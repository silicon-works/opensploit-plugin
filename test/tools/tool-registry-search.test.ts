import { describe, expect, test, afterEach } from "bun:test"
import { mkdirSync, writeFileSync, rmSync, existsSync } from "fs"
import { join } from "path"
import * as SessionDirectory from "../../src/session/directory"
import { registerRootSession, unregister } from "../../src/session/hierarchy"
import yaml from "js-yaml"

import {
  calculateTriggerBonus,
  calculateUseForBonus,
  calculateNeverUseForPenalty,
  checkAntiPatterns,
  normalizeNeverUseFor,
  extractSuggestedAlternatives,
  formatToolResult,
  formatToolResultWithSuggestion,
  formatOutput,
  searchToolsInMemory,
  mergeSessionRecipes,
  isCacheStale,
  scoreAndGroupMethods,
  createToolRegistrySearchTool,
  RegistrySchema,
  RegistryToolSchema,
  VALID_PHASES,
  REGISTRY_CONFIG,
  type Registry,
  type RegistryTool,
  type ToolSearchResult,
} from "../../src/tools/tool-registry-search"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeTool(overrides: Partial<RegistryTool> = {}): RegistryTool {
  return RegistryToolSchema.parse({
    name: overrides.name ?? "test-tool",
    description: overrides.description ?? "A test tool",
    capabilities: overrides.capabilities ?? [],
    phases: overrides.phases ?? [],
    ...overrides,
  })
}

function makeRegistry(tools: Record<string, Partial<RegistryTool>> = {}): Registry {
  const parsed: Record<string, RegistryTool> = {}
  for (const [id, partial] of Object.entries(tools)) {
    parsed[id] = makeTool({ name: partial.name ?? id, ...partial })
  }
  return RegistrySchema.parse({ version: "2.0", tools: parsed })
}

// ---------------------------------------------------------------------------
// 1. Schema Validation (RegistrySchema, RegistryToolSchema)
// ---------------------------------------------------------------------------

describe("registry schema validation", () => {
  test("RegistryToolSchema accepts a minimal tool", () => {
    const tool = RegistryToolSchema.parse({
      name: "nmap",
      description: "Network scanner",
    })
    expect(tool.name).toBe("nmap")
    expect(tool.capabilities).toEqual([])
    expect(tool.phases).toEqual([])
  })

  test("RegistryToolSchema accepts a fully-featured tool", () => {
    const tool = RegistryToolSchema.parse({
      name: "sqlmap",
      version: "1.8",
      description: "SQL injection testing",
      image: "ghcr.io/silicon-works/mcp-tools-sqlmap:latest",
      image_size_mb: 150,
      external: false,
      capabilities: ["sql_injection", "database_extraction"],
      phases: ["exploitation"],
      routing: {
        use_for: ["SQL injection testing"],
        triggers: ["sql.*inject"],
        never_use_for: [
          { task: "port scanning", use_instead: "nmap", reason: "wrong tool" },
          "authentication brute force",
        ],
        prefer_over: ["manual-sql"],
      },
      requirements: {
        network: true,
        privileged: false,
      },
      resources: {
        memory_mb: 256,
        cpu: 1,
      },
      methods: {
        scan: {
          description: "Run SQL injection scan",
          when_to_use: "When you suspect SQL injection",
          next_step: "Extract data if injection found",
          params: {
            url: { type: "string", required: true, description: "Target URL" },
            level: { type: "number", required: false, default: 1, description: "Injection level" },
          },
          returns: {
            vulnerable: { type: "boolean", description: "Whether injection was found" },
          },
        },
      },
      see_also: ["curl", "web-session"],
    })
    expect(tool.name).toBe("sqlmap")
    expect(tool.capabilities).toContain("sql_injection")
    expect(tool.methods?.scan?.description).toBe("Run SQL injection scan")
  })

  test("RegistryToolSchema rejects tool missing name", () => {
    expect(() => RegistryToolSchema.parse({ description: "no name" })).toThrow()
  })

  test("RegistryToolSchema rejects tool missing description", () => {
    expect(() => RegistryToolSchema.parse({ name: "bad" })).toThrow()
  })

  test("RegistrySchema validates a complete registry", () => {
    const reg = RegistrySchema.parse({
      version: "2.0",
      tools: {
        nmap: { name: "nmap", description: "Network mapper" },
        ffuf: { name: "ffuf", description: "Web fuzzer" },
      },
    })
    expect(reg.version).toBe("2.0")
    expect(Object.keys(reg.tools)).toHaveLength(2)
  })

  test("RegistrySchema rejects registry without version", () => {
    expect(() =>
      RegistrySchema.parse({
        tools: { nmap: { name: "nmap", description: "Network mapper" } },
      })
    ).toThrow()
  })
})

// ---------------------------------------------------------------------------
// 2. VALID_PHASES
// ---------------------------------------------------------------------------

describe("VALID_PHASES", () => {
  test("contains exactly the four security phases", () => {
    expect(VALID_PHASES).toEqual([
      "reconnaissance",
      "enumeration",
      "exploitation",
      "post-exploitation",
    ])
  })

  test("phases are immutable (readonly tuple)", () => {
    expect(VALID_PHASES.length).toBe(4)
  })
})

// ---------------------------------------------------------------------------
// 3. REGISTRY_CONFIG
// ---------------------------------------------------------------------------

describe("REGISTRY_CONFIG", () => {
  test("remote URLs point to opensploit.ai", () => {
    expect(REGISTRY_CONFIG.REMOTE_URL).toContain("opensploit.ai")
    expect(REGISTRY_CONFIG.REMOTE_HASH_URL).toContain("opensploit.ai")
    expect(REGISTRY_CONFIG.REMOTE_LANCE_URL).toContain("opensploit.ai")
  })

  test("cache paths are under ~/.opensploit", () => {
    expect(REGISTRY_CONFIG.CACHE_DIR).toContain(".opensploit")
    expect(REGISTRY_CONFIG.CACHE_PATH).toContain("registry.yaml")
  })

  test("cache TTL is 24 hours", () => {
    expect(REGISTRY_CONFIG.CACHE_TTL_MS).toBe(24 * 60 * 60 * 1000)
  })
})

// ---------------------------------------------------------------------------
// 4. isCacheStale
// ---------------------------------------------------------------------------

describe("isCacheStale", () => {
  test("returns false for timestamp within TTL", () => {
    expect(isCacheStale(Date.now() - 1000)).toBe(false)
  })

  test("returns false for timestamp at TTL boundary minus 1", () => {
    expect(isCacheStale(Date.now() - REGISTRY_CONFIG.CACHE_TTL_MS + 1)).toBe(false)
  })

  test("returns true for timestamp older than TTL", () => {
    expect(isCacheStale(Date.now() - REGISTRY_CONFIG.CACHE_TTL_MS - 1)).toBe(true)
  })

  test("returns true for timestamp of 0 (epoch)", () => {
    expect(isCacheStale(0)).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// 5. calculateTriggerBonus (Bug Fix 1: triggers matched as regex)
// ---------------------------------------------------------------------------

describe("calculateTriggerBonus", () => {
  test("returns 0 when tool has no triggers", () => {
    const tool = makeTool({ routing: { use_for: [] } })
    expect(calculateTriggerBonus("port scan", tool)).toBe(0)
  })

  test("returns 0 when no triggers match", () => {
    const tool = makeTool({ routing: { triggers: ["sql.*inject"] } })
    expect(calculateTriggerBonus("port scan", tool)).toBe(0)
  })

  test("returns 35 when regex trigger matches", () => {
    const tool = makeTool({ routing: { triggers: ["sql.*inject"] } })
    expect(calculateTriggerBonus("SQL injection test", tool)).toBe(35)
  })

  test("matches triggers case-insensitively", () => {
    const tool = makeTool({ routing: { triggers: ["PORT\\s+SCAN"] } })
    expect(calculateTriggerBonus("port scan the target", tool)).toBe(35)
  })

  test("accumulates bonus for multiple matching triggers", () => {
    const tool = makeTool({ routing: { triggers: ["port", "scan"] } })
    expect(calculateTriggerBonus("port scan", tool)).toBe(70)
  })

  test("ignores invalid regex patterns gracefully", () => {
    const tool = makeTool({ routing: { triggers: ["[invalid", "port"] } })
    expect(calculateTriggerBonus("port scan", tool)).toBe(35)
  })
})

// ---------------------------------------------------------------------------
// 6. calculateUseForBonus (Bug Fix 2: use_for weighted)
// ---------------------------------------------------------------------------

describe("calculateUseForBonus", () => {
  test("returns 0 when tool has no use_for", () => {
    const tool = makeTool({ routing: {} })
    expect(calculateUseForBonus("anything", tool)).toBe(0)
  })

  test("returns 8 for exact substring match (query includes use_for)", () => {
    const tool = makeTool({ routing: { use_for: ["port scanning"] } })
    expect(calculateUseForBonus("I need port scanning", tool)).toBe(8)
  })

  test("returns 5 for reverse substring match (use_for includes query)", () => {
    const tool = makeTool({ routing: { use_for: ["port scanning and enumeration"] } })
    expect(calculateUseForBonus("port", tool)).toBe(5)
  })

  test("returns 3 for word overlap >= 2", () => {
    const tool = makeTool({ routing: { use_for: ["network port scanning"] } })
    expect(calculateUseForBonus("scanning network interfaces", tool)).toBe(3)
  })

  test("returns 0 for no meaningful overlap", () => {
    const tool = makeTool({ routing: { use_for: ["SQL injection"] } })
    expect(calculateUseForBonus("port scanning", tool)).toBe(0)
  })

  test("accumulates bonuses for multiple matching use_for entries", () => {
    const tool = makeTool({ routing: { use_for: ["port scanning", "network mapping"] } })
    // "port scanning" is substring of query → 8
    // "network mapping" no match → 0
    expect(calculateUseForBonus("run port scanning on target", tool)).toBe(8)
  })
})

// ---------------------------------------------------------------------------
// 7. calculateNeverUseForPenalty (Bug Fix 3: never_use_for penalizes)
// ---------------------------------------------------------------------------

describe("calculateNeverUseForPenalty", () => {
  test("returns 0 when tool has no never_use_for", () => {
    const tool = makeTool({ routing: {} })
    expect(calculateNeverUseForPenalty("anything", tool)).toBe(0)
  })

  test("returns -15 when query matches a string pattern", () => {
    const tool = makeTool({ routing: { never_use_for: ["port scanning"] } })
    expect(calculateNeverUseForPenalty("do port scanning", tool)).toBe(-15)
  })

  test("returns -15 when query matches an object pattern task", () => {
    const tool = makeTool({
      routing: {
        never_use_for: [{ task: "port scanning", use_instead: "nmap" }],
      },
    })
    expect(calculateNeverUseForPenalty("do port scanning", tool)).toBe(-15)
  })

  test("returns 0 when query does not match never_use_for", () => {
    const tool = makeTool({
      routing: { never_use_for: ["port scanning"] },
    })
    expect(calculateNeverUseForPenalty("SQL injection", tool)).toBe(0)
  })

  test("accumulates penalties for multiple matches", () => {
    const tool = makeTool({
      routing: { never_use_for: ["port scanning", "scanning"] },
    })
    // Both contain "scanning" but only second one matches "scanning"
    // "port scanning" is in "do port scanning" → -15
    // "scanning" is in "do port scanning" → -15
    expect(calculateNeverUseForPenalty("do port scanning", tool)).toBe(-30)
  })
})

// ---------------------------------------------------------------------------
// 8. checkAntiPatterns
// ---------------------------------------------------------------------------

describe("checkAntiPatterns", () => {
  test("returns undefined when no anti-patterns match", () => {
    const tool = makeTool({ routing: { never_use_for: ["port scanning"] } })
    expect(checkAntiPatterns("SQL injection", tool)).toBeUndefined()
  })

  test("returns warning string for matching string pattern", () => {
    const tool = makeTool({
      name: "curl",
      routing: { never_use_for: ["web scraping"] },
    })
    const warning = checkAntiPatterns("web scraping target", tool)
    expect(warning).toContain("curl")
    expect(warning).toContain("web scraping")
  })

  test("returns warning with use_instead for object pattern", () => {
    const tool = makeTool({
      name: "curl",
      routing: {
        never_use_for: [
          { task: "web scraping", use_instead: "playwright-mcp", reason: "curl returns empty for JS pages" },
        ],
      },
    })
    const warning = checkAntiPatterns("web scraping", tool)
    expect(warning).toContain("playwright-mcp")
    expect(warning).toContain("curl returns empty for JS pages")
  })

  test("returns warning with array use_instead joined", () => {
    const tool = makeTool({
      name: "curl",
      routing: {
        never_use_for: [
          { task: "web pages", use_instead: ["playwright-mcp", "web-session"] },
        ],
      },
    })
    const warning = checkAntiPatterns("render web pages", tool)
    expect(warning).toContain("playwright-mcp or web-session")
  })

  test("returns undefined when tool has no never_use_for", () => {
    const tool = makeTool({ routing: {} })
    expect(checkAntiPatterns("anything", tool)).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// 9. normalizeNeverUseFor
// ---------------------------------------------------------------------------

describe("normalizeNeverUseFor", () => {
  test("converts string entries to object format", () => {
    const result = normalizeNeverUseFor(["port scanning", "web scraping"])
    expect(result).toEqual([
      { task: "port scanning", use_instead: "" },
      { task: "web scraping", use_instead: "" },
    ])
  })

  test("passes through object entries unchanged", () => {
    const input = [{ task: "scanning", use_instead: "nmap", reason: "better tool" }]
    const result = normalizeNeverUseFor(input)
    expect(result[0].task).toBe("scanning")
    expect(result[0].use_instead).toBe("nmap")
    expect(result[0].reason).toBe("better tool")
  })

  test("handles mixed string and object entries", () => {
    const result = normalizeNeverUseFor([
      "simple task",
      { task: "complex task", use_instead: "better-tool" },
    ])
    expect(result).toHaveLength(2)
    expect(result[0].task).toBe("simple task")
    expect(result[1].task).toBe("complex task")
  })

  test("returns empty array for empty input", () => {
    expect(normalizeNeverUseFor([])).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// 10. extractSuggestedAlternatives
// ---------------------------------------------------------------------------

describe("extractSuggestedAlternatives", () => {
  test("extracts from prefer_over", () => {
    const tool = makeTool({ routing: { prefer_over: ["curl", "wget"] } })
    const alts = extractSuggestedAlternatives(tool)
    expect(alts).toContain("curl")
    expect(alts).toContain("wget")
  })

  test("extracts from never_use_for use_instead (string)", () => {
    const tool = makeTool({
      routing: {
        never_use_for: [
          { task: "scanning", use_instead: "nmap" },
        ],
      },
    })
    expect(extractSuggestedAlternatives(tool)).toContain("nmap")
  })

  test("extracts from never_use_for use_instead (array)", () => {
    const tool = makeTool({
      routing: {
        never_use_for: [
          { task: "scanning", use_instead: ["nmap", "masscan"] },
        ],
      },
    })
    const alts = extractSuggestedAlternatives(tool)
    expect(alts).toContain("nmap")
    expect(alts).toContain("masscan")
  })

  test("deduplicates alternatives", () => {
    const tool = makeTool({
      routing: {
        prefer_over: ["nmap"],
        never_use_for: [{ task: "scanning", use_instead: "nmap" }],
      },
    })
    const alts = extractSuggestedAlternatives(tool)
    expect(alts.filter((a) => a === "nmap")).toHaveLength(1)
  })

  test("returns empty for tool with no routing", () => {
    const tool = makeTool({})
    expect(extractSuggestedAlternatives(tool)).toEqual([])
  })

  test("skips string-only never_use_for entries (no use_instead)", () => {
    const tool = makeTool({
      routing: { never_use_for: ["port scanning"] },
    })
    expect(extractSuggestedAlternatives(tool)).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// 11. formatToolResult
// ---------------------------------------------------------------------------

describe("formatToolResult", () => {
  test("formats a minimal tool correctly", () => {
    const tool = makeTool({
      name: "nmap",
      description: "Network scanner",
      phases: ["reconnaissance"],
      capabilities: ["port_scanning"],
    })
    const result = formatToolResult("nmap", tool)
    expect(result.tool).toBe("nmap")
    expect(result.name).toBe("nmap")
    expect(result.description).toBe("Network scanner")
    expect(result.phases).toContain("reconnaissance")
    expect(result.capabilities).toContain("port_scanning")
    expect(result.methods).toEqual([])
  })

  test("includes methods with params and returns", () => {
    const tool = makeTool({
      name: "sqlmap",
      description: "SQL injection",
      methods: {
        scan: {
          description: "Run scan",
          when_to_use: "SQL injection suspected",
          next_step: "Extract data",
          params: {
            url: { type: "string", required: true, description: "Target URL" },
          },
          returns: {
            vulnerable: { type: "boolean", description: "Result" },
          },
        },
      },
    })
    const result = formatToolResult("sqlmap", tool)
    expect(result.methods).toHaveLength(1)
    expect(result.methods[0].name).toBe("scan")
    expect(result.methods[0].when_to_use).toBe("SQL injection suspected")
    expect(result.methods[0].next_step).toBe("Extract data")
    expect(result.methods[0].params.url.required).toBe(true)
    expect(result.methods[0].returns?.vulnerable.type).toBe("boolean")
  })

  test("includes routing information", () => {
    const tool = makeTool({
      name: "nmap",
      description: "Scanner",
      routing: {
        use_for: ["port scanning", "host discovery"],
        triggers: ["nmap"],
        never_use_for: [{ task: "web fuzzing", use_instead: "ffuf" }],
        prefer_over: ["masscan"],
      },
    })
    const result = formatToolResult("nmap", tool)
    expect(result.routing.use_for).toEqual(["port scanning", "host discovery"])
    expect(result.routing.triggers).toEqual(["nmap"])
    expect(result.routing.never_use_for?.[0].task).toBe("web fuzzing")
    expect(result.routing.prefer_over).toEqual(["masscan"])
    expect(result.suggested_alternatives).toContain("masscan")
    expect(result.suggested_alternatives).toContain("ffuf")
  })

  test("includes warning when provided", () => {
    const tool = makeTool({ name: "bad-tool", description: "Don't use" })
    const result = formatToolResult("bad-tool", tool, "This tool is deprecated")
    expect(result.warning).toBe("This tool is deprecated")
  })

  test("includes requirements when present", () => {
    const tool = makeTool({
      name: "nmap",
      description: "Scanner",
      requirements: { network: true, privileged: true, privileged_reason: "raw sockets" },
    })
    const result = formatToolResult("nmap", tool)
    expect(result.requirements?.network).toBe(true)
    expect(result.requirements?.privileged).toBe(true)
    expect(result.requirements?.privileged_reason).toBe("raw sockets")
  })
})

// ---------------------------------------------------------------------------
// 12. formatToolResultWithSuggestion
// ---------------------------------------------------------------------------

describe("formatToolResultWithSuggestion", () => {
  const toolWithMethods = makeTool({
    name: "nmap",
    description: "Scanner",
    methods: {
      quick_scan: { description: "Fast scan" },
      full_scan: { description: "Comprehensive scan" },
      vuln_scan: { description: "Vulnerability scan" },
    },
  })

  test("sets suggested_method field", () => {
    const result = formatToolResultWithSuggestion("nmap", toolWithMethods, "full_scan", [])
    expect(result.suggested_method).toBe("full_scan")
  })

  test("reorders methods so suggested is first", () => {
    const result = formatToolResultWithSuggestion("nmap", toolWithMethods, "vuln_scan", [])
    expect(result.methods[0].name).toBe("vuln_scan")
  })

  test("appends see_also to suggested_alternatives", () => {
    const result = formatToolResultWithSuggestion("nmap", toolWithMethods, "quick_scan", ["masscan", "rustscan"])
    expect(result.suggested_alternatives).toContain("masscan")
    expect(result.suggested_alternatives).toContain("rustscan")
  })

  test("does not duplicate see_also if already in suggested_alternatives", () => {
    const toolWithPreferOver = makeTool({
      name: "nmap",
      description: "Scanner",
      routing: { prefer_over: ["masscan"] },
      methods: { scan: { description: "Scan" } },
    })
    const result = formatToolResultWithSuggestion("nmap", toolWithPreferOver, "scan", ["masscan"])
    const masscanCount = result.suggested_alternatives!.filter((a) => a === "masscan").length
    expect(masscanCount).toBe(1)
  })

  test("handles empty see_also", () => {
    const result = formatToolResultWithSuggestion("nmap", toolWithMethods, "quick_scan", [])
    // No error, no extra alternatives beyond routing
    expect(result.suggested_method).toBe("quick_scan")
  })
})

// ---------------------------------------------------------------------------
// 13. formatOutput
// ---------------------------------------------------------------------------

describe("formatOutput", () => {
  test("formats header with query and result count", () => {
    const searchResult: ToolSearchResult = {
      query: "port scanning",
      results: [],
      anti_pattern_warnings: [],
      registry_hash: "abcdef1234567890abcdef1234567890",
    }
    const output = formatOutput(searchResult)
    expect(output).toContain("port scanning")
    expect(output).toContain("0 tools found")
    expect(output).toContain("abcdef1234567890")
  })

  test("includes phase filter when specified", () => {
    const searchResult: ToolSearchResult = {
      query: "scanning",
      phase: "reconnaissance",
      results: [],
      anti_pattern_warnings: [],
      registry_hash: "abc123",
    }
    const output = formatOutput(searchResult)
    expect(output).toContain("Phase Filter:** reconnaissance")
  })

  test("includes capability filter when specified", () => {
    const searchResult: ToolSearchResult = {
      query: "scanning",
      capability: "port_scanning",
      results: [],
      anti_pattern_warnings: [],
      registry_hash: "abc123",
    }
    const output = formatOutput(searchResult)
    expect(output).toContain("Capability Filter:** port_scanning")
  })

  test("shows stale cache warning", () => {
    const searchResult: ToolSearchResult = {
      query: "scan",
      results: [],
      anti_pattern_warnings: [],
      registry_hash: "abc123",
      cache_status: "stale",
    }
    const output = formatOutput(searchResult)
    expect(output).toContain("opensploit update")
  })

  test("includes anti-pattern warnings section", () => {
    const searchResult: ToolSearchResult = {
      query: "web scraping",
      results: [],
      anti_pattern_warnings: ["curl should not be used for web scraping"],
      registry_hash: "abc123",
    }
    const output = formatOutput(searchResult)
    expect(output).toContain("Warnings")
    expect(output).toContain("curl should not be used for web scraping")
  })

  test("shows valid phases hint when no results found", () => {
    const searchResult: ToolSearchResult = {
      query: "nonexistent",
      results: [],
      anti_pattern_warnings: [],
      registry_hash: "abc123",
    }
    const output = formatOutput(searchResult)
    expect(output).toContain("No tools found")
    expect(output).toContain("reconnaissance")
    expect(output).toContain("exploitation")
  })

  test("formats tool details when results present", () => {
    const tool = makeTool({
      name: "nmap",
      description: "Network scanner",
      image: "ghcr.io/silicon-works/mcp-tools-nmap:latest",
      phases: ["reconnaissance"],
      capabilities: ["port_scanning"],
      requirements: { network: true, privileged: true, privileged_reason: "raw sockets" },
      routing: { use_for: ["port scanning", "host discovery"] },
      methods: {
        quick_scan: {
          description: "Fast TCP scan",
          when_to_use: "For initial recon",
          params: { target: { type: "string", required: true, description: "IP address" } },
          returns: { ports: { type: "array", description: "Open ports" } },
          next_step: "Run full scan on found ports",
        },
      },
    })
    const result = formatToolResult("nmap", tool)

    const searchResult: ToolSearchResult = {
      query: "port scan",
      results: [result],
      anti_pattern_warnings: [],
      registry_hash: "abc123",
    }
    const output = formatOutput(searchResult)
    expect(output).toContain("## nmap")
    expect(output).toContain("Network scanner")
    expect(output).toContain("ghcr.io/silicon-works/mcp-tools-nmap:latest")
    expect(output).toContain("reconnaissance")
    expect(output).toContain("port_scanning")
    expect(output).toContain("raw sockets")
    expect(output).toContain("port scanning, host discovery")
    expect(output).toContain("quick_scan")
    expect(output).toContain("Fast TCP scan")
    expect(output).toContain("For initial recon")
    expect(output).toContain("IP address")
    expect(output).toContain("Open ports")
    expect(output).toContain("Run full scan on found ports")
    expect(output).toContain("MCP with the tool ID")
  })

  test("shows suggested method prominently when not 'default'", () => {
    const toolWithSuggestion = makeTool({
      name: "nmap",
      description: "Scanner",
      methods: {
        vuln_scan: { description: "Vulnerability scan" },
        quick_scan: { description: "Fast scan" },
      },
    })
    const result = formatToolResultWithSuggestion("nmap", toolWithSuggestion, "vuln_scan", [])

    const searchResult: ToolSearchResult = {
      query: "vulnerability scan",
      results: [result],
      anti_pattern_warnings: [],
      registry_hash: "abc123",
    }
    const output = formatOutput(searchResult)
    expect(output).toContain("Suggested method:** `vuln_scan`")
  })

  test("does NOT show suggested method when it is 'default'", () => {
    const toolDef = makeTool({
      name: "nmap",
      description: "Scanner",
      methods: { default: { description: "Default method" } },
    })
    const result = formatToolResultWithSuggestion("nmap", toolDef, "default", [])

    const searchResult: ToolSearchResult = {
      query: "scan",
      results: [result],
      anti_pattern_warnings: [],
      registry_hash: "abc123",
    }
    const output = formatOutput(searchResult)
    expect(output).not.toContain("Suggested method:** `default`")
  })
})

// ---------------------------------------------------------------------------
// 14. searchToolsInMemory (keyword-based fallback)
// ---------------------------------------------------------------------------

describe("searchToolsInMemory", () => {
  const registry = makeRegistry({
    nmap: {
      name: "nmap",
      description: "Network mapper and port scanner",
      capabilities: ["port_scanning", "host_discovery"],
      phases: ["reconnaissance", "enumeration"],
      routing: {
        use_for: ["port scanning", "network discovery"],
        triggers: ["nmap"],
      },
    },
    sqlmap: {
      name: "sqlmap",
      description: "Automatic SQL injection and database takeover tool",
      capabilities: ["sql_injection", "database_extraction"],
      phases: ["exploitation"],
      routing: {
        use_for: ["SQL injection testing"],
        triggers: ["sql.*inject"],
        never_use_for: ["port scanning"],
      },
    },
    ffuf: {
      name: "ffuf",
      description: "Fast web fuzzer for directory and parameter discovery",
      capabilities: ["web_fuzzing", "directory_brute_force"],
      phases: ["enumeration"],
      routing: {
        use_for: ["directory brute force", "parameter fuzzing"],
      },
    },
    hydra: {
      name: "hydra",
      description: "Network login cracker and password brute force tool",
      capabilities: ["password_cracking", "brute_force"],
      phases: ["exploitation"],
      routing: {
        use_for: ["password brute force", "login cracking"],
      },
    },
  })

  test("finds tools matching keyword query", () => {
    const result = searchToolsInMemory(registry, "port scanning")
    expect(result.results.length).toBeGreaterThan(0)
    expect(result.results[0].tool).toBe("nmap")
  })

  test("ranks nmap first for 'port scanning' over sqlmap", () => {
    const result = searchToolsInMemory(registry, "port scanning")
    const toolIds = result.results.map((r) => r.tool)
    const nmapIdx = toolIds.indexOf("nmap")
    const sqlmapIdx = toolIds.indexOf("sqlmap")
    // nmap should rank higher (or sqlmap shouldn't appear at all due to penalty)
    if (sqlmapIdx >= 0) {
      expect(nmapIdx).toBeLessThan(sqlmapIdx)
    }
  })

  test("applies phase filter", () => {
    const result = searchToolsInMemory(registry, "scanning", "reconnaissance")
    // nmap has reconnaissance phase, so it should get a phase bonus
    expect(result.results.length).toBeGreaterThan(0)
    // All top results should ideally be recon tools; at minimum nmap should be first
    expect(result.results[0].tool).toBe("nmap")
  })

  test("applies capability filter", () => {
    const result = searchToolsInMemory(registry, "testing", undefined, "sql_injection")
    expect(result.results.length).toBeGreaterThan(0)
    for (const r of result.results) {
      expect(r.capabilities).toContain("sql_injection")
    }
  })

  test("respects limit parameter", () => {
    const result = searchToolsInMemory(registry, "tool", undefined, undefined, 2)
    expect(result.results.length).toBeLessThanOrEqual(2)
  })

  test("returns empty results for completely unrelated query", () => {
    const result = searchToolsInMemory(registry, "quantum teleportation")
    expect(result.results.length).toBe(0)
  })

  test("generates anti-pattern warnings", () => {
    const result = searchToolsInMemory(registry, "port scanning")
    // sqlmap has never_use_for: ["port scanning"]
    expect(result.warnings.length).toBeGreaterThan(0)
    expect(result.warnings.some((w) => w.includes("sqlmap"))).toBe(true)
  })

  test("trigger bonus significantly boosts matching tool", () => {
    // Trigger "nmap" directly matches
    const result = searchToolsInMemory(registry, "nmap scan")
    expect(result.results[0].tool).toBe("nmap")
    expect(result.scoredResults[0].score).toBeGreaterThan(35) // trigger bonus alone is 35
  })

  test("returns scoredResults alongside formatted results", () => {
    const result = searchToolsInMemory(registry, "SQL injection testing")
    expect(result.scoredResults.length).toBeGreaterThan(0)
    expect(result.scoredResults[0]).toHaveProperty("tool")
    expect(result.scoredResults[0]).toHaveProperty("score")
    expect(result.scoredResults[0]).toHaveProperty("description")
  })

  test("results are sorted by score descending", () => {
    const result = searchToolsInMemory(registry, "scanning fuzzing")
    for (let i = 1; i < result.scoredResults.length; i++) {
      expect(result.scoredResults[i].score).toBeLessThanOrEqual(result.scoredResults[i - 1].score)
    }
  })
})

// ---------------------------------------------------------------------------
// 15. scoreAndGroupMethods
// ---------------------------------------------------------------------------

describe("scoreAndGroupMethods", () => {
  const registry = makeRegistry({
    nmap: {
      name: "nmap",
      description: "Network scanner",
      phases: ["reconnaissance"],
      routing: { use_for: ["port scanning"] },
      methods: {
        quick_scan: { description: "Fast TCP scan" },
        full_scan: { description: "Comprehensive scan" },
      },
    },
    ffuf: {
      name: "ffuf",
      description: "Web fuzzer",
      phases: ["enumeration"],
      routing: { use_for: ["directory brute force"] },
      methods: {
        dir_scan: { description: "Directory scan" },
      },
    },
  })

  test("groups methods by tool and selects best method", () => {
    const rows = [
      { tool_id: "nmap", method_name: "quick_scan", method_description: "Fast TCP scan", when_to_use: "", _distance: 0.2 },
      { tool_id: "nmap", method_name: "full_scan", method_description: "Comprehensive scan", when_to_use: "", _distance: 0.5 },
      { tool_id: "ffuf", method_name: "dir_scan", method_description: "Directory scan", when_to_use: "", _distance: 0.3 },
    ]
    const result = scoreAndGroupMethods(rows, registry, "port scan", undefined, undefined, null, [])
    const nmapResult = result.find((t) => t.toolId === "nmap")
    expect(nmapResult).toBeDefined()
    // quick_scan has lower distance (0.2 vs 0.5) so higher similarity
    expect(nmapResult!.suggestedMethod).toBe("quick_scan")
    expect(nmapResult!.rankedMethods).toHaveLength(2)
    expect(nmapResult!.rankedMethods[0].score).toBeGreaterThanOrEqual(nmapResult!.rankedMethods[1].score)
  })

  test("applies phase bonus when phase matches", () => {
    const rows = [
      { tool_id: "nmap", method_name: "quick_scan", method_description: "Fast scan", when_to_use: "", _distance: 0.3 },
      { tool_id: "ffuf", method_name: "dir_scan", method_description: "Dir scan", when_to_use: "", _distance: 0.3 },
    ]
    const withPhase = scoreAndGroupMethods(rows, registry, "scan", "reconnaissance", undefined, null, [])
    const withoutPhase = scoreAndGroupMethods(rows, registry, "scan", undefined, undefined, null, [])

    const nmapWithPhase = withPhase.find((t) => t.toolId === "nmap")
    const nmapWithoutPhase = withoutPhase.find((t) => t.toolId === "nmap")
    expect(nmapWithPhase!.score).toBeGreaterThan(nmapWithoutPhase!.score)
  })

  test("filters by capability", () => {
    const rows = [
      { tool_id: "nmap", method_name: "quick_scan", method_description: "Fast scan", when_to_use: "", _distance: 0.2 },
      { tool_id: "ffuf", method_name: "dir_scan", method_description: "Dir scan", when_to_use: "", _distance: 0.2 },
    ]
    const result = scoreAndGroupMethods(rows, registry, "scan", undefined, "web_fuzzing", null, [])
    // nmap doesn't have web_fuzzing capability, ffuf doesn't either in this fixture
    // Both tools lack the capability in our fixture (we didn't add it)
    // This tests the filter logic itself
    const toolIds = result.map((t) => t.toolId)
    expect(toolIds).not.toContain("nmap") // nmap has no web_fuzzing
  })

  test("computes combined score with sparse when available", () => {
    const rows = [
      {
        tool_id: "nmap",
        method_name: "quick_scan",
        method_description: "Fast scan",
        when_to_use: "",
        _distance: 0.2,
        sparse_json: JSON.stringify({ "100": 0.5, "200": 0.3 }),
      },
    ]
    const querySparse = { "100": 0.8, "200": 0.4, "300": 0.1 }
    const result = scoreAndGroupMethods(rows, registry, "scan", undefined, undefined, querySparse, [])
    const nmap = result.find((t) => t.toolId === "nmap")
    expect(nmap).toBeDefined()
    // With sparse, score should differ from pure dense
    // Dense: 1/(1+0.2) = 0.833
    // Sparse cosine sim of {100:0.5,200:0.3} vs {100:0.8,200:0.4,300:0.1}
    // Combined = dense * 0.6 + sparse * 0.4
    // This test verifies the hybrid combination is used
    const denseOnly = 1 / (1 + 0.2) // ~0.833
    // The combined score should be different from pure dense
    const methodScore = nmap!.rankedMethods[0].score
    expect(methodScore).not.toBeCloseTo(denseOnly, 2)
  })

  test("uses pure dense score when no sparse provided", () => {
    const rows = [
      { tool_id: "nmap", method_name: "quick_scan", method_description: "Fast scan", when_to_use: "", _distance: 0.2 },
    ]
    const result = scoreAndGroupMethods(rows, registry, "scan", undefined, undefined, null, [])
    const nmap = result.find((t) => t.toolId === "nmap")
    const expectedDense = 1 / (1 + 0.2) // ~0.833
    expect(nmap!.rankedMethods[0].score).toBeCloseTo(expectedDense, 3)
  })

  test("handles FTS _score normalization", () => {
    const rows = [
      { tool_id: "nmap", method_name: "quick_scan", method_description: "Scan", when_to_use: "", _score: 10 },
    ]
    const result = scoreAndGroupMethods(rows, registry, "scan", undefined, undefined, null, [])
    const nmap = result.find((t) => t.toolId === "nmap")
    expect(nmap).toBeDefined()
    // _score / 20 = 0.5
    expect(nmap!.rankedMethods[0].score).toBeCloseTo(0.5, 3)
  })

  test("caps FTS score normalization at 1.0", () => {
    const rows = [
      { tool_id: "nmap", method_name: "quick_scan", method_description: "Scan", when_to_use: "", _score: 50 },
    ]
    const result = scoreAndGroupMethods(rows, registry, "scan", undefined, undefined, null, [])
    const nmap = result.find((t) => t.toolId === "nmap")
    // Math.min(50/20, 1) = 1.0
    expect(nmap!.rankedMethods[0].score).toBeCloseTo(1.0, 3)
  })

  test("uses 0.05 default when neither _distance nor _score present", () => {
    const rows = [
      { tool_id: "nmap", method_name: "quick_scan", method_description: "Scan", when_to_use: "" },
    ]
    const result = scoreAndGroupMethods(rows, registry, "scan", undefined, undefined, null, [])
    const nmap = result.find((t) => t.toolId === "nmap")
    expect(nmap!.rankedMethods[0].score).toBeCloseTo(0.05, 3)
  })

  test("excludes tools with score <= 0", () => {
    // A tool that only gets a heavy penalty with no positive score
    const regWithPenalty = makeRegistry({
      badtool: {
        name: "badtool",
        description: "A tool",
        routing: { never_use_for: ["scanning"] },
      },
    })
    const rows = [
      { tool_id: "badtool", method_name: "default", method_description: "Tool", when_to_use: "" },
    ]
    // Score will be 0.05 (default) + negative routing. If penalty is large enough, filtered out
    const result = scoreAndGroupMethods(rows, regWithPenalty, "scanning", undefined, undefined, null, [])
    // The penalty is normalized: (neverUseForPenalty / 15 * 0.2) = (-15/15)*0.2 = -0.2
    // Total = 0.05 + (-0.2) = -0.15 → filtered out
    expect(result.length).toBe(0)
  })

  test("collects anti-pattern warnings", () => {
    const warnings: string[] = []
    const rows = [
      { tool_id: "nmap", method_name: "quick_scan", method_description: "Scan", when_to_use: "", _distance: 0.2 },
    ]
    const regWithAntiPattern = makeRegistry({
      nmap: {
        name: "nmap",
        description: "Scanner",
        routing: { never_use_for: ["fuzzing"] },
      },
    })
    scoreAndGroupMethods(rows, regWithAntiPattern, "fuzzing", undefined, undefined, null, warnings)
    expect(warnings.length).toBeGreaterThan(0)
    expect(warnings[0]).toContain("nmap")
    expect(warnings[0]).toContain("fuzzing")
  })

  test("skips rows for tools not in registry", () => {
    const rows = [
      { tool_id: "ghost-tool", method_name: "method", method_description: "Desc", when_to_use: "", _distance: 0.1 },
    ]
    const result = scoreAndGroupMethods(rows, registry, "scan", undefined, undefined, null, [])
    expect(result.length).toBe(0)
  })

  test("falls back to row.id when tool_id is missing (legacy)", () => {
    const rows = [
      { id: "nmap", method_name: "quick_scan", method_description: "Scan", when_to_use: "", _distance: 0.2 },
    ]
    const result = scoreAndGroupMethods(rows, registry, "scan", undefined, undefined, null, [])
    expect(result.find((t) => t.toolId === "nmap")).toBeDefined()
  })

  test("falls back to 'default' when method_name is missing", () => {
    const rows = [
      { tool_id: "nmap", method_description: "Scan", when_to_use: "", _distance: 0.2 },
    ]
    const result = scoreAndGroupMethods(rows, registry, "scan", undefined, undefined, null, [])
    const nmap = result.find((t) => t.toolId === "nmap")
    expect(nmap!.suggestedMethod).toBe("default")
  })
})

// ---------------------------------------------------------------------------
// 16. mergeSessionRecipes (dynamic recipe system)
// ---------------------------------------------------------------------------

describe("mergeSessionRecipes", () => {
  const testSessionID = `test-recipe-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`

  afterEach(() => {
    SessionDirectory.cleanup(testSessionID)
    unregister(testSessionID)
  })

  test("does nothing when session directory does not exist", () => {
    const registry = makeRegistry({
      nmap: { name: "nmap", description: "Scanner" },
    })
    // Should not throw
    mergeSessionRecipes(registry, testSessionID)
    expect(Object.keys(registry.tools.nmap.methods ?? {})).toHaveLength(0)
  })

  test("does nothing when tool_recipes directory does not exist", () => {
    registerRootSession(testSessionID, testSessionID)
    SessionDirectory.create(testSessionID)
    const registry = makeRegistry({
      nmap: { name: "nmap", description: "Scanner" },
    })
    mergeSessionRecipes(registry, testSessionID)
    expect(Object.keys(registry.tools.nmap.methods ?? {})).toHaveLength(0)
  })

  test("merges YAML recipe into existing tool", () => {
    registerRootSession(testSessionID, testSessionID)
    SessionDirectory.create(testSessionID)
    const sessionDir = SessionDirectory.get(testSessionID)
    const recipesDir = join(sessionDir, "tool_recipes", "nmap")
    mkdirSync(recipesDir, { recursive: true })

    const recipe = {
      name: "custom_scan",
      description: "Custom scan recipe",
      when_to_use: "When you need a custom scan",
      params: {
        target: { type: "string", description: "Target IP" },
        ports: { type: "string", description: "Port range" },
      },
    }
    writeFileSync(join(recipesDir, "custom_scan.yaml"), yaml.dump(recipe))

    const registry = makeRegistry({
      nmap: { name: "nmap", description: "Scanner" },
    })
    mergeSessionRecipes(registry, testSessionID)
    expect(registry.tools.nmap.methods).toBeDefined()
    expect(registry.tools.nmap.methods!.custom_scan).toBeDefined()
    expect(registry.tools.nmap.methods!.custom_scan.description).toBe("Custom scan recipe")
    expect(registry.tools.nmap.methods!.custom_scan.when_to_use).toBe("When you need a custom scan")
    expect(registry.tools.nmap.methods!.custom_scan.params?.target.type).toBe("string")
  })

  test("does not override existing methods from published registry", () => {
    registerRootSession(testSessionID, testSessionID)
    SessionDirectory.create(testSessionID)
    const sessionDir = SessionDirectory.get(testSessionID)
    const recipesDir = join(sessionDir, "tool_recipes", "nmap")
    mkdirSync(recipesDir, { recursive: true })

    const recipe = { name: "quick_scan", description: "Overridden!" }
    writeFileSync(join(recipesDir, "quick_scan.yaml"), yaml.dump(recipe))

    const registry = makeRegistry({
      nmap: {
        name: "nmap",
        description: "Scanner",
        methods: { quick_scan: { description: "Original quick scan" } },
      },
    })
    mergeSessionRecipes(registry, testSessionID)
    expect(registry.tools.nmap.methods!.quick_scan.description).toBe("Original quick scan")
  })

  test("ignores recipes for tools not in the registry", () => {
    registerRootSession(testSessionID, testSessionID)
    SessionDirectory.create(testSessionID)
    const sessionDir = SessionDirectory.get(testSessionID)
    const recipesDir = join(sessionDir, "tool_recipes", "nonexistent-tool")
    mkdirSync(recipesDir, { recursive: true })

    const recipe = { name: "method", description: "Ghost method" }
    writeFileSync(join(recipesDir, "method.yaml"), yaml.dump(recipe))

    const registry = makeRegistry({
      nmap: { name: "nmap", description: "Scanner" },
    })
    mergeSessionRecipes(registry, testSessionID)
    expect(registry.tools["nonexistent-tool"]).toBeUndefined()
  })

  test("ignores non-YAML files", () => {
    registerRootSession(testSessionID, testSessionID)
    SessionDirectory.create(testSessionID)
    const sessionDir = SessionDirectory.get(testSessionID)
    const recipesDir = join(sessionDir, "tool_recipes", "nmap")
    mkdirSync(recipesDir, { recursive: true })

    writeFileSync(join(recipesDir, "readme.md"), "# Not a recipe")
    writeFileSync(join(recipesDir, "notes.txt"), "Just notes")

    const registry = makeRegistry({
      nmap: { name: "nmap", description: "Scanner" },
    })
    mergeSessionRecipes(registry, testSessionID)
    expect(Object.keys(registry.tools.nmap.methods ?? {})).toHaveLength(0)
  })

  test("skips malformed YAML files gracefully", () => {
    registerRootSession(testSessionID, testSessionID)
    SessionDirectory.create(testSessionID)
    const sessionDir = SessionDirectory.get(testSessionID)
    const recipesDir = join(sessionDir, "tool_recipes", "nmap")
    mkdirSync(recipesDir, { recursive: true })

    writeFileSync(join(recipesDir, "bad.yaml"), ": : : this is not valid yaml [[[")

    const registry = makeRegistry({
      nmap: { name: "nmap", description: "Scanner" },
    })
    // Should not throw
    mergeSessionRecipes(registry, testSessionID)
  })

  test("skips recipe files without name field", () => {
    registerRootSession(testSessionID, testSessionID)
    SessionDirectory.create(testSessionID)
    const sessionDir = SessionDirectory.get(testSessionID)
    const recipesDir = join(sessionDir, "tool_recipes", "nmap")
    mkdirSync(recipesDir, { recursive: true })

    writeFileSync(join(recipesDir, "noname.yaml"), yaml.dump({ description: "No name" }))

    const registry = makeRegistry({
      nmap: { name: "nmap", description: "Scanner" },
    })
    mergeSessionRecipes(registry, testSessionID)
    expect(Object.keys(registry.tools.nmap.methods ?? {})).toHaveLength(0)
  })

  test("merges .yml extension in addition to .yaml", () => {
    registerRootSession(testSessionID, testSessionID)
    SessionDirectory.create(testSessionID)
    const sessionDir = SessionDirectory.get(testSessionID)
    const recipesDir = join(sessionDir, "tool_recipes", "nmap")
    mkdirSync(recipesDir, { recursive: true })

    const recipe = { name: "yml_method", description: "Method from .yml" }
    writeFileSync(join(recipesDir, "yml_method.yml"), yaml.dump(recipe))

    const registry = makeRegistry({
      nmap: { name: "nmap", description: "Scanner" },
    })
    mergeSessionRecipes(registry, testSessionID)
    expect(registry.tools.nmap.methods!.yml_method).toBeDefined()
  })

  test("merges multiple recipes from multiple tools", () => {
    registerRootSession(testSessionID, testSessionID)
    SessionDirectory.create(testSessionID)
    const sessionDir = SessionDirectory.get(testSessionID)

    const nmapDir = join(sessionDir, "tool_recipes", "nmap")
    const ffufDir = join(sessionDir, "tool_recipes", "ffuf")
    mkdirSync(nmapDir, { recursive: true })
    mkdirSync(ffufDir, { recursive: true })

    writeFileSync(join(nmapDir, "recipe1.yaml"), yaml.dump({ name: "r1", description: "R1" }))
    writeFileSync(join(nmapDir, "recipe2.yaml"), yaml.dump({ name: "r2", description: "R2" }))
    writeFileSync(join(ffufDir, "recipe3.yaml"), yaml.dump({ name: "r3", description: "R3" }))

    const registry = makeRegistry({
      nmap: { name: "nmap", description: "Scanner" },
      ffuf: { name: "ffuf", description: "Fuzzer" },
    })
    mergeSessionRecipes(registry, testSessionID)
    expect(Object.keys(registry.tools.nmap.methods!)).toHaveLength(2)
    expect(Object.keys(registry.tools.ffuf.methods!)).toHaveLength(1)
  })
})

// ---------------------------------------------------------------------------
// 17. Dense + Sparse Scoring Weights (REQ-FUN-036-D verification)
// ---------------------------------------------------------------------------

describe("scoring weights: dense * 0.6 + sparse * 0.4", () => {
  const registry = makeRegistry({
    nmap: {
      name: "nmap",
      description: "Scanner",
      methods: { scan: { description: "Scan" } },
    },
  })

  test("combined score follows dense * 0.6 + sparse * 0.4 formula", () => {
    // Use known sparse vectors for deterministic calculation
    const docSparse = { "100": 1.0, "200": 1.0 }
    const querySparse = { "100": 1.0, "200": 1.0 }
    // Sparse cosine similarity of identical vectors = 1.0

    const rows = [
      {
        tool_id: "nmap",
        method_name: "scan",
        method_description: "Scan",
        when_to_use: "",
        _distance: 0.0, // Perfect match → dense = 1/(1+0) = 1.0
        sparse_json: JSON.stringify(docSparse),
      },
    ]
    const result = scoreAndGroupMethods(rows, registry, "scan", undefined, undefined, querySparse, [])
    const nmap = result.find((t) => t.toolId === "nmap")
    // Combined = 1.0 * 0.6 + 1.0 * 0.4 = 1.0
    expect(nmap!.rankedMethods[0].score).toBeCloseTo(1.0, 3)
  })

  test("sparse-only match is weighted at 0.4", () => {
    // Dense is terrible, sparse is perfect
    const docSparse = { "100": 1.0 }
    const querySparse = { "100": 1.0 }

    const rows = [
      {
        tool_id: "nmap",
        method_name: "scan",
        method_description: "Scan",
        when_to_use: "",
        _distance: 100.0, // Very bad → dense = 1/(1+100) ≈ 0.0099
        sparse_json: JSON.stringify(docSparse),
      },
    ]
    const result = scoreAndGroupMethods(rows, registry, "scan", undefined, undefined, querySparse, [])
    const nmap = result.find((t) => t.toolId === "nmap")
    const denseComponent = (1 / 101) * 0.6
    const sparseComponent = 1.0 * 0.4
    expect(nmap!.rankedMethods[0].score).toBeCloseTo(denseComponent + sparseComponent, 3)
  })

  test("dense-only match is weighted at 0.6 when sparse is zero", () => {
    // No overlap in sparse vectors → sparse sim = 0
    const docSparse = { "100": 1.0 }
    const querySparse = { "999": 1.0 }

    const rows = [
      {
        tool_id: "nmap",
        method_name: "scan",
        method_description: "Scan",
        when_to_use: "",
        _distance: 0.0, // Perfect dense match
        sparse_json: JSON.stringify(docSparse),
      },
    ]
    const result = scoreAndGroupMethods(rows, registry, "scan", undefined, undefined, querySparse, [])
    const nmap = result.find((t) => t.toolId === "nmap")
    // Combined = 1.0 * 0.6 + 0.0 * 0.4 = 0.6
    expect(nmap!.rankedMethods[0].score).toBeCloseTo(0.6, 3)
  })
})

// ---------------------------------------------------------------------------
// 18. Phase Matching (REQ-FUN-036-D phase component)
// ---------------------------------------------------------------------------

describe("phase matching in scoring", () => {
  const registry = makeRegistry({
    nmap: {
      name: "nmap",
      description: "Network scanner",
      phases: ["reconnaissance", "enumeration"],
    },
    sqlmap: {
      name: "sqlmap",
      description: "SQL injection",
      phases: ["exploitation"],
    },
  })

  test("phase bonus is 0.15 for matching phase", () => {
    const rowsNmap = [
      { tool_id: "nmap", method_name: "scan", method_description: "Scan", when_to_use: "", _distance: 0.3 },
    ]
    const withPhase = scoreAndGroupMethods(rowsNmap, registry, "scan", "reconnaissance", undefined, null, [])
    const withoutPhase = scoreAndGroupMethods(rowsNmap, registry, "scan", undefined, undefined, null, [])

    const diff = withPhase[0].score - withoutPhase[0].score
    expect(diff).toBeCloseTo(0.15, 2)
  })

  test("no phase bonus for non-matching phase", () => {
    const rows = [
      { tool_id: "nmap", method_name: "scan", method_description: "Scan", when_to_use: "", _distance: 0.3 },
    ]
    const withPostPhase = scoreAndGroupMethods(rows, registry, "scan", "post-exploitation", undefined, null, [])
    const withoutPhase = scoreAndGroupMethods(rows, registry, "scan", undefined, undefined, null, [])

    expect(withPostPhase[0].score).toBeCloseTo(withoutPhase[0].score, 5)
  })
})

// ---------------------------------------------------------------------------
// 19. Routing Normalization (normalized to [0,1], capped at 0.5)
// ---------------------------------------------------------------------------

describe("routing bonus normalization", () => {
  test("trigger bonus normalized to max ~0.3 (35/35 * 0.3)", () => {
    const registry = makeRegistry({
      nmap: {
        name: "nmap",
        description: "Scanner",
        routing: { triggers: ["nmap"] },
      },
    })
    const rows = [
      { tool_id: "nmap", method_name: "scan", method_description: "Scan", when_to_use: "", _distance: 1000 },
    ]
    const result = scoreAndGroupMethods(rows, registry, "nmap", undefined, undefined, null, [])
    const nmap = result.find((t) => t.toolId === "nmap")
    // Dense score ≈ 0 (distance huge), routing = trigger 35/35*0.3 = 0.3
    // Total ≈ 0.001 + 0.3 ≈ 0.301
    expect(nmap!.score).toBeLessThan(0.5)
    expect(nmap!.score).toBeGreaterThan(0.2)
  })

  test("total routing bonus capped at 0.5", () => {
    // Multiple strong bonuses should still be capped
    const registry = makeRegistry({
      supertool: {
        name: "supertool",
        description: "The super tool does scanning and port scanning",
        phases: ["reconnaissance"],
        routing: {
          triggers: ["super", "tool"],
          use_for: ["scanning", "port scanning"],
        },
      },
    })
    const rows = [
      { tool_id: "supertool", method_name: "default", method_description: "Do stuff", when_to_use: "", _distance: 1000 },
    ]
    const result = scoreAndGroupMethods(rows, registry, "super tool scanning port scanning", "reconnaissance", undefined, null, [])
    const st = result.find((t) => t.toolId === "supertool")
    // Dense ≈ 0, all routing maxed → capped at 0.5
    // Score should be dense + min(routing, 0.5) ≤ 0.5 + epsilon
    expect(st!.score).toBeLessThanOrEqual(0.5 + 0.01)
  })
})

// ---------------------------------------------------------------------------
// 20. REQ-FUN-038: Tool Registry Search is ONLY mechanism
// ---------------------------------------------------------------------------

describe("REQ-FUN-038: tool discovery is only through registry search", () => {
  test("tool description file declares it as the ONLY mechanism", () => {
    // This test validates the contract documented in the tool description
    // The actual enforcement is architectural (agents have no hardcoded tool lists)
    // but we verify the description states the exclusivity requirement
    const tool = createToolRegistrySearchTool()
    expect(tool.description).toContain("ONLY mechanism")
  })
})

// ---------------------------------------------------------------------------
// 21. REQ-FUN-036: RAG-based tool callable by any agent
// ---------------------------------------------------------------------------

describe("REQ-FUN-036: tool is a proper tool definition", () => {
  test("createToolRegistrySearchTool returns a tool with required fields", () => {
    const tool = createToolRegistrySearchTool()
    expect(tool).toBeDefined()
    expect(tool.description).toBeDefined()
    expect(tool.description.length).toBeGreaterThan(0)
    expect(tool.args).toBeDefined()
    expect(tool.execute).toBeDefined()
    expect(typeof tool.execute).toBe("function")
  })

  test("tool accepts query, phase, capability, limit, explain parameters", () => {
    const tool = createToolRegistrySearchTool()
    const argKeys = Object.keys(tool.args)
    expect(argKeys).toContain("query")
    expect(argKeys).toContain("phase")
    expect(argKeys).toContain("capability")
    expect(argKeys).toContain("limit")
    expect(argKeys).toContain("explain")
  })
})

// ---------------------------------------------------------------------------
// 22. REQ-FUN-036-B: selection_level verified through registry structure
// ---------------------------------------------------------------------------

describe("REQ-FUN-036-B: selection_level in registry schema", () => {
  test("RegistryToolSchema accepts selection_level via passthrough", () => {
    // The schema uses .passthrough() so extra fields like selection_level are allowed
    const tool = RegistryToolSchema.parse({
      name: "nmap",
      description: "Scanner",
      selection_level: 2,
    })
    expect((tool as any).selection_level).toBe(2)
  })

  test("selection_level values 1 (Skill), 2 (Specialized), 3 (General) all valid", () => {
    for (const level of [1, 2, 3]) {
      const tool = RegistryToolSchema.parse({
        name: `tool-${level}`,
        description: `Level ${level} tool`,
        selection_level: level,
      })
      expect((tool as any).selection_level).toBe(level)
    }
  })
})

// ---------------------------------------------------------------------------
// 23. Integration: searchToolsInMemory round-trip
// ---------------------------------------------------------------------------

describe("searchToolsInMemory integration", () => {
  test("SQL injection query ranks sqlmap above unrelated tools", () => {
    const registry = makeRegistry({
      sqlmap: {
        name: "sqlmap",
        description: "Automatic SQL injection and database takeover tool",
        capabilities: ["sql_injection"],
        phases: ["exploitation"],
        routing: {
          use_for: ["SQL injection testing", "database extraction"],
          triggers: ["sql.*inject"],
        },
      },
      nmap: {
        name: "nmap",
        description: "Network mapper and port scanner",
        capabilities: ["port_scanning"],
        phases: ["reconnaissance"],
        routing: { use_for: ["port scanning"] },
      },
      hydra: {
        name: "hydra",
        description: "Password brute force tool",
        capabilities: ["password_cracking"],
        phases: ["exploitation"],
      },
    })

    const result = searchToolsInMemory(registry, "SQL injection testing")
    expect(result.results[0].tool).toBe("sqlmap")
  })

  test("password brute force query finds hydra", () => {
    const registry = makeRegistry({
      hydra: {
        name: "hydra",
        description: "Network login cracker supporting many protocols for password brute force",
        capabilities: ["password_cracking", "brute_force"],
        phases: ["exploitation"],
        routing: { use_for: ["password brute force", "login cracking"] },
      },
      nmap: {
        name: "nmap",
        description: "Network mapper",
        routing: { use_for: ["port scanning"] },
      },
    })

    const result = searchToolsInMemory(registry, "brute force password")
    expect(result.results[0].tool).toBe("hydra")
  })

  test("in-memory search respects never_use_for warnings in formatted output", () => {
    const registry = makeRegistry({
      curl: {
        name: "curl",
        description: "HTTP client",
        routing: {
          use_for: ["HTTP requests"],
          never_use_for: [
            { task: "web scraping", use_instead: "playwright-mcp", reason: "curl returns empty for JS pages" },
          ],
        },
      },
    })

    const result = searchToolsInMemory(registry, "web scraping")
    expect(result.warnings.length).toBeGreaterThan(0)
    expect(result.warnings[0]).toContain("playwright-mcp")
  })
})

// ---------------------------------------------------------------------------
// Infrastructure-dependent tests (documented only)
// ---------------------------------------------------------------------------

describe.skip("requires real infrastructure (documented)", () => {
  test("LanceDB vector search (ANN queries) — requires running LanceDB", () => {})
  test("remote registry fetch from opensploit.ai — requires network", () => {})
  test("embedding generation (BGE-M3) — requires embedding service", () => {})
  test("hash-based freshness check — requires remote hash endpoint", () => {})
  test("downloadAndImportLance — requires remote .lance archive", () => {})
  test("unified search with experiences and insights — requires populated LanceDB", () => {})
})
