import { describe, test, expect, mock, beforeEach } from "bun:test"
import type { ToolContext } from "@opencode-ai/plugin"
import type { PatternSearchResult, PatternQuery } from "../../src/pattern/search"
import type { CaptureResult } from "../../src/pattern/capture"

/**
 * Behavioral tests for pattern_search and save_pattern tools.
 *
 * Both tools depend on LanceDB + an embedding Docker container that won't be
 * running in CI or local test environments. We mock the backend functions
 * (searchPatterns, formatPatternResults, capturePattern) and test the tool
 * layer itself: output formatting, metadata emissions, error paths, and
 * parameter handling.
 *
 * Mocked backends:
 *   - searchPatterns  → returns controlled PatternSearchResult[]
 *   - formatPatternResults → returns controlled markdown strings
 *   - capturePattern → returns controlled CaptureResult
 *
 * What we verify through execute():
 *   - pattern_search: cold-start path, results path, metadata emissions
 *   - save_pattern: success path, duplicate path, failure path, metadata
 *   - Both: parameter forwarding, no crashes on edge inputs
 */

// =============================================================================
// Cold-start result (mirrors COLD_START_RESULT from search.ts)
// =============================================================================

const COLD_START: PatternSearchResult = {
  similarity: 0,
  pattern_id: "",
  summary: "No similar patterns found yet. This will improve as you complete more engagements.",
  vulnerability_type: "",
  tools_sequence: [],
  access_achieved: "none",
  time_to_access: 0,
  key_insights: [
    "Consider starting with standard methodology for this target profile.",
    "Run reconnaissance to identify services and technologies.",
    "Check for common vulnerabilities based on discovered services.",
  ],
  phases: [],
}

const REAL_RESULT: PatternSearchResult = {
  similarity: 0.87,
  pattern_id: "pat-abc123",
  summary: "SQL injection in login form -> DB creds -> SSH",
  vulnerability_type: "sqli",
  cve: "CVE-2024-1234",
  tools_sequence: ["nmap", "ffuf", "sqlmap", "ssh"],
  access_achieved: "root",
  time_to_access: 45,
  key_insights: [
    "Login form was vulnerable to time-based blind SQLi",
    "Database contained plaintext SSH credentials",
  ],
  phases: [
    { phase: "enumeration", tool: "ffuf", action: "Fuzzed web directories", result: "Found /admin login page", pivotal: true },
    { phase: "exploitation", tool: "sqlmap", action: "Exploited SQLi in login", result: "Extracted DB credentials", pivotal: true },
  ],
}

const SECOND_RESULT: PatternSearchResult = {
  similarity: 0.72,
  pattern_id: "pat-def456",
  summary: "LFI to RCE via log poisoning",
  vulnerability_type: "lfi",
  tools_sequence: ["nmap", "ffuf", "curl"],
  access_achieved: "user",
  time_to_access: 30,
  key_insights: ["Apache access log was includable via LFI"],
  phases: [],
}

// =============================================================================
// Mocks - declared BEFORE tool imports so mock.module takes effect
// =============================================================================

const mockSearchPatterns = mock<(query: PatternQuery) => Promise<PatternSearchResult[]>>()
const mockFormatPatternResults = mock<(results: PatternSearchResult[], query: PatternQuery) => string>()
const mockCapturePattern = mock<(sessionID: string, options: any) => Promise<CaptureResult>>()

mock.module("../../src/pattern", () => ({
  searchPatterns: mockSearchPatterns,
  formatPatternResults: mockFormatPatternResults,
}))

mock.module("../../src/pattern/capture", () => ({
  capturePattern: mockCapturePattern,
}))

// Now import the tools -- they will receive the mocked functions
const { createPatternSearchTool } = await import("../../src/tools/pattern-search")
const { createSavePatternTool } = await import("../../src/tools/save-pattern")

const patternSearchTool = createPatternSearchTool()
const savePatternTool = createSavePatternTool()

// =============================================================================
// Helpers
// =============================================================================

/** Build a minimal ToolContext that captures metadata calls. */
function makeContext(sessionId = "test-pattern-session") {
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

// =============================================================================
// pattern_search
// =============================================================================

describe("tool.pattern_search", () => {
  beforeEach(() => {
    mockSearchPatterns.mockReset()
    mockFormatPatternResults.mockReset()
  })

  // ---------------------------------------------------------------------------
  // Cold-start path (no patterns in database)
  // ---------------------------------------------------------------------------

  describe("cold-start path", () => {
    beforeEach(() => {
      mockSearchPatterns.mockResolvedValue([COLD_START])
      mockFormatPatternResults.mockReturnValue(
        "# Attack Pattern Search Results\n\n## No Matching Patterns Yet\n\nNo similar patterns found yet."
      )
    })

    test("returns the formatted output from formatPatternResults", async () => {
      const { ctx } = makeContext()
      const result = await patternSearchTool.execute(
        { target_profile: { services: ["http"] }, objective: "initial_access" },
        ctx,
      )

      expect(result).toContain("Attack Pattern Search Results")
      expect(result).toContain("No Matching Patterns Yet")
    })

    test("metadata title indicates no patterns", async () => {
      const { ctx, metadataCalls } = makeContext()
      await patternSearchTool.execute(
        { target_profile: { services: ["http"] }, objective: "initial_access" },
        ctx,
      )

      expect(metadataCalls).toHaveLength(1)
      expect(metadataCalls[0].title).toContain("no patterns")
    })

    test("metadata has cold_start=true", async () => {
      const { ctx, metadataCalls } = makeContext()
      await patternSearchTool.execute(
        { target_profile: { services: ["http"] }, objective: "initial_access" },
        ctx,
      )

      expect(metadataCalls[0].metadata?.cold_start).toBe(true)
    })

    test("metadata has results_count=0", async () => {
      const { ctx, metadataCalls } = makeContext()
      await patternSearchTool.execute(
        { target_profile: { services: ["http"] }, objective: "initial_access" },
        ctx,
      )

      expect(metadataCalls[0].metadata?.results_count).toBe(0)
    })

    test("metadata has top_similarity=0", async () => {
      const { ctx, metadataCalls } = makeContext()
      await patternSearchTool.execute(
        { target_profile: { services: ["http"] }, objective: "initial_access" },
        ctx,
      )

      expect(metadataCalls[0].metadata?.top_similarity).toBe(0)
    })
  })

  // ---------------------------------------------------------------------------
  // Results found path
  // ---------------------------------------------------------------------------

  describe("results found path", () => {
    beforeEach(() => {
      mockSearchPatterns.mockResolvedValue([REAL_RESULT, SECOND_RESULT])
      mockFormatPatternResults.mockReturnValue(
        "# Attack Pattern Search Results\n\n## Pattern 1\n\nSQL injection in login form"
      )
    })

    test("returns formatted output", async () => {
      const { ctx } = makeContext()
      const result = await patternSearchTool.execute(
        { target_profile: { os: "linux", services: ["http", "ssh"] }, objective: "initial_access" },
        ctx,
      )

      expect(result).toContain("Pattern 1")
      expect(result).toContain("SQL injection")
    })

    test("metadata title shows result count", async () => {
      const { ctx, metadataCalls } = makeContext()
      await patternSearchTool.execute(
        { target_profile: { os: "linux", services: ["http", "ssh"] }, objective: "initial_access" },
        ctx,
      )

      expect(metadataCalls[0].title).toContain("2 pattern(s) found")
    })

    test("metadata has cold_start=false", async () => {
      const { ctx, metadataCalls } = makeContext()
      await patternSearchTool.execute(
        { target_profile: { services: ["http"] }, objective: "initial_access" },
        ctx,
      )

      expect(metadataCalls[0].metadata?.cold_start).toBe(false)
    })

    test("metadata results_count matches actual count", async () => {
      const { ctx, metadataCalls } = makeContext()
      await patternSearchTool.execute(
        { target_profile: { services: ["http"] }, objective: "initial_access" },
        ctx,
      )

      expect(metadataCalls[0].metadata?.results_count).toBe(2)
    })

    test("metadata top_similarity comes from first result", async () => {
      const { ctx, metadataCalls } = makeContext()
      await patternSearchTool.execute(
        { target_profile: { services: ["http"] }, objective: "initial_access" },
        ctx,
      )

      expect(metadataCalls[0].metadata?.top_similarity).toBe(0.87)
    })
  })

  // ---------------------------------------------------------------------------
  // Parameter forwarding to searchPatterns
  // ---------------------------------------------------------------------------

  describe("parameter forwarding", () => {
    beforeEach(() => {
      mockSearchPatterns.mockResolvedValue([COLD_START])
      mockFormatPatternResults.mockReturnValue("formatted")
    })

    test("forwards OS to searchPatterns query", async () => {
      const { ctx } = makeContext()
      await patternSearchTool.execute(
        { target_profile: { os: "windows", services: ["smb"] }, objective: "initial_access" },
        ctx,
      )

      expect(mockSearchPatterns).toHaveBeenCalledTimes(1)
      const query = mockSearchPatterns.mock.calls[0][0] as PatternQuery
      expect(query.target_profile.os).toBe("windows")
    })

    test("forwards services array to searchPatterns query", async () => {
      const { ctx } = makeContext()
      await patternSearchTool.execute(
        { target_profile: { services: ["http", "ssh", "smb"] }, objective: "initial_access" },
        ctx,
      )

      const query = mockSearchPatterns.mock.calls[0][0] as PatternQuery
      expect(query.target_profile.services).toEqual(["http", "ssh", "smb"])
    })

    test("forwards technologies to searchPatterns query", async () => {
      const { ctx } = makeContext()
      await patternSearchTool.execute(
        {
          target_profile: { services: ["http"], technologies: ["wordpress", "php"] },
          objective: "initial_access",
        },
        ctx,
      )

      const query = mockSearchPatterns.mock.calls[0][0] as PatternQuery
      expect(query.target_profile.technologies).toEqual(["wordpress", "php"])
    })

    test("forwards characteristics to searchPatterns query", async () => {
      const { ctx } = makeContext()
      await patternSearchTool.execute(
        {
          target_profile: { services: ["http"], characteristics: ["login_form", "file_upload"] },
          objective: "initial_access",
        },
        ctx,
      )

      const query = mockSearchPatterns.mock.calls[0][0] as PatternQuery
      expect(query.target_profile.characteristics).toEqual(["login_form", "file_upload"])
    })

    test("forwards objective to searchPatterns query", async () => {
      const { ctx } = makeContext()
      await patternSearchTool.execute(
        { target_profile: { services: ["http"] }, objective: "privilege_escalation" },
        ctx,
      )

      const query = mockSearchPatterns.mock.calls[0][0] as PatternQuery
      expect(query.objective).toBe("privilege_escalation")
    })

    test("forwards custom limit to searchPatterns query", async () => {
      const { ctx } = makeContext()
      await patternSearchTool.execute(
        { target_profile: { services: ["http"] }, objective: "initial_access", limit: 3 },
        ctx,
      )

      const query = mockSearchPatterns.mock.calls[0][0] as PatternQuery
      expect(query.limit).toBe(3)
    })

    test("uses default limit=5 when omitted", async () => {
      const { ctx } = makeContext()
      await patternSearchTool.execute(
        { target_profile: { services: ["http"] }, objective: "initial_access" },
        ctx,
      )

      const query = mockSearchPatterns.mock.calls[0][0] as PatternQuery
      expect(query.limit).toBe(5)
    })

    test("passes results and query to formatPatternResults", async () => {
      const { ctx } = makeContext()
      await patternSearchTool.execute(
        { target_profile: { services: ["http"] }, objective: "initial_access" },
        ctx,
      )

      expect(mockFormatPatternResults).toHaveBeenCalledTimes(1)
      const [results, query] = mockFormatPatternResults.mock.calls[0]
      expect(results).toEqual([COLD_START])
      expect(query.objective).toBe("initial_access")
    })
  })

  // ---------------------------------------------------------------------------
  // Metadata emissions — always exactly one
  // ---------------------------------------------------------------------------

  describe("metadata emissions", () => {
    beforeEach(() => {
      mockSearchPatterns.mockResolvedValue([REAL_RESULT])
      mockFormatPatternResults.mockReturnValue("formatted")
    })

    test("emits exactly one metadata call", async () => {
      const { ctx, metadataCalls } = makeContext()
      await patternSearchTool.execute(
        { target_profile: { services: ["http"] }, objective: "initial_access" },
        ctx,
      )

      expect(metadataCalls).toHaveLength(1)
    })

    test("metadata query includes os, services, and objective", async () => {
      const { ctx, metadataCalls } = makeContext()
      await patternSearchTool.execute(
        {
          target_profile: { os: "linux", services: ["http", "ssh"] },
          objective: "lateral_movement",
        },
        ctx,
      )

      const queryMeta = metadataCalls[0].metadata?.query
      expect(queryMeta.os).toBe("linux")
      expect(queryMeta.services).toEqual(["http", "ssh"])
      expect(queryMeta.objective).toBe("lateral_movement")
    })
  })

  // ---------------------------------------------------------------------------
  // Edge cases
  // ---------------------------------------------------------------------------

  describe("edge cases", () => {
    beforeEach(() => {
      mockSearchPatterns.mockResolvedValue([COLD_START])
      mockFormatPatternResults.mockReturnValue("formatted")
    })

    test("empty services array does not crash", async () => {
      const { ctx } = makeContext()
      const result = await patternSearchTool.execute(
        { target_profile: { services: [] }, objective: "initial_access" },
        ctx,
      )

      expect(typeof result).toBe("string")
    })

    test("all optional fields populated does not crash", async () => {
      const { ctx } = makeContext()
      const result = await patternSearchTool.execute(
        {
          target_profile: {
            os: "windows",
            services: ["smb", "rdp", "http", "winrm"],
            technologies: ["iis", "asp.net", "mssql"],
            characteristics: ["login_form", "api_endpoint"],
          },
          objective: "privilege_escalation",
          limit: 10,
        },
        ctx,
      )

      expect(typeof result).toBe("string")
    })
  })
})

// =============================================================================
// save_pattern
// =============================================================================

describe("tool.save_pattern", () => {
  beforeEach(() => {
    mockCapturePattern.mockReset()
  })

  // ---------------------------------------------------------------------------
  // Success path
  // ---------------------------------------------------------------------------

  describe("success path", () => {
    const successResult: CaptureResult = {
      success: true,
      message: "Pattern captured: SQL injection in login form -> DB creds -> SSH",
      pattern: {
        id: "pat-new-001",
        target_profile: {
          os: "linux",
          services: ["http", "ssh"],
          ports: [80, 22],
          technologies: ["apache", "wordpress"],
          characteristics: ["login_form"],
        },
        vulnerability: {
          type: "sqli",
          description: "Time-based blind SQL injection in login form",
          cve: "CVE-2024-1234",
          cvss: 9.8,
        },
        methodology: {
          summary: "SQL injection in login form -> DB creds -> SSH",
          phases: [],
          tools_sequence: ["nmap", "ffuf", "sqlmap", "ssh"],
          key_insights: ["Login form vulnerable to time-based blind SQLi"],
        },
        outcome: {
          success: true,
          access_achieved: "root",
          time_to_access_minutes: 45,
          flags_captured: 2,
        },
        metadata: {
          source: "local",
          created_at: new Date().toISOString(),
          session_id: "test-session",
          anonymized: true,
          confidence: 1.0,
          access_count: 0,
        },
        vector: [],
      },
    }

    beforeEach(() => {
      mockCapturePattern.mockResolvedValue(successResult)
    })

    test("output confirms pattern was saved", async () => {
      const { ctx } = makeContext()
      const result = await savePatternTool.execute({}, ctx)

      expect(result).toContain("Pattern Saved Successfully")
    })

    test("output includes pattern ID", async () => {
      const { ctx } = makeContext()
      const result = await savePatternTool.execute({}, ctx)

      expect(result).toContain("pat-new-001")
    })

    test("output includes methodology summary", async () => {
      const { ctx } = makeContext()
      const result = await savePatternTool.execute({}, ctx)

      expect(result).toContain("SQL injection in login form")
    })

    test("output includes target profile details", async () => {
      const { ctx } = makeContext()
      const result = await savePatternTool.execute({}, ctx)

      expect(result).toContain("linux")
      expect(result).toContain("http")
      expect(result).toContain("ssh")
    })

    test("output includes technologies", async () => {
      const { ctx } = makeContext()
      const result = await savePatternTool.execute({}, ctx)

      expect(result).toContain("apache")
      expect(result).toContain("wordpress")
    })

    test("output includes vulnerability type and description", async () => {
      const { ctx } = makeContext()
      const result = await savePatternTool.execute({}, ctx)

      expect(result).toContain("sqli")
      expect(result).toContain("Time-based blind SQL injection")
    })

    test("output includes outcome details", async () => {
      const { ctx } = makeContext()
      const result = await savePatternTool.execute({}, ctx)

      expect(result).toContain("root")
      expect(result).toContain("45 minutes")
      expect(result).toContain("Flags Captured: 2")
    })

    test("output includes key insights", async () => {
      const { ctx } = makeContext()
      const result = await savePatternTool.execute({}, ctx)

      expect(result).toContain("Login form vulnerable to time-based blind SQLi")
    })

    test("output includes anonymization note", async () => {
      const { ctx } = makeContext()
      const result = await savePatternTool.execute({}, ctx)

      expect(result).toContain("anonymized")
    })

    test("metadata title is 'Pattern saved'", async () => {
      const { ctx, metadataCalls } = makeContext()
      await savePatternTool.execute({}, ctx)

      expect(metadataCalls[0].title).toBe("Pattern saved")
    })

    test("metadata has success=true", async () => {
      const { ctx, metadataCalls } = makeContext()
      await savePatternTool.execute({}, ctx)

      expect(metadataCalls[0].metadata?.success).toBe(true)
    })

    test("metadata has patternId from the saved pattern", async () => {
      const { ctx, metadataCalls } = makeContext()
      await savePatternTool.execute({}, ctx)

      expect(metadataCalls[0].metadata?.patternId).toBe("pat-new-001")
    })
  })

  // ---------------------------------------------------------------------------
  // Duplicate path
  // ---------------------------------------------------------------------------

  describe("duplicate path", () => {
    beforeEach(() => {
      mockCapturePattern.mockResolvedValue({
        success: false,
        message: "Similar pattern already exists (similarity: 95.2%)",
        duplicateOf: "pat-existing-789",
      })
    })

    test("output indicates duplicate detected", async () => {
      const { ctx } = makeContext()
      const result = await savePatternTool.execute({}, ctx)

      expect(result).toContain("Duplicate Detected")
    })

    test("output includes the existing pattern ID", async () => {
      const { ctx } = makeContext()
      const result = await savePatternTool.execute({}, ctx)

      expect(result).toContain("pat-existing-789")
    })

    test("output includes the similarity message", async () => {
      const { ctx } = makeContext()
      const result = await savePatternTool.execute({}, ctx)

      expect(result).toContain("95.2%")
    })

    test("metadata title is 'Pattern duplicate'", async () => {
      const { ctx, metadataCalls } = makeContext()
      await savePatternTool.execute({}, ctx)

      expect(metadataCalls[0].title).toBe("Pattern duplicate")
    })

    test("metadata has success=false", async () => {
      const { ctx, metadataCalls } = makeContext()
      await savePatternTool.execute({}, ctx)

      expect(metadataCalls[0].metadata?.success).toBe(false)
    })

    test("metadata patternId is the existing duplicate's ID", async () => {
      const { ctx, metadataCalls } = makeContext()
      await savePatternTool.execute({}, ctx)

      expect(metadataCalls[0].metadata?.patternId).toBe("pat-existing-789")
    })
  })

  // ---------------------------------------------------------------------------
  // Failure path (no engagement state, no access, etc.)
  // ---------------------------------------------------------------------------

  describe("failure path", () => {
    beforeEach(() => {
      mockCapturePattern.mockResolvedValue({
        success: false,
        message: "No engagement state found for session",
      })
    })

    test("output indicates pattern was not saved", async () => {
      const { ctx } = makeContext()
      const result = await savePatternTool.execute({}, ctx)

      expect(result).toContain("Pattern Not Saved")
    })

    test("output includes the error message", async () => {
      const { ctx } = makeContext()
      const result = await savePatternTool.execute({}, ctx)

      expect(result).toContain("No engagement state found")
    })

    test("output includes common-reasons guidance", async () => {
      const { ctx } = makeContext()
      const result = await savePatternTool.execute({}, ctx)

      expect(result).toContain("Common reasons")
    })

    test("common reasons mention access requirement", async () => {
      const { ctx } = makeContext()
      const result = await savePatternTool.execute({}, ctx)

      expect(result).toContain("access")
    })

    test("common reasons mention engagement state", async () => {
      const { ctx } = makeContext()
      const result = await savePatternTool.execute({}, ctx)

      expect(result).toContain("engagement state")
    })

    test("common reasons mention embedding service", async () => {
      const { ctx } = makeContext()
      const result = await savePatternTool.execute({}, ctx)

      expect(result).toContain("Embedding service")
    })

    test("metadata title is 'Pattern save failed'", async () => {
      const { ctx, metadataCalls } = makeContext()
      await savePatternTool.execute({}, ctx)

      expect(metadataCalls[0].title).toBe("Pattern save failed")
    })

    test("metadata has success=false", async () => {
      const { ctx, metadataCalls } = makeContext()
      await savePatternTool.execute({}, ctx)

      expect(metadataCalls[0].metadata?.success).toBe(false)
    })

    test("metadata patternId is undefined (no pattern, no duplicate)", async () => {
      const { ctx, metadataCalls } = makeContext()
      await savePatternTool.execute({}, ctx)

      expect(metadataCalls[0].metadata?.patternId).toBeUndefined()
    })

    test("metadata message matches the error", async () => {
      const { ctx, metadataCalls } = makeContext()
      await savePatternTool.execute({}, ctx)

      expect(metadataCalls[0].metadata?.message).toBe("No engagement state found for session")
    })
  })

  // ---------------------------------------------------------------------------
  // Failure: no access achieved
  // ---------------------------------------------------------------------------

  describe("failure path: no access achieved", () => {
    beforeEach(() => {
      mockCapturePattern.mockResolvedValue({
        success: false,
        message: "Cannot save pattern: no access achieved yet. Achieve user or root access first.",
      })
    })

    test("output includes the access requirement message", async () => {
      const { ctx } = makeContext()
      const result = await savePatternTool.execute({}, ctx)

      expect(result).toContain("no access achieved")
    })

    test("output still shows common reasons for guidance", async () => {
      const { ctx } = makeContext()
      const result = await savePatternTool.execute({}, ctx)

      expect(result).toContain("Common reasons")
    })
  })

  // ---------------------------------------------------------------------------
  // Parameter forwarding
  // ---------------------------------------------------------------------------

  describe("parameter forwarding", () => {
    beforeEach(() => {
      mockCapturePattern.mockResolvedValue({
        success: false,
        message: "No engagement state found for session",
      })
    })

    test("forwards sessionID from context to capturePattern", async () => {
      const { ctx } = makeContext("my-session-42")
      await savePatternTool.execute({}, ctx)

      expect(mockCapturePattern).toHaveBeenCalledTimes(1)
      expect(mockCapturePattern.mock.calls[0][0]).toBe("my-session-42")
    })

    test("forwards engagement_type to capturePattern options", async () => {
      const { ctx } = makeContext()
      await savePatternTool.execute({ engagement_type: "htb" }, ctx)

      const options = mockCapturePattern.mock.calls[0][1]
      expect(options.engagementType).toBe("htb")
    })

    test("sets userTriggered=true in capturePattern options", async () => {
      const { ctx } = makeContext()
      await savePatternTool.execute({}, ctx)

      const options = mockCapturePattern.mock.calls[0][1]
      expect(options.userTriggered).toBe(true)
    })

    test("forwards 'ctf' engagement type", async () => {
      const { ctx } = makeContext()
      await savePatternTool.execute({ engagement_type: "ctf" }, ctx)

      const options = mockCapturePattern.mock.calls[0][1]
      expect(options.engagementType).toBe("ctf")
    })

    test("omitted engagement_type forwards as undefined", async () => {
      const { ctx } = makeContext()
      await savePatternTool.execute({}, ctx)

      const options = mockCapturePattern.mock.calls[0][1]
      expect(options.engagementType).toBeUndefined()
    })
  })

  // ---------------------------------------------------------------------------
  // Metadata: always exactly one emission
  // ---------------------------------------------------------------------------

  describe("metadata emissions", () => {
    test("success path emits exactly one metadata call", async () => {
      mockCapturePattern.mockResolvedValue({
        success: true,
        message: "ok",
        pattern: {
          id: "pat-x",
          target_profile: { os: "linux", services: [], ports: [], technologies: [], characteristics: [] },
          vulnerability: { type: "rce", description: "RCE" },
          methodology: { summary: "RCE via deserialization", phases: [], tools_sequence: [], key_insights: [] },
          outcome: { success: true, access_achieved: "root", time_to_access_minutes: 10 },
          metadata: { source: "local", created_at: "", session_id: "", anonymized: true, confidence: 1, access_count: 0 },
          vector: [],
        },
      })

      const { ctx, metadataCalls } = makeContext()
      await savePatternTool.execute({}, ctx)

      expect(metadataCalls).toHaveLength(1)
    })

    test("failure path emits exactly one metadata call", async () => {
      mockCapturePattern.mockResolvedValue({ success: false, message: "error" })

      const { ctx, metadataCalls } = makeContext()
      await savePatternTool.execute({}, ctx)

      expect(metadataCalls).toHaveLength(1)
    })

    test("duplicate path emits exactly one metadata call", async () => {
      mockCapturePattern.mockResolvedValue({
        success: false,
        message: "duplicate",
        duplicateOf: "pat-dup",
      })

      const { ctx, metadataCalls } = makeContext()
      await savePatternTool.execute({}, ctx)

      expect(metadataCalls).toHaveLength(1)
    })
  })

  // ---------------------------------------------------------------------------
  // Session isolation
  // ---------------------------------------------------------------------------

  describe("session isolation", () => {
    beforeEach(() => {
      mockCapturePattern.mockResolvedValue({ success: false, message: "no state" })
    })

    test("different session IDs produce independent metadata", async () => {
      const { ctx: ctx1, metadataCalls: meta1 } = makeContext("session-alpha")
      const { ctx: ctx2, metadataCalls: meta2 } = makeContext("session-beta")

      await savePatternTool.execute({}, ctx1)
      await savePatternTool.execute({}, ctx2)

      expect(meta1).toHaveLength(1)
      expect(meta2).toHaveLength(1)
    })

    test("each call receives its own session ID", async () => {
      const { ctx: ctx1 } = makeContext("session-alpha")
      const { ctx: ctx2 } = makeContext("session-beta")

      await savePatternTool.execute({}, ctx1)
      await savePatternTool.execute({}, ctx2)

      expect(mockCapturePattern.mock.calls[0][0]).toBe("session-alpha")
      expect(mockCapturePattern.mock.calls[1][0]).toBe("session-beta")
    })
  })

  // ---------------------------------------------------------------------------
  // Output formatting: success with zero flags
  // ---------------------------------------------------------------------------

  describe("output formatting edge cases", () => {
    test("success with flags_captured=0 omits flags line", async () => {
      mockCapturePattern.mockResolvedValue({
        success: true,
        message: "ok",
        pattern: {
          id: "pat-noflag",
          target_profile: { os: "linux", services: ["http"], ports: [80], technologies: [], characteristics: [] },
          vulnerability: { type: "lfi", description: "Local file inclusion" },
          methodology: { summary: "LFI to shell", phases: [], tools_sequence: ["curl"], key_insights: ["LFI in param"] },
          outcome: { success: true, access_achieved: "user", time_to_access_minutes: 20, flags_captured: 0 },
          metadata: { source: "local", created_at: "", session_id: "", anonymized: true, confidence: 1, access_count: 0 },
          vector: [],
        },
      })

      const { ctx } = makeContext()
      const result = await savePatternTool.execute({}, ctx)

      // flags_captured is falsy (0), so the line should be filtered out
      expect(result).not.toContain("Flags Captured")
    })

    test("success with empty services shows 'none'", async () => {
      mockCapturePattern.mockResolvedValue({
        success: true,
        message: "ok",
        pattern: {
          id: "pat-nosvc",
          target_profile: { os: "unknown", services: [], ports: [], technologies: [], characteristics: [] },
          vulnerability: { type: "rce", description: "Remote code execution" },
          methodology: { summary: "Direct RCE", phases: [], tools_sequence: [], key_insights: [] },
          outcome: { success: true, access_achieved: "root", time_to_access_minutes: 5 },
          metadata: { source: "local", created_at: "", session_id: "", anonymized: true, confidence: 1, access_count: 0 },
          vector: [],
        },
      })

      const { ctx } = makeContext()
      const result = await savePatternTool.execute({}, ctx)

      expect(result).toContain("none")
    })
  })
})
