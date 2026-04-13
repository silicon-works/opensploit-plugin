import { describe, test, expect, afterEach } from "bun:test"

// sparse.ts
import {
  sparseDotProduct,
  sparseCosineSimilarity,
  parseSparseJson,
  serializeSparse,
  type SparseVector,
} from "../../src/memory/sparse"

// context.ts
import {
  createToolContext,
  getToolContext,
  clearToolContext,
  stopCleanupInterval,
  updateSearchContext,
  recordToolTried,
  recordToolSuccess,
  recordToolFailure,
  clearPreviousFailure,
  getPreviousFailure,
  setCurrentPhase,
  getContextSummary,
} from "../../src/memory/context"

// schema.ts
import {
  generateExperienceId,
  generateInsightId,
  generatePatternId,
  createExperience,
  createInsight,
  createPattern,
  parsePattern,
  VECTOR_DIMENSIONS,
  EXPERIENCE_DEDUP_THRESHOLD,
  INSIGHT_DEDUP_THRESHOLD,
  PATTERN_DEDUP_THRESHOLD,
} from "../../src/memory/schema"

// =============================================================================
// sparse.ts
// =============================================================================

describe("memory/sparse", () => {
  describe("sparseDotProduct", () => {
    test("returns 0 for empty vectors", () => {
      expect(sparseDotProduct({}, {})).toBe(0)
    })

    test("returns 0 when vectors share no keys", () => {
      const a: SparseVector = { "1": 1.0, "2": 2.0 }
      const b: SparseVector = { "3": 3.0, "4": 4.0 }
      expect(sparseDotProduct(a, b)).toBe(0)
    })

    test("computes dot product for overlapping keys", () => {
      const a: SparseVector = { "1": 2.0, "2": 3.0 }
      const b: SparseVector = { "1": 4.0, "2": 5.0 }
      // 2*4 + 3*5 = 8 + 15 = 23
      expect(sparseDotProduct(a, b)).toBe(23)
    })

    test("handles partial overlap", () => {
      const a: SparseVector = { "1": 2.0, "2": 3.0, "99": 10.0 }
      const b: SparseVector = { "1": 4.0, "3": 5.0 }
      // only key "1" overlaps: 2*4 = 8
      expect(sparseDotProduct(a, b)).toBe(8)
    })

    test("is commutative", () => {
      const a: SparseVector = { "1": 2.0, "2": 3.0 }
      const b: SparseVector = { "2": 5.0, "3": 7.0 }
      expect(sparseDotProduct(a, b)).toBe(sparseDotProduct(b, a))
    })

    test("iterates over the smaller vector for efficiency (asymmetric sizes)", () => {
      const small: SparseVector = { "5": 1.0 }
      const large: SparseVector = {}
      for (let i = 0; i < 1000; i++) large[String(i)] = 1.0
      // key "5" overlaps: 1*1 = 1
      expect(sparseDotProduct(small, large)).toBe(1)
      expect(sparseDotProduct(large, small)).toBe(1)
    })

    test("handles negative weights", () => {
      const a: SparseVector = { "1": -2.0, "2": 3.0 }
      const b: SparseVector = { "1": 4.0, "2": -1.0 }
      // -2*4 + 3*(-1) = -8 + -3 = -11
      expect(sparseDotProduct(a, b)).toBe(-11)
    })
  })

  describe("sparseCosineSimilarity", () => {
    test("returns 0 for empty vectors", () => {
      expect(sparseCosineSimilarity({}, {})).toBe(0)
    })

    test("returns 0 when one vector is empty", () => {
      expect(sparseCosineSimilarity({ "1": 1.0 }, {})).toBe(0)
      expect(sparseCosineSimilarity({}, { "1": 1.0 })).toBe(0)
    })

    test("returns 0 when vectors share no keys", () => {
      const a: SparseVector = { "1": 1.0 }
      const b: SparseVector = { "2": 1.0 }
      expect(sparseCosineSimilarity(a, b)).toBe(0)
    })

    test("returns 1 for identical vectors", () => {
      const v: SparseVector = { "1": 3.0, "2": 4.0 }
      expect(sparseCosineSimilarity(v, v)).toBeCloseTo(1.0, 10)
    })

    test("returns 1 for proportional vectors", () => {
      const a: SparseVector = { "1": 1.0, "2": 2.0 }
      const b: SparseVector = { "1": 10.0, "2": 20.0 }
      expect(sparseCosineSimilarity(a, b)).toBeCloseTo(1.0, 10)
    })

    test("returns value between 0 and 1 for non-negative vectors", () => {
      const a: SparseVector = { "1": 1.0, "2": 0.5 }
      const b: SparseVector = { "2": 0.8, "3": 1.0 }
      const sim = sparseCosineSimilarity(a, b)
      expect(sim).toBeGreaterThan(0)
      expect(sim).toBeLessThan(1)
    })

    test("is commutative", () => {
      const a: SparseVector = { "1": 1.0, "2": 3.0 }
      const b: SparseVector = { "2": 2.0, "3": 5.0 }
      expect(sparseCosineSimilarity(a, b)).toBe(sparseCosineSimilarity(b, a))
    })

    test("computes known value", () => {
      // a = (3, 4), b = (4, 3)
      // dot = 12+12 = 24, |a| = 5, |b| = 5
      // cosine = 24/25 = 0.96
      const a: SparseVector = { "1": 3.0, "2": 4.0 }
      const b: SparseVector = { "1": 4.0, "2": 3.0 }
      expect(sparseCosineSimilarity(a, b)).toBeCloseTo(0.96, 10)
    })
  })

  describe("parseSparseJson", () => {
    test("returns empty object for null", () => {
      expect(parseSparseJson(null)).toEqual({})
    })

    test("returns empty object for undefined", () => {
      expect(parseSparseJson(undefined)).toEqual({})
    })

    test("returns empty object for empty string", () => {
      expect(parseSparseJson("")).toEqual({})
    })

    test("parses valid JSON object", () => {
      const json = '{"1": 0.5, "42": 1.2}'
      expect(parseSparseJson(json)).toEqual({ "1": 0.5, "42": 1.2 })
    })

    test("returns empty object for JSON array", () => {
      expect(parseSparseJson("[1, 2, 3]")).toEqual({})
    })

    test("returns empty object for JSON string", () => {
      expect(parseSparseJson('"hello"')).toEqual({})
    })

    test("returns empty object for JSON number", () => {
      expect(parseSparseJson("42")).toEqual({})
    })

    test("returns empty object for JSON null", () => {
      expect(parseSparseJson("null")).toEqual({})
    })

    test("returns empty object for invalid JSON", () => {
      expect(parseSparseJson("{not valid json}")).toEqual({})
    })
  })

  describe("serializeSparse", () => {
    test("returns empty string for null", () => {
      expect(serializeSparse(null)).toBe("")
    })

    test("returns empty string for undefined", () => {
      expect(serializeSparse(undefined)).toBe("")
    })

    test("returns empty string for empty object", () => {
      expect(serializeSparse({})).toBe("")
    })

    test("serializes non-empty object to JSON", () => {
      const v: SparseVector = { "1": 0.5, "42": 1.2 }
      const result = serializeSparse(v)
      expect(JSON.parse(result)).toEqual(v)
    })

    test("roundtrips with parseSparseJson", () => {
      const original: SparseVector = { "10": 3.14, "20": 2.71 }
      const serialized = serializeSparse(original)
      const parsed = parseSparseJson(serialized)
      expect(parsed).toEqual(original)
    })
  })
})

// =============================================================================
// context.ts
// =============================================================================

describe("memory/context", () => {
  const sessionId = "test-session-ctx-" + Date.now()

  afterEach(() => {
    clearToolContext(sessionId)
    stopCleanupInterval()
  })

  describe("createToolContext", () => {
    test("returns fresh context with all default values", () => {
      const ctx = createToolContext()
      expect(ctx.lastSearchQuery).toBeNull()
      expect(ctx.lastSearchResults).toEqual([])
      expect(ctx.currentPhase).toBeNull()
      expect(ctx.toolsTried).toEqual([])
      expect(ctx.recentSuccesses).toEqual([])
      expect(ctx.previousFailure).toBeNull()
      expect(ctx.lastAccessTime).toBeGreaterThan(0)
    })
  })

  describe("getToolContext", () => {
    test("creates a new context for unknown session", () => {
      const ctx = getToolContext(sessionId)
      expect(ctx.lastSearchQuery).toBeNull()
      expect(ctx.toolsTried).toEqual([])
    })

    test("returns the same context for the same session", () => {
      const ctx1 = getToolContext(sessionId)
      ctx1.currentPhase = "recon"
      const ctx2 = getToolContext(sessionId)
      expect(ctx2.currentPhase).toBe("recon")
    })

    test("updates lastAccessTime on each access", () => {
      const ctx1 = getToolContext(sessionId)
      const t1 = ctx1.lastAccessTime
      // Ensure at least 1ms passes
      const start = Date.now()
      while (Date.now() === start) {}
      const ctx2 = getToolContext(sessionId)
      expect(ctx2.lastAccessTime).toBeGreaterThanOrEqual(t1)
    })
  })

  describe("updateSearchContext", () => {
    test("updates query and results", () => {
      updateSearchContext(sessionId, "port scanning tool", [
        { tool: "nmap", score: 0.95 },
        { tool: "masscan", score: 0.82, method: "quick_scan" },
      ])
      const ctx = getToolContext(sessionId)
      expect(ctx.lastSearchQuery).toBe("port scanning tool")
      expect(ctx.lastSearchResults).toHaveLength(2)
      expect(ctx.lastSearchResults[0].tool).toBe("nmap")
      expect(ctx.lastSearchResults[1].method).toBe("quick_scan")
    })
  })

  describe("recordToolTried", () => {
    test("adds tool to toolsTried", () => {
      recordToolTried(sessionId, "nmap")
      const ctx = getToolContext(sessionId)
      expect(ctx.toolsTried).toContain("nmap")
    })

    test("does not duplicate tools", () => {
      recordToolTried(sessionId, "nmap")
      recordToolTried(sessionId, "nmap")
      const ctx = getToolContext(sessionId)
      expect(ctx.toolsTried.filter((t) => t === "nmap")).toHaveLength(1)
    })

    test("evicts oldest when at capacity", () => {
      // Fill to capacity (100)
      for (let i = 0; i < 100; i++) {
        recordToolTried(sessionId, `tool-${i}`)
      }
      const ctx = getToolContext(sessionId)
      expect(ctx.toolsTried).toHaveLength(100)
      expect(ctx.toolsTried[0]).toBe("tool-0")

      // Add one more
      recordToolTried(sessionId, "tool-overflow")
      expect(ctx.toolsTried).toHaveLength(100)
      expect(ctx.toolsTried).not.toContain("tool-0")
      expect(ctx.toolsTried[ctx.toolsTried.length - 1]).toBe("tool-overflow")
    })
  })

  describe("recordToolSuccess", () => {
    test("adds tool to recentSuccesses", () => {
      recordToolSuccess(sessionId, "sqlmap")
      const ctx = getToolContext(sessionId)
      expect(ctx.recentSuccesses).toContain("sqlmap")
    })

    test("does not duplicate tools", () => {
      recordToolSuccess(sessionId, "sqlmap")
      recordToolSuccess(sessionId, "sqlmap")
      const ctx = getToolContext(sessionId)
      expect(ctx.recentSuccesses.filter((t) => t === "sqlmap")).toHaveLength(1)
    })

    test("evicts oldest when at capacity", () => {
      for (let i = 0; i < 100; i++) {
        recordToolSuccess(sessionId, `success-${i}`)
      }
      const ctx = getToolContext(sessionId)
      expect(ctx.recentSuccesses).toHaveLength(100)

      recordToolSuccess(sessionId, "success-overflow")
      expect(ctx.recentSuccesses).toHaveLength(100)
      expect(ctx.recentSuccesses).not.toContain("success-0")
      expect(ctx.recentSuccesses[ctx.recentSuccesses.length - 1]).toBe("success-overflow")
    })
  })

  describe("recordToolFailure / getPreviousFailure / clearPreviousFailure", () => {
    test("records failure information", () => {
      recordToolFailure(sessionId, "exp_123_abc", "nmap", "connection timeout")
      const failure = getPreviousFailure(sessionId)
      expect(failure).not.toBeNull()
      expect(failure!.experienceId).toBe("exp_123_abc")
      expect(failure!.tool).toBe("nmap")
      expect(failure!.reason).toBe("connection timeout")
    })

    test("overwrites previous failure", () => {
      recordToolFailure(sessionId, "exp_1", "nmap", "timeout")
      recordToolFailure(sessionId, "exp_2", "sqlmap", "auth error")
      const failure = getPreviousFailure(sessionId)
      expect(failure!.experienceId).toBe("exp_2")
      expect(failure!.tool).toBe("sqlmap")
    })

    test("clearPreviousFailure removes the failure", () => {
      recordToolFailure(sessionId, "exp_1", "nmap", "timeout")
      clearPreviousFailure(sessionId)
      expect(getPreviousFailure(sessionId)).toBeNull()
    })
  })

  describe("setCurrentPhase", () => {
    test("sets the current phase", () => {
      setCurrentPhase(sessionId, "exploitation")
      const ctx = getToolContext(sessionId)
      expect(ctx.currentPhase).toBe("exploitation")
    })

    test("overwrites previous phase", () => {
      setCurrentPhase(sessionId, "reconnaissance")
      setCurrentPhase(sessionId, "enumeration")
      const ctx = getToolContext(sessionId)
      expect(ctx.currentPhase).toBe("enumeration")
    })
  })

  describe("clearToolContext", () => {
    test("removes the session context entirely", () => {
      recordToolTried(sessionId, "nmap")
      setCurrentPhase(sessionId, "recon")
      clearToolContext(sessionId)
      // Getting the context after clear should return a fresh one
      const ctx = getToolContext(sessionId)
      expect(ctx.toolsTried).toEqual([])
      expect(ctx.currentPhase).toBeNull()
    })
  })

  describe("getContextSummary", () => {
    test("returns summary of a fresh context", () => {
      const summary = getContextSummary(sessionId)
      expect(summary.hasLastSearch).toBe(false)
      expect(summary.lastSearchResultCount).toBe(0)
      expect(summary.currentPhase).toBeNull()
      expect(summary.toolsTriedCount).toBe(0)
      expect(summary.recentSuccessCount).toBe(0)
      expect(summary.hasPreviousFailure).toBe(false)
    })

    test("reflects state changes", () => {
      updateSearchContext(sessionId, "scan", [{ tool: "nmap", score: 0.9 }])
      recordToolTried(sessionId, "nmap")
      recordToolSuccess(sessionId, "nmap")
      setCurrentPhase(sessionId, "enumeration")
      recordToolFailure(sessionId, "exp_1", "ffuf", "not found")

      const summary = getContextSummary(sessionId)
      expect(summary.hasLastSearch).toBe(true)
      expect(summary.lastSearchResultCount).toBe(1)
      expect(summary.currentPhase).toBe("enumeration")
      expect(summary.toolsTriedCount).toBe(1)
      expect(summary.recentSuccessCount).toBe(1)
      expect(summary.hasPreviousFailure).toBe(true)
    })
  })
})

// =============================================================================
// schema.ts
// =============================================================================

describe("memory/schema", () => {
  describe("constants", () => {
    test("VECTOR_DIMENSIONS is 1024 (BGE-M3)", () => {
      expect(VECTOR_DIMENSIONS).toBe(1024)
    })

    test("dedup thresholds are set correctly", () => {
      expect(EXPERIENCE_DEDUP_THRESHOLD).toBe(0.92)
      expect(INSIGHT_DEDUP_THRESHOLD).toBe(0.90)
      expect(PATTERN_DEDUP_THRESHOLD).toBe(0.92)
    })
  })

  describe("generateExperienceId", () => {
    test("starts with exp_ prefix", () => {
      expect(generateExperienceId()).toMatch(/^exp_/)
    })

    test("contains timestamp and random parts", () => {
      const id = generateExperienceId()
      const parts = id.split("_")
      expect(parts).toHaveLength(3)
      expect(parts[0]).toBe("exp")
      expect(Number(parts[1])).toBeGreaterThan(0)
      expect(parts[2].length).toBeGreaterThanOrEqual(1)
    })

    test("generates unique IDs", () => {
      const ids = new Set(Array.from({ length: 50 }, () => generateExperienceId()))
      expect(ids.size).toBe(50)
    })
  })

  describe("generateInsightId", () => {
    test("starts with ins_ prefix", () => {
      expect(generateInsightId()).toMatch(/^ins_/)
    })

    test("generates unique IDs", () => {
      const ids = new Set(Array.from({ length: 50 }, () => generateInsightId()))
      expect(ids.size).toBe(50)
    })
  })

  describe("generatePatternId", () => {
    test("starts with pat_ prefix", () => {
      expect(generatePatternId()).toMatch(/^pat_/)
    })

    test("generates unique IDs", () => {
      const ids = new Set(Array.from({ length: 50 }, () => generatePatternId()))
      expect(ids.size).toBe(50)
    })
  })

  describe("createExperience", () => {
    const minInput = {
      action: {
        query: "scan ports",
        tool_selected: "nmap",
        tool_input: '{"target": "10.10.10.1"}',
      },
      outcome: {
        success: true,
        result_summary: "Found 3 open ports",
      },
      context: {
        phase: "reconnaissance",
      },
    }

    test("auto-generates id and timestamp when omitted", () => {
      const exp = createExperience(minInput)
      expect(exp.id).toMatch(/^exp_/)
      expect(typeof exp.timestamp).toBe("string")
      expect((exp.timestamp as string).length).toBeGreaterThan(0)
    })

    test("uses provided id and timestamp", () => {
      const exp = createExperience({
        ...minInput,
        id: "exp_custom_id",
        timestamp: "2026-01-01T00:00:00Z",
      })
      expect(exp.id).toBe("exp_custom_id")
      expect(exp.timestamp).toBe("2026-01-01T00:00:00Z")
    })

    test("normalizes nullable fields to safe defaults", () => {
      const exp = createExperience(minInput)
      const outcome = exp.outcome as Record<string, unknown>
      expect(outcome.failure_reason).toBe("")
      expect(outcome.recovery).toEqual({ tool: "", method: "", worked: false })
      const ctx = exp.context as Record<string, unknown>
      expect(ctx.target_characteristics).toEqual([])
      expect(exp.sparse_json).toBe("")
      expect(exp.archived).toBe(false)
    })

    test("preserves provided optional fields", () => {
      const exp = createExperience({
        ...minInput,
        outcome: {
          success: false,
          result_summary: "Failed",
          failure_reason: "connection refused",
          recovery: { tool: "masscan", method: "tcp_scan", worked: true },
        },
        context: {
          phase: "reconnaissance",
          target_characteristics: ["linux", "web"],
        },
        sparse_json: '{"42": 1.5}',
        archived: true,
      })
      const outcome = exp.outcome as Record<string, unknown>
      expect(outcome.failure_reason).toBe("connection refused")
      expect(outcome.recovery).toEqual({ tool: "masscan", method: "tcp_scan", worked: true })
      const ctx = exp.context as Record<string, unknown>
      expect(ctx.target_characteristics).toEqual(["linux", "web"])
      expect(exp.sparse_json).toBe('{"42": 1.5}')
      expect(exp.archived).toBe(true)
    })

    test("creates 1024-dim zero vector when vector omitted", () => {
      const exp = createExperience(minInput)
      const vector = exp.vector as number[]
      expect(vector).toHaveLength(1024)
      expect(vector.every((v) => v === 0)).toBe(true)
    })

    test("uses provided vector", () => {
      const vec = Array(1024).fill(0.5)
      const exp = createExperience({ ...minInput, vector: vec })
      expect(exp.vector).toEqual(vec)
    })
  })

  describe("createInsight", () => {
    const minInput = {
      created_from: ["exp_1", "exp_2"],
      confidence: 0.75,
      contradictions: 0,
      rule: "nmap is better than masscan for stealth scans",
      suggestion: {
        prefer: "nmap",
        when: "stealth is required",
      },
    }

    test("auto-generates id and created_at when omitted", () => {
      const ins = createInsight(minInput)
      expect(ins.id).toMatch(/^ins_/)
      expect(typeof ins.created_at).toBe("string")
    })

    test("uses provided id and created_at", () => {
      const ins = createInsight({
        ...minInput,
        id: "ins_custom",
        created_at: "2026-01-01T00:00:00Z",
      })
      expect(ins.id).toBe("ins_custom")
      expect(ins.created_at).toBe("2026-01-01T00:00:00Z")
    })

    test("normalizes nullable fields", () => {
      const ins = createInsight(minInput)
      expect(ins.last_reinforced).toBe("")
      expect(ins.sparse_json).toBe("")
      const suggestion = ins.suggestion as Record<string, unknown>
      expect(suggestion.over).toBe("")
    })

    test("preserves provided optional fields", () => {
      const ins = createInsight({
        ...minInput,
        last_reinforced: "2026-03-15T00:00:00Z",
        suggestion: {
          prefer: "nmap",
          over: "masscan",
          when: "stealth is required",
        },
        sparse_json: '{"7": 0.3}',
      })
      expect(ins.last_reinforced).toBe("2026-03-15T00:00:00Z")
      const suggestion = ins.suggestion as Record<string, unknown>
      expect(suggestion.over).toBe("masscan")
      expect(ins.sparse_json).toBe('{"7": 0.3}')
    })

    test("creates 1024-dim zero vector when vector omitted", () => {
      const ins = createInsight(minInput)
      const vector = ins.vector as number[]
      expect(vector).toHaveLength(1024)
      expect(vector.every((v) => v === 0)).toBe(true)
    })

    test("passes through created_from and confidence", () => {
      const ins = createInsight(minInput)
      expect(ins.created_from).toEqual(["exp_1", "exp_2"])
      expect(ins.confidence).toBe(0.75)
      expect(ins.contradictions).toBe(0)
      expect(ins.rule).toBe("nmap is better than masscan for stealth scans")
    })
  })

  describe("createPattern", () => {
    const fullInput = {
      target_profile: {
        os: "linux" as const,
        services: ["http", "ssh"],
        ports: [80, 22],
        technologies: ["apache", "php"],
        characteristics: ["login_form"],
      },
      vulnerability: {
        type: "sqli",
        description: "SQL injection in login form",
        cve: "CVE-2024-1234",
        cvss: 9.8,
      },
      methodology: {
        summary: "SQLi in login -> DB creds -> SSH",
        phases: [
          {
            phase: "reconnaissance" as const,
            action: "port scan",
            tool: "nmap",
            result: "found 80, 22",
            pivotal: false,
          },
        ],
        tools_sequence: ["nmap", "sqlmap", "ssh"],
        key_insights: ["Check login forms first"],
      },
      outcome: {
        success: true,
        access_achieved: "root" as const,
        time_to_access_minutes: 45,
        flags_captured: 2,
      },
      metadata: {
        source: "local" as const,
        created_at: "2026-01-01T00:00:00Z",
        engagement_type: "htb",
        anonymized: true,
      },
    }

    test("auto-generates id when omitted", () => {
      const pat = createPattern(fullInput)
      expect(pat.id).toMatch(/^pat_/)
    })

    test("uses provided id", () => {
      const pat = createPattern({ ...fullInput, id: "pat_custom" })
      expect(pat.id).toBe("pat_custom")
    })

    test("serializes phases to JSON", () => {
      const pat = createPattern(fullInput)
      const methodology = pat.methodology as Record<string, unknown>
      expect(typeof methodology.phases_json).toBe("string")
      const parsed = JSON.parse(methodology.phases_json as string)
      expect(parsed).toHaveLength(1)
      expect(parsed[0].tool).toBe("nmap")
    })

    test("fills in defaults for missing optional nested fields", () => {
      const minimal = {
        target_profile: {
          os: "unknown" as const,
          services: [],
          ports: [],
          technologies: [],
          characteristics: [],
        },
        vulnerability: { type: "rce", description: "Remote code execution" },
        methodology: {
          summary: "RCE via file upload",
          phases: [],
          tools_sequence: ["curl"],
          key_insights: [],
        },
        outcome: {
          success: true,
          access_achieved: "user" as const,
          time_to_access_minutes: 30,
        },
        metadata: {
          source: "local" as const,
          created_at: "2026-01-01T00:00:00Z",
          anonymized: false,
        },
      }
      const pat = createPattern(minimal)
      const vuln = pat.vulnerability as Record<string, unknown>
      expect(vuln.cve).toBe("")
      expect(vuln.cvss).toBe(0)

      const outcome = pat.outcome as Record<string, unknown>
      expect(outcome.flags_captured).toBe(0)
      expect(outcome.requires_external_trigger).toBe(false)
      expect(outcome.active_time_minutes).toBe(0)

      const meta = pat.metadata as Record<string, unknown>
      expect(meta.model_used).toBe("")
      expect(meta.engagement_type).toBe("")
      expect(meta.confidence).toBe(1.0)
      expect(meta.last_accessed).toBe("")
      expect(meta.access_count).toBe(0)
      expect(meta.superseded_by).toBe("")
    })

    test("creates 1024-dim zero vector when vector omitted", () => {
      const pat = createPattern(fullInput)
      const vector = pat.vector as number[]
      expect(vector).toHaveLength(1024)
    })

    test("preserves all provided fields", () => {
      const pat = createPattern(fullInput)
      const tp = pat.target_profile as Record<string, unknown>
      expect(tp.os).toBe("linux")
      expect(tp.services).toEqual(["http", "ssh"])
      expect(tp.ports).toEqual([80, 22])

      const outcome = pat.outcome as Record<string, unknown>
      expect(outcome.success).toBe(true)
      expect(outcome.access_achieved).toBe("root")
      expect(outcome.flags_captured).toBe(2)
    })
  })

  describe("parsePattern", () => {
    test("roundtrips through createPattern and parsePattern", () => {
      const input = {
        target_profile: {
          os: "windows" as const,
          services: ["smb", "rdp"],
          ports: [445, 3389],
          technologies: ["iis"],
          characteristics: ["domain_joined"],
        },
        vulnerability: {
          type: "ms17-010",
          description: "EternalBlue SMB exploit",
          cve: "CVE-2017-0144",
          cvss: 9.8,
        },
        methodology: {
          summary: "EternalBlue -> SYSTEM shell",
          phases: [
            {
              phase: "exploitation" as const,
              action: "run eternalblue",
              tool: "metasploit",
              result: "SYSTEM shell",
              pivotal: true,
            },
          ],
          tools_sequence: ["nmap", "metasploit"],
          key_insights: ["Always check for MS17-010 on SMB"],
        },
        outcome: {
          success: true,
          access_achieved: "root" as const,
          time_to_access_minutes: 10,
          flags_captured: 2,
        },
        metadata: {
          source: "local" as const,
          created_at: "2026-02-01T00:00:00Z",
          anonymized: true,
        },
      }

      const record = createPattern(input) as Record<string, unknown>
      const parsed = parsePattern(record)

      expect(parsed.id).toMatch(/^pat_/)
      expect(parsed.target_profile.os).toBe("windows")
      expect(parsed.target_profile.services).toEqual(["smb", "rdp"])
      expect(parsed.target_profile.ports).toEqual([445, 3389])
      expect(parsed.methodology.summary).toBe("EternalBlue -> SYSTEM shell")
      expect(parsed.methodology.phases).toHaveLength(1)
      expect(parsed.methodology.phases[0].tool).toBe("metasploit")
      expect(parsed.methodology.phases[0].pivotal).toBe(true)
      expect(parsed.methodology.tools_sequence).toEqual(["nmap", "metasploit"])
    })

    test("handles missing phases_json gracefully", () => {
      const record = {
        id: "pat_test",
        target_profile: { os: "unknown" },
        vulnerability: { type: "xss", description: "XSS" },
        methodology: { summary: "test" },
        outcome: { success: false, access_achieved: "none", time_to_access_minutes: 0 },
        metadata: { source: "local", created_at: "2026-01-01", anonymized: false },
        vector: [0.1, 0.2],
      }
      const parsed = parsePattern(record)
      expect(parsed.methodology.phases).toEqual([])
      expect(parsed.methodology.tools_sequence).toEqual([])
    })

    test("converts Arrow-like iterable objects to arrays", () => {
      // Simulate an Arrow Vector with toArray()
      const mockArrowVector = {
        toArray: () => new Int32Array([80, 443, 8080]),
        [Symbol.iterator]: function* () {
          yield 80
          yield 443
          yield 8080
        },
      }
      const record = {
        id: "pat_arrow",
        target_profile: {
          os: "linux",
          services: ["http"],
          ports: mockArrowVector,
          technologies: [],
          characteristics: [],
        },
        vulnerability: { type: "rce", description: "test" },
        methodology: { summary: "test", tools_sequence: [], key_insights: [], phases_json: "[]" },
        outcome: { success: true, access_achieved: "user", time_to_access_minutes: 5 },
        metadata: { source: "local", created_at: "2026-01-01", anonymized: false },
        vector: [],
      }
      const parsed = parsePattern(record)
      // Int32Array gets spread into a plain array
      expect(parsed.target_profile.ports).toEqual([80, 443, 8080])
      expect(Array.isArray(parsed.target_profile.ports)).toBe(true)
    })
  })
})
