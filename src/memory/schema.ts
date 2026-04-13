/**
 * Memory System Schema Definitions
 *
 * Implements Doc 22 §Part 6 (lines 1732-1778)
 * - Experience table: Records tool execution outcomes for learning
 * - Insight table: Extracted rules from experience patterns
 * - MethodRow: Method-level tool rows for fine-grained search
 *
 * Apache Arrow schemas are used for LanceDB table creation.
 * TypeScript interfaces are used for type safety in the application.
 */

import {
  Schema,
  Field,
  Utf8,
  Float32,
  List,
  FixedSizeList,
  Struct,
  Bool,
  Int32,
} from "apache-arrow"

// =============================================================================
// TypeScript Interfaces
// =============================================================================

/**
 * Experience record - captures a tool execution and its outcome
 * Doc 22 §Part 6 (lines 1736-1760)
 */
export interface Experience {
  /** Unique ID: exp_{timestamp}_{random} */
  id: string

  /** When this experience was recorded (ISO string) */
  timestamp: string

  /** What action was taken */
  action: {
    /** The search query that led to tool selection */
    query: string
    /** Which tool was selected */
    tool_selected: string
    /** Input parameters passed to the tool (JSON string) */
    tool_input: string
  }

  /** What happened when the tool ran */
  outcome: {
    /** Did the tool achieve its goal? */
    success: boolean
    /** Summary of what happened */
    result_summary: string
    /** If failed, why? */
    failure_reason?: string
    /** If failed then recovered, what worked? */
    recovery?: {
      tool: string
      method: string
      worked: boolean
    }
  }

  /** Context about the engagement state */
  context: {
    /** Current phase (reconnaissance, enumeration, etc.) */
    phase: string
    /** Target characteristics that might affect tool selection */
    target_characteristics?: string[]
  }

  /** Embedding vector for semantic search (BGE-M3: 1024 dimensions) */
  vector: number[]

  /** Sparse embedding as JSON Record<string, number> for hybrid scoring */
  sparse_json?: string

  /** Whether this experience has been archived */
  archived?: boolean
}

/**
 * Insight record - an extracted rule from experience patterns
 * Doc 22 §Part 6 (lines 1762-1778)
 */
export interface Insight {
  /** Unique ID: ins_{timestamp}_{random} */
  id: string

  /** When this insight was created (ISO string) */
  created_at: string

  /** Experience IDs this insight was derived from */
  created_from: string[]

  /** Confidence score 0-1, starts at 0.5 */
  confidence: number

  /** Last time this insight was reinforced (ISO string) */
  last_reinforced?: string

  /** Number of times this insight was contradicted */
  contradictions: number

  /** Natural language description of the insight */
  rule: string

  /** Actionable suggestion */
  suggestion: {
    /** Tool to prefer */
    prefer: string
    /** Tool to avoid (optional) */
    over?: string
    /** When this preference applies */
    when: string
  }

  /** Embedding vector for semantic search */
  vector: number[]

  /** Sparse embedding as JSON Record<string, number> for hybrid scoring */
  sparse_json?: string
}

/**
 * Attack phase record - a step in an attack methodology
 * Doc 13 §AttackPhase (lines 507-518)
 */
export interface AttackPhase {
  /** Security phase: reconnaissance, enumeration, exploitation, post_exploitation, reporting */
  phase: "reconnaissance" | "enumeration" | "exploitation" | "post_exploitation" | "reporting"
  /** What action was performed */
  action: string
  /** Which tool was used */
  tool: string
  /** What was found or achieved */
  result: string
  /** Was this a key breakthrough? (see §Pivotal Step Detection) */
  pivotal: boolean
  /** P1: Does success depend on victim action? */
  requires_victim_interaction?: boolean
  /** P1: How exfiltration/callback works */
  callback_method?: "http" | "dns" | "oob" | "none"
  /** P1: Delivery mechanism for multi-stage attacks */
  delivery_mechanism?: string
}

/**
 * Attack pattern record - a successful attack methodology for learning
 * Doc 13 §AttackPattern (lines 453-505)
 */
export interface AttackPattern {
  /** Unique ID: pat_{timestamp}_{random} */
  id: string

  /** Target profile - what we match against for "surface similarity" */
  target_profile: {
    /** Operating system: linux, windows, or unknown */
    os: "linux" | "windows" | "unknown"
    /** Discovered services: http, ssh, smb, etc. */
    services: string[]
    /** Open ports */
    ports: number[]
    /** Technologies found: apache, wordpress, php, etc. */
    technologies: string[]
    /** Characteristics: login_form, file_upload, api_endpoint, etc. */
    characteristics: string[]
  }

  /** What vulnerability was exploited */
  vulnerability: {
    /** Type: sqli, rce, lfi, xxe, ssrf, etc. */
    type: string
    /** Brief description */
    description: string
    /** CVE identifier if known */
    cve?: string
    /** CVSS severity score */
    cvss?: number
  }

  /** The attack methodology - the valuable knowledge */
  methodology: {
    /** Summary: "SQL injection in login form → DB creds → SSH" */
    summary: string
    /** Detailed steps (stored as JSON in LanceDB) */
    phases: AttackPhase[]
    /** Tool sequence: ["nmap", "ffuf", "sqlmap", "ssh"] */
    tools_sequence: string[]
    /** Key insights/lessons learned */
    key_insights: string[]
  }

  /** Outcome metrics */
  outcome: {
    /** Did the attack succeed? */
    success: boolean
    /** Access level achieved: none, user, root */
    access_achieved: "none" | "user" | "root"
    /** Time to achieve access */
    time_to_access_minutes: number
    /** Number of flags captured (CTF) */
    flags_captured?: number
    /** P1: Did success depend on victim action? */
    requires_external_trigger?: boolean
    /** P1: Time spent actively working (vs waiting) */
    active_time_minutes?: number
  }

  /** Metadata */
  metadata: {
    /** Source: local (user's patterns) or community (shared) */
    source: "local" | "community"
    /** When this pattern was created */
    created_at: string
    /** Session ID - removed during anonymization */
    session_id?: string
    /** Model used for the engagement */
    model_used?: string
    /** Engagement type: htb, vulnhub, real */
    engagement_type?: string
    /** Whether PII has been removed */
    anonymized: boolean
    /** Confidence score 0.0-1.0, decreases if contradicted (P2: industry best practice) */
    confidence?: number
    /** Last time this pattern was accessed/retrieved (ISO string, for relevance decay) */
    last_accessed?: string
    /** Number of times this pattern has been retrieved (for popularity ranking) */
    access_count?: number
    /** ID of pattern that supersedes this one (for version tracking) */
    superseded_by?: string
  }

  /** Embedding vector for semantic search (BGE-M3: 1024 dimensions) */
  vector: number[]
}

// =============================================================================
// Apache Arrow Schemas (for LanceDB)
// =============================================================================

/**
 * Experience table schema
 * Doc 22 §Part 6 (lines 1736-1760)
 */
export const experienceSchema = new Schema([
  new Field("id", new Utf8()),
  new Field("timestamp", new Utf8()),
  new Field(
    "action",
    new Struct([
      new Field("query", new Utf8()),
      new Field("tool_selected", new Utf8()),
      new Field("tool_input", new Utf8()),
    ])
  ),
  new Field(
    "outcome",
    new Struct([
      new Field("success", new Bool()),
      new Field("result_summary", new Utf8()),
      new Field("failure_reason", new Utf8(), true), // nullable
      new Field(
        "recovery",
        new Struct([
          new Field("tool", new Utf8()),
          new Field("method", new Utf8()),
          new Field("worked", new Bool()),
        ]),
        true
      ), // nullable
    ])
  ),
  new Field(
    "context",
    new Struct([
      new Field("phase", new Utf8()),
      new Field(
        "target_characteristics",
        new List(new Field("item", new Utf8())),
        true
      ),
    ])
  ),
  // Vector must be FixedSizeList for LanceDB vector search (BGE-M3: 1024 dims)
  new Field("vector", new FixedSizeList(1024, new Field("item", new Float32()))),
  new Field("sparse_json", new Utf8(), true), // Sparse embedding as JSON Record<string, number>
  new Field("archived", new Bool(), true),
])

/**
 * Insight table schema
 * Doc 22 §Part 6 (lines 1762-1778)
 */
export const insightSchema = new Schema([
  new Field("id", new Utf8()),
  new Field("created_at", new Utf8()),
  new Field("created_from", new List(new Field("item", new Utf8()))),
  new Field("confidence", new Float32()),
  new Field("last_reinforced", new Utf8(), true),
  new Field("contradictions", new Int32()),
  new Field("rule", new Utf8()),
  new Field(
    "suggestion",
    new Struct([
      new Field("prefer", new Utf8()),
      new Field("over", new Utf8(), true),
      new Field("when", new Utf8()),
    ])
  ),
  // Vector must be FixedSizeList for LanceDB vector search (BGE-M3: 1024 dims)
  new Field("vector", new FixedSizeList(1024, new Field("item", new Float32()))),
  new Field("sparse_json", new Utf8(), true), // Sparse embedding as JSON Record<string, number>
])

/**
 * Pattern table schema
 * Doc 13 §LanceDB Table Schema (lines 1011-1063)
 */
export const patternSchema = new Schema([
  new Field("id", new Utf8()),

  // Target profile
  new Field(
    "target_profile",
    new Struct([
      new Field("os", new Utf8()),
      new Field("services", new List(new Field("item", new Utf8()))),
      new Field("ports", new List(new Field("item", new Int32()))),
      new Field("technologies", new List(new Field("item", new Utf8()))),
      new Field("characteristics", new List(new Field("item", new Utf8()))),
    ])
  ),

  // Vulnerability
  new Field(
    "vulnerability",
    new Struct([
      new Field("type", new Utf8()),
      new Field("description", new Utf8()),
      new Field("cve", new Utf8(), true), // nullable
      new Field("cvss", new Float32(), true), // nullable
    ])
  ),

  // Methodology (phases stored as JSON string for LanceDB compatibility)
  new Field(
    "methodology",
    new Struct([
      new Field("summary", new Utf8()),
      new Field("tools_sequence", new List(new Field("item", new Utf8()))),
      new Field("key_insights", new List(new Field("item", new Utf8()))),
      new Field("phases_json", new Utf8()), // JSON string of AttackPhase[]
    ])
  ),

  // Outcome
  new Field(
    "outcome",
    new Struct([
      new Field("success", new Bool()),
      new Field("access_achieved", new Utf8()),
      new Field("time_to_access_minutes", new Int32()),
      new Field("flags_captured", new Int32(), true), // nullable
      new Field("requires_external_trigger", new Bool(), true), // nullable, P1
      new Field("active_time_minutes", new Int32(), true), // nullable, P1
    ])
  ),

  // Metadata
  new Field(
    "metadata",
    new Struct([
      new Field("source", new Utf8()),
      new Field("created_at", new Utf8()),
      new Field("model_used", new Utf8(), true), // nullable
      new Field("engagement_type", new Utf8(), true), // nullable
      new Field("anonymized", new Bool()),
      // P2 fields: industry best practices for memory management
      new Field("confidence", new Float32(), true), // nullable, 0.0-1.0
      new Field("last_accessed", new Utf8(), true), // nullable, ISO string
      new Field("access_count", new Int32(), true), // nullable
      new Field("superseded_by", new Utf8(), true), // nullable, pattern ID
    ])
  ),

  // Vector embedding (BGE-M3: 1024 dimensions)
  new Field("vector", new FixedSizeList(1024, new Field("item", new Float32()))),
])

/**
 * Memory system metadata
 */
export interface MemoryMetadata {
  initialized: boolean
  timestamp: string
  version: string
}

/**
 * Generate a unique experience ID
 */
export function generateExperienceId(): string {
  const timestamp = Date.now()
  const random = Math.random().toString(36).substring(2, 8)
  return `exp_${timestamp}_${random}`
}

/**
 * Generate a unique insight ID
 */
export function generateInsightId(): string {
  const timestamp = Date.now()
  const random = Math.random().toString(36).substring(2, 8)
  return `ins_${timestamp}_${random}`
}

/**
 * Generate a unique pattern ID
 * Doc 13 compatibility - for future pattern learning implementation
 */
export function generatePatternId(): string {
  const timestamp = Date.now()
  const random = Math.random().toString(36).substring(2, 8)
  return `pat_${timestamp}_${random}`
}

// =============================================================================
// Factory Functions (handle LanceDB nullable field limitations)
// =============================================================================

/**
 * LanceDB/Apache Arrow has issues with nullable nested struct fields.
 * These factory functions normalize records before insertion, replacing
 * undefined/null with schema-compliant defaults.
 */

/** Default empty recovery struct */
const EMPTY_RECOVERY = { tool: "", method: "", worked: false }

/**
 * Create a LanceDB-compatible experience record
 *
 * Normalizes nullable fields to prevent Arrow buffer errors.
 * Use this before inserting into the experiences table.
 */
export function createExperience(
  input: Omit<Experience, "id" | "timestamp" | "vector"> & {
    id?: string
    timestamp?: string
    vector?: number[]
    sparse_json?: string
  }
): Record<string, unknown> {
  return {
    id: input.id ?? generateExperienceId(),
    timestamp: input.timestamp ?? new Date().toISOString(),
    action: {
      query: input.action.query,
      tool_selected: input.action.tool_selected,
      tool_input: input.action.tool_input,
    },
    outcome: {
      success: input.outcome.success,
      result_summary: input.outcome.result_summary,
      failure_reason: input.outcome.failure_reason ?? "",
      recovery: input.outcome.recovery ?? EMPTY_RECOVERY,
    },
    context: {
      phase: input.context.phase,
      target_characteristics: input.context.target_characteristics ?? [],
    },
    vector: input.vector ?? Array(1024).fill(0),
    sparse_json: input.sparse_json ?? "",
    archived: input.archived ?? false,
  }
}

/** Default empty suggestion struct */
const EMPTY_SUGGESTION = { prefer: "", over: "", when: "" }

/**
 * Create a LanceDB-compatible insight record
 *
 * Normalizes nullable fields to prevent Arrow buffer errors.
 * Use this before inserting into the insights table.
 */
export function createInsight(
  input: Omit<Insight, "id" | "created_at" | "vector"> & {
    id?: string
    created_at?: string
    vector?: number[]
    sparse_json?: string
  }
): Record<string, unknown> {
  return {
    id: input.id ?? generateInsightId(),
    created_at: input.created_at ?? new Date().toISOString(),
    created_from: input.created_from,
    confidence: input.confidence,
    last_reinforced: input.last_reinforced ?? "",
    contradictions: input.contradictions,
    rule: input.rule,
    suggestion: {
      prefer: input.suggestion.prefer,
      over: input.suggestion.over ?? "",
      when: input.suggestion.when,
    },
    vector: input.vector ?? Array(1024).fill(0),
    sparse_json: input.sparse_json ?? "",
  }
}

/** Default empty target profile struct */
const EMPTY_TARGET_PROFILE = {
  os: "unknown",
  services: [] as string[],
  ports: [] as number[],
  technologies: [] as string[],
  characteristics: [] as string[],
}

/** Default empty vulnerability struct */
const EMPTY_VULNERABILITY = {
  type: "",
  description: "",
  cve: "",
  cvss: 0,
}

/** Default empty methodology struct */
const EMPTY_METHODOLOGY = {
  summary: "",
  tools_sequence: [] as string[],
  key_insights: [] as string[],
  phases_json: "[]",
}

/** Default empty outcome struct */
const EMPTY_OUTCOME = {
  success: false,
  access_achieved: "none",
  time_to_access_minutes: 0,
  flags_captured: 0,
  requires_external_trigger: false,
  active_time_minutes: 0,
}

/** Default empty metadata struct */
const EMPTY_METADATA = {
  source: "local",
  created_at: "",
  model_used: "",
  engagement_type: "",
  anonymized: false,
  // P2 fields: industry best practices for memory management
  confidence: 1.0, // Start at full confidence
  last_accessed: "",
  access_count: 0,
  superseded_by: "",
}

/**
 * Create a LanceDB-compatible pattern record
 *
 * Normalizes nullable fields and serializes phases to JSON.
 * Use this before inserting into the patterns table.
 *
 * Doc 13 §LanceDB Table Schema (lines 1011-1063)
 */
export function createPattern(
  input: Omit<AttackPattern, "id" | "vector"> & {
    id?: string
    vector?: number[]
  }
): Record<string, unknown> {
  return {
    id: input.id ?? generatePatternId(),

    target_profile: {
      os: input.target_profile?.os ?? "unknown",
      services: input.target_profile?.services ?? [],
      ports: input.target_profile?.ports ?? [],
      technologies: input.target_profile?.technologies ?? [],
      characteristics: input.target_profile?.characteristics ?? [],
    },

    vulnerability: {
      type: input.vulnerability?.type ?? "",
      description: input.vulnerability?.description ?? "",
      cve: input.vulnerability?.cve ?? "",
      cvss: input.vulnerability?.cvss ?? 0,
    },

    methodology: {
      summary: input.methodology?.summary ?? "",
      tools_sequence: input.methodology?.tools_sequence ?? [],
      key_insights: input.methodology?.key_insights ?? [],
      // Serialize phases array to JSON string for LanceDB
      phases_json: JSON.stringify(input.methodology?.phases ?? []),
    },

    outcome: {
      success: input.outcome?.success ?? false,
      access_achieved: input.outcome?.access_achieved ?? "none",
      time_to_access_minutes: input.outcome?.time_to_access_minutes ?? 0,
      flags_captured: input.outcome?.flags_captured ?? 0,
      requires_external_trigger: input.outcome?.requires_external_trigger ?? false,
      active_time_minutes: input.outcome?.active_time_minutes ?? 0,
    },

    metadata: {
      source: input.metadata?.source ?? "local",
      created_at: input.metadata?.created_at ?? new Date().toISOString(),
      model_used: input.metadata?.model_used ?? "",
      engagement_type: input.metadata?.engagement_type ?? "",
      anonymized: input.metadata?.anonymized ?? false,
      // P2 fields: industry best practices for memory management
      confidence: input.metadata?.confidence ?? 1.0, // Start at full confidence
      last_accessed: input.metadata?.last_accessed ?? "",
      access_count: input.metadata?.access_count ?? 0,
      superseded_by: input.metadata?.superseded_by ?? "",
    },

    vector: input.vector ?? Array(1024).fill(0),
  }
}

/**
 * Convert Arrow Vector to JavaScript array if needed
 * LanceDB returns Arrow Vector objects for array fields, not JS arrays.
 * For numeric types, .toArray() returns TypedArrays (Int32Array, Float32Array)
 * which need to be spread into regular arrays.
 */
function toArray<T>(value: unknown): T[] {
  if (Array.isArray(value)) {
    return value as T[]
  }
  // Check for Arrow Vector's toArray method
  if (value && typeof value === "object" && "toArray" in value && typeof (value as { toArray: () => unknown }).toArray === "function") {
    const arr = (value as { toArray: () => unknown }).toArray()
    // TypedArrays (Int32Array, Float32Array) need to be spread into regular arrays
    if (ArrayBuffer.isView(arr) && !(arr instanceof DataView)) {
      return [...(arr as unknown as Iterable<T>)] as T[]
    }
    return arr as T[]
  }
  // Check for iterable (Symbol.iterator) as fallback
  if (value && typeof value === "object" && Symbol.iterator in value) {
    return [...(value as Iterable<T>)]
  }
  return []
}

/**
 * Parse a pattern record from LanceDB back to the AttackPattern interface
 *
 * Deserializes the phases_json field back to AttackPhase[].
 * Converts Arrow Vector objects to JavaScript arrays.
 */
export function parsePattern(record: Record<string, unknown>): AttackPattern {
  const methodology = record.methodology as Record<string, unknown>
  const phases_json = (methodology?.phases_json as string) || "[]"
  const targetProfile = record.target_profile as Record<string, unknown>

  return {
    id: record.id as string,
    target_profile: {
      os: (targetProfile?.os as AttackPattern["target_profile"]["os"]) ?? "unknown",
      services: toArray<string>(targetProfile?.services),
      ports: toArray<number>(targetProfile?.ports),
      technologies: toArray<string>(targetProfile?.technologies),
      characteristics: toArray<string>(targetProfile?.characteristics),
    },
    vulnerability: record.vulnerability as AttackPattern["vulnerability"],
    methodology: {
      summary: (methodology?.summary as string) ?? "",
      tools_sequence: toArray<string>(methodology?.tools_sequence),
      key_insights: toArray<string>(methodology?.key_insights),
      phases: JSON.parse(phases_json) as AttackPhase[],
    },
    outcome: record.outcome as AttackPattern["outcome"],
    metadata: record.metadata as AttackPattern["metadata"],
    vector: toArray<number>(record.vector),
  }
}

// =============================================================================
// Method-Level Tool Row (Phase A1)
// =============================================================================

/**
 * Method-level row in the tools table.
 *
 * Each row represents a single method within a tool. A tool with 9 methods
 * produces 9 rows, each with method-specific search_text and method_vector.
 * This enables fine-grained search that suggests the right method, not just
 * the right tool.
 */
export interface MethodRow {
  /** Composite ID: "tool_id:method_name" (e.g., "nmap:port_scan") */
  id: string
  /** Tool ID (e.g., "nmap") */
  tool_id: string
  /** Method name (e.g., "port_scan") */
  method_name: string
  /** Tool display name */
  tool_name: string
  /** Tool description */
  tool_description: string
  /** Method description */
  method_description: string
  /** Method when_to_use hint */
  when_to_use: string
  /** Focused method-level search text for FTS */
  search_text: string
  /** Tool phases as JSON array */
  phases_json: string
  /** Tool capabilities as JSON array */
  capabilities_json: string
  /** Tool routing as JSON object */
  routing_json: string
  /** ALL tool methods as JSON (for reconstruction) */
  methods_json: string
  /** Tool requirements as JSON (optional) */
  requirements_json: string
  /** Tool resources as JSON (optional) */
  resources_json: string
  /** Full tool entry as JSON (for loadRegistry reconstruction) */
  raw_json: string
  /** Tool see_also as JSON array of tool IDs */
  see_also_json: string
  /** SHA-256 content hash for freshness */
  registry_hash: string
  /** Dense BGE-M3 embedding (1024 dims), present when imported from .lance */
  method_vector?: number[]
  /** Sparse vector as JSON Record<string, number> */
  sparse_json?: string
}

// =============================================================================
// Constants
// =============================================================================

/** BGE-M3 embedding dimension */
export const VECTOR_DIMENSIONS = 1024

/** Experience deduplication threshold (Doc 22 REQ-MEM-010) */
export const EXPERIENCE_DEDUP_THRESHOLD = 0.92

/** Insight deduplication threshold (Doc 22 REQ-MEM-011) */
export const INSIGHT_DEDUP_THRESHOLD = 0.90

/** Pattern deduplication threshold (Doc 13) - conservative to avoid losing variations */
export const PATTERN_DEDUP_THRESHOLD = 0.92
