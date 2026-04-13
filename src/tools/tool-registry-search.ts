import z from "zod"
import { tool, type ToolContext } from "@opencode-ai/plugin"
import DESCRIPTION from "./tool-registry-search.txt"
import path from "path"
import os from "os"
import fs from "fs/promises"
import yaml from "js-yaml"
import * as lancedb from "@lancedb/lancedb"
import { createLog } from "../util/log"
import { getRootSession } from "../session/hierarchy"
import * as SessionDirectory from "../session/directory"
import { readdirSync, statSync, readFileSync, existsSync } from "fs"
import {
  updateSearchContext,
  getToolContext,
  unifiedSearch,
  formatUnifiedResults,
  type SearchResult,
  type ScoredTool,
  type SearchContext,
} from "../memory/index"
import {
  importFromLance,
  importFromYAML,
  loadRegistry,
  getStoredHash,
  needsUpdate,
  hasVectors,
  TOOLS_TABLE_NAME,
} from "../memory/tools"
import { getConnection } from "../memory/database"
import { getEmbeddingService } from "../memory/embedding"
import { sparseCosineSimilarity, parseSparseJson } from "../memory/sparse"

const log = createLog("tool.registry-search")

// =============================================================================
// Configuration
// =============================================================================

const REGISTRY_CONFIG = {
  REMOTE_URL: "https://opensploit.ai/registry.yaml",
  REMOTE_HASH_URL: "https://opensploit.ai/registry.sha256",
  REMOTE_LANCE_URL: "https://opensploit.ai/registry.lance.tar.gz",
  CACHE_DIR: path.join(os.homedir(), ".opensploit"),
  CACHE_PATH: path.join(os.homedir(), ".opensploit", "registry.yaml"),
  LANCE_CACHE_PATH: path.join(os.homedir(), ".opensploit", "registry.lance.tar.gz"),
  CACHE_TTL_MS: 24 * 60 * 60 * 1000, // 24 hours
}

const VALID_PHASES = ["reconnaissance", "enumeration", "exploitation", "post-exploitation"] as const
type Phase = (typeof VALID_PHASES)[number]

// =============================================================================
// Registry Zod Schemas (for validation)
// =============================================================================

const ParamDefSchema = z.object({
  type: z.union([z.string(), z.array(z.string())]),
  required: z.boolean().optional(),
  default: z.any().optional(),
  description: z.string().optional(),
  enum: z.array(z.union([z.string(), z.number()])).optional(),
  values: z.array(z.string().nullable()).optional(),
})

const ReturnDefSchema = z.object({
  type: z.string(),
  description: z.string().optional(),
  items: z.string().optional(),
})

const MethodDefSchema = z.object({
  description: z.string(),
  when_to_use: z.string().optional(),
  next_step: z.string().optional(),
  params: z.record(z.string(), ParamDefSchema).optional(),
  returns: z.record(z.string(), ReturnDefSchema).optional(),
})

const NeverUseForEntrySchema = z.union([
  z.string(),
  z.object({
    task: z.string(),
    use_instead: z.union([z.string(), z.array(z.string())]).optional(),
    reason: z.string().optional(),
  }),
])

const RegistryToolSchema = z.object({
  name: z.string(),
  version: z.string().optional(),
  description: z.string(),
  image: z.string().optional(),
  image_size_mb: z.number().optional(),
  external: z.boolean().optional(),
  source: z.string().optional(),
  capabilities: z.array(z.string()).optional().default([]),
  phases: z.array(z.string()).optional().default([]),
  routing: z
    .object({
      use_for: z.array(z.string()).optional(),
      triggers: z.array(z.string()).optional(),
      never_use_for: z.array(NeverUseForEntrySchema).optional(),
      prefer_over: z.array(z.string()).optional(),
    })
    .optional(),
  requirements: z
    .object({
      network: z.boolean().optional(),
      privileged: z.boolean().optional(),
      privileged_reason: z.string().optional(),
    })
    .optional(),
  resources: z
    .object({
      memory_mb: z.number().optional(),
      cpu: z.number().optional(),
    })
    .optional(),
  methods: z.record(z.string(), MethodDefSchema).optional(),
}).passthrough() // Allow extra fields like see_also, warnings, internal

const RegistrySchema = z.object({
  version: z.string().optional(),
  updated_at: z.string().optional(),
  tools: z.record(z.string(), RegistryToolSchema.passthrough()),
}).passthrough()

// =============================================================================
// Registry Types (inferred from Zod schemas)
// =============================================================================

type ParamDef = z.infer<typeof ParamDefSchema>
type ReturnDef = z.infer<typeof ReturnDefSchema>
type MethodDef = z.infer<typeof MethodDefSchema>
type NeverUseForEntry = z.infer<typeof NeverUseForEntrySchema>
type RegistryTool = z.infer<typeof RegistryToolSchema>
type Registry = z.infer<typeof RegistrySchema>

// =============================================================================
// Result Types
// =============================================================================

interface ToolMethodResult {
  name: string
  description: string
  when_to_use?: string
  next_step?: string
  params: Record<string, ParamDef>
  returns?: Record<string, ReturnDef>
}

interface ToolResult {
  tool: string
  name: string
  description: string
  image?: string
  routing: {
    use_for: string[]
    triggers?: string[]
    never_use_for?: NeverUseForEntry[]
    prefer_over?: string[]
  }
  suggested_alternatives?: string[]
  /** Top-scoring method for this query (method-level search) */
  suggested_method?: string
  capabilities: string[]
  phases: string[]
  requirements?: {
    network?: boolean
    privileged?: boolean
    privileged_reason?: string
  }
  methods: ToolMethodResult[]
  warning?: string
}

interface ToolSearchResult {
  query: string
  phase?: string
  capability?: string
  results: ToolResult[]
  anti_pattern_warnings: string[]
  registry_hash: string
  cache_status?: "fresh" | "stale" | "new"
}

// =============================================================================
// Method-Level Search Types
// =============================================================================

/** A scored method from LanceDB search */
interface ScoredMethod {
  toolId: string
  methodName: string
  methodDescription: string
  whenToUse: string
  /** Combined dense + sparse score */
  score: number
}

/** A tool with method-level scoring */
interface ToolWithMethods {
  toolId: string
  tool: RegistryTool
  /** Best method score + routing adjustment */
  score: number
  /** Top-scoring method for this tool */
  suggestedMethod: string
  suggestedMethodDescription: string
  /** All methods ranked by score */
  rankedMethods: ScoredMethod[]
  warning?: string
  /** see_also tool IDs from registry */
  seeAlso: string[]
}

// =============================================================================
// Registry Fetching — Hash-Based Freshness
// =============================================================================

interface CacheInfo {
  registry: Registry
  hash: string
  timestamp: number
}

let memoryCache: CacheInfo | null = null

/** Cached result of hasVectors() — reset on registry import */
let _vectorsAvailable: boolean | null = null

async function ensureCacheDir(): Promise<void> {
  try {
    await fs.mkdir(REGISTRY_CONFIG.CACHE_DIR, { recursive: true })
  } catch {
    // Directory may already exist
  }
}

function isCacheStale(timestamp: number): boolean {
  return Date.now() - timestamp > REGISTRY_CONFIG.CACHE_TTL_MS
}

async function loadCacheFromDisk(): Promise<Registry | null> {
  try {
    const text = await fs.readFile(REGISTRY_CONFIG.CACHE_PATH, "utf-8")
    const parsed = yaml.load(text)
    const validated = RegistrySchema.parse(parsed)
    log.info("loaded registry from cache", { path: REGISTRY_CONFIG.CACHE_PATH })
    return validated
  } catch (error) {
    if (error instanceof z.ZodError) {
      log.warn("invalid registry cache format", { errors: error.issues.slice(0, 3) })
    }
    return null
  }
}

/**
 * Compute SHA-256 hash of string content.
 */
async function computeHash(content: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(content)
  const hashBuffer = await crypto.subtle.digest("SHA-256", data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("")
}

/**
 * Fetch remote registry hash (64 bytes, very fast).
 */
async function fetchRemoteHash(): Promise<string | null> {
  try {
    const response = await fetch(REGISTRY_CONFIG.REMOTE_HASH_URL, {
      headers: { "User-Agent": "opensploit-cli" },
      signal: AbortSignal.timeout(5000), // 5 second timeout — it's tiny
    })
    if (!response.ok) return null
    const text = await response.text()
    return text.trim()
  } catch {
    return null
  }
}

/**
 * Download and import .lance archive.
 */
async function downloadAndImportLance(hash: string): Promise<boolean> {
  try {
    log.info("downloading registry .lance archive", { url: REGISTRY_CONFIG.REMOTE_LANCE_URL })
    const response = await fetch(REGISTRY_CONFIG.REMOTE_LANCE_URL, {
      headers: { "User-Agent": "opensploit-cli" },
      signal: AbortSignal.timeout(60000), // 60 second timeout — larger file
    })
    if (!response.ok) {
      log.warn("failed to download .lance archive", { status: response.status })
      return false
    }

    await ensureCacheDir()
    const buffer = await response.arrayBuffer()
    await fs.writeFile(REGISTRY_CONFIG.LANCE_CACHE_PATH, Buffer.from(buffer))

    await importFromLance(REGISTRY_CONFIG.LANCE_CACHE_PATH, hash)
    _vectorsAvailable = null // Reset cache — new import may change vector availability
    log.info("imported registry from .lance archive")

    // Clean up tar file
    try { await fs.unlink(REGISTRY_CONFIG.LANCE_CACHE_PATH) } catch { /* ok */ }
    return true
  } catch (error) {
    log.warn("lance archive import failed", { error: String(error) })
    return false
  }
}

/**
 * Download YAML and import to LanceDB (fallback).
 */
async function downloadAndImportYAML(hash: string): Promise<Registry | null> {
  try {
    log.info("fetching registry YAML", { url: REGISTRY_CONFIG.REMOTE_URL })
    const response = await fetch(REGISTRY_CONFIG.REMOTE_URL, {
      headers: { "User-Agent": "opensploit-cli" },
      signal: AbortSignal.timeout(30000),
    })
    if (!response.ok) return null

    const text = await response.text()
    const parsed = yaml.load(text)
    const validated = RegistrySchema.parse(parsed)

    // Save to disk cache
    await ensureCacheDir()
    await fs.writeFile(REGISTRY_CONFIG.CACHE_PATH, text, "utf-8")

    // Import into LanceDB with FTS index (no vectors)
    await importFromYAML(validated.tools, hash)
    _vectorsAvailable = null // Reset cache — YAML import has no vectors
    log.info("imported registry from YAML fallback")

    return validated
  } catch (error) {
    log.warn("YAML registry fetch/import failed", { error: String(error) })
    return null
  }
}

/**
 * Load registry from LanceDB and reconstruct into Registry format.
 */
async function loadFromLanceDB(): Promise<{ registry: Registry; hash: string } | null> {
  try {
    const result = await loadRegistry()
    if (!result) return null

    // Version is not stored in LanceDB (only per-tool data is). Hardcoded
    // to satisfy RegistrySchema. Version checking was replaced by hash-based
    // freshness, so this value is unused for any logic.
    const parsed = { version: "2.0", tools: result.tools }
    const validated = RegistrySchema.parse(parsed)
    log.info("loaded registry from LanceDB", { hash: result.hash.slice(0, 16) })
    return { registry: validated, hash: result.hash }
  } catch (error) {
    log.debug("LanceDB registry load failed", { error: String(error) })
    return null
  }
}

interface GetRegistryResult {
  registry: Registry
  hash: string
  cacheStatus: "fresh" | "stale" | "new"
}

/**
 * Get the registry with hash-based freshness checking.
 *
 * Flow:
 * 1. Memory cache (instant, within session)
 * 2. Fetch remote hash (64 bytes, <100ms)
 * 3. Compare to stored hash
 * 4. Match → load from LanceDB (instant)
 * 5. Mismatch → download .lance archive → importFromLance()
 * 6. .lance fails → download YAML → importFromYAML()
 * 7. All remote fail → use existing LanceDB or YAML disk cache
 */
async function getRegistry(): Promise<GetRegistryResult> {
  const now = Date.now()

  // 1. Check memory cache (within-session performance)
  if (memoryCache && !isCacheStale(memoryCache.timestamp)) {
    return { registry: memoryCache.registry, hash: memoryCache.hash, cacheStatus: "fresh" }
  }

  // 2. Fetch remote hash (tiny, fast)
  const remoteHash = await fetchRemoteHash()

  if (remoteHash) {
    // 3. Compare to stored hash
    const isStale = await needsUpdate(remoteHash)

    if (!isStale) {
      // 4. Hash matches — load from LanceDB (instant, no download needed)
      const lanceResult = await loadFromLanceDB()
      if (lanceResult) {
        memoryCache = { registry: lanceResult.registry, hash: lanceResult.hash, timestamp: now }
        return { registry: lanceResult.registry, hash: lanceResult.hash, cacheStatus: "fresh" }
      }
    }

    // 5. Hash mismatch or LanceDB empty — try downloading .lance archive
    const lanceImported = await downloadAndImportLance(remoteHash)
    if (lanceImported) {
      const lanceResult = await loadFromLanceDB()
      if (lanceResult) {
        memoryCache = { registry: lanceResult.registry, hash: remoteHash, timestamp: now }
        return { registry: lanceResult.registry, hash: remoteHash, cacheStatus: "new" }
      }
    }

    // 6. .lance failed — fall back to YAML download
    const yamlRegistry = await downloadAndImportYAML(remoteHash)
    if (yamlRegistry) {
      memoryCache = { registry: yamlRegistry, hash: remoteHash, timestamp: now }
      return { registry: yamlRegistry, hash: remoteHash, cacheStatus: "new" }
    }
  }

  // 7. All remote failed — try existing LanceDB (stale)
  const staleResult = await loadFromLanceDB()
  if (staleResult) {
    log.warn("using stale LanceDB data, remote unavailable")
    memoryCache = { registry: staleResult.registry, hash: staleResult.hash, timestamp: now }
    return { registry: staleResult.registry, hash: staleResult.hash, cacheStatus: "stale" }
  }

  // Final fallback — disk cache YAML
  const diskCache = await loadCacheFromDisk()
  if (diskCache) {
    log.warn("using YAML disk cache, remote and LanceDB both unavailable")
    const fallbackHash = await computeHash(JSON.stringify(diskCache))
    // Import to LanceDB so search works
    try {
      await importFromYAML(diskCache.tools, fallbackHash)
      _vectorsAvailable = null
    } catch { /* non-critical */ }
    memoryCache = { registry: diskCache, hash: fallbackHash, timestamp: now }
    return { registry: diskCache, hash: fallbackHash, cacheStatus: "stale" }
  }

  throw new Error("Registry unavailable. Check network connection and try 'opensploit update'.")
}

// =============================================================================
// Dynamic Recipe Merging
// =============================================================================

/**
 * Merge dynamic recipes from /session/tool_recipes/ into the registry.
 * This allows tool_registry_search to discover methods defined by the build
 * agent at runtime (e.g., impacket-dacledit recipe).
 *
 * Mutates registry.tools in place for efficiency.
 */
function mergeSessionRecipes(registry: Registry, sessionID: string): void {
  try {
    const rootSessionID = getRootSession(sessionID)
    const sessionDir = SessionDirectory.get(rootSessionID)
    const recipesDir = path.join(sessionDir, "tool_recipes")

    if (!existsSync(recipesDir)) return

    for (const toolDir of readdirSync(recipesDir)) {
      const toolPath = path.join(recipesDir, toolDir)
      try {
        if (!statSync(toolPath).isDirectory()) continue
      } catch {
        continue
      }

      // Only merge into tools that exist in the registry
      if (!registry.tools[toolDir]) continue

      for (const file of readdirSync(toolPath)) {
        if (!file.endsWith(".yaml") && !file.endsWith(".yml")) continue
        try {
          const content = readFileSync(path.join(toolPath, file), "utf-8")
          const recipe = yaml.load(content) as Record<string, any> | null
          if (!recipe || !recipe.name) continue

          // Don't override existing methods from the published registry
          if (registry.tools[toolDir].methods?.[recipe.name]) continue

          // Merge into registry
          if (!registry.tools[toolDir].methods) {
            registry.tools[toolDir].methods = {}
          }
          registry.tools[toolDir].methods[recipe.name] = {
            description: recipe.description || "",
            when_to_use: recipe.when_to_use || "",
            params: Object.fromEntries(
              Object.entries(recipe.params || {}).map(([k, v]: [string, any]) => [
                k,
                { type: v.type || "string", description: v.description || "" },
              ]),
            ),
          }
          log.debug("merged session recipe", { tool: toolDir, method: recipe.name })
        } catch {
          // Skip malformed recipe files silently
        }
      }
    }
  } catch {
    // Session directory may not exist yet — non-critical
  }
}

// =============================================================================
// Routing Bonus / Penalty Functions (kept from original)
// =============================================================================

/**
 * Bug Fix 1: Triggers should be matched as regex patterns
 * Doc 22 §Part 1, Bug 1 (lines 274-290)
 */
function calculateTriggerBonus(query: string, tool: RegistryTool): number {
  let bonus = 0
  const triggers = tool.routing?.triggers || []

  for (const trigger of triggers) {
    try {
      const regex = new RegExp(trigger, "i")
      if (regex.test(query)) {
        bonus += 35
        log.debug("trigger regex matched", { tool: tool.name, trigger, query })
      }
    } catch {
      log.debug("invalid trigger regex", { tool: tool.name, trigger })
    }
  }

  return bonus
}

/**
 * Bug Fix 2: use_for should receive bonus weighting
 * Doc 22 §Part 1, Bug 2 (lines 292-309)
 */
function calculateUseForBonus(query: string, tool: RegistryTool): number {
  let bonus = 0
  const queryLower = query.toLowerCase()
  const useForList = tool.routing?.use_for || []

  for (const useFor of useForList) {
    const useForLower = useFor.toLowerCase()

    if (queryLower.includes(useForLower)) {
      bonus += 8
    } else if (useForLower.includes(queryLower)) {
      bonus += 5
    } else {
      const useForWords = useForLower.split(/\s+/)
      const queryWords = queryLower.split(/\s+/)
      const overlap = useForWords.filter((w) =>
        queryWords.some((qw) => qw.startsWith(w) || w.startsWith(qw) || qw === w)
      )
      if (overlap.length >= 2) {
        bonus += 3
      }
    }
  }

  return bonus
}

/**
 * Bug Fix 3: never_use_for should penalize score
 * Doc 22 §Part 1, Bug 3 (lines 311-326)
 */
function calculateNeverUseForPenalty(query: string, tool: RegistryTool): number {
  let penalty = 0
  const queryLower = query.toLowerCase()
  const neverUseFor = tool.routing?.never_use_for || []

  for (const pattern of neverUseFor) {
    const task = typeof pattern === "string" ? pattern : pattern.task
    if (task && queryLower.includes(task.toLowerCase())) {
      penalty -= 15
    }
  }

  return penalty
}

function checkAntiPatterns(query: string, tool: RegistryTool): string | undefined {
  const neverUseFor = tool.routing?.never_use_for || []
  const queryLower = query.toLowerCase()

  for (const pattern of neverUseFor) {
    if (typeof pattern === "string") {
      if (queryLower.includes(pattern.toLowerCase())) {
        return `${tool.name} should not be used for "${pattern}"`
      }
    } else if (pattern.task && queryLower.includes(pattern.task.toLowerCase())) {
      const alternative = Array.isArray(pattern.use_instead) ? pattern.use_instead.join(" or ") : pattern.use_instead
      const reason = pattern.reason ? ` (${pattern.reason})` : ""
      return `${tool.name} should not be used for "${pattern.task}". Use ${alternative} instead${reason}.`
    }
  }

  return undefined
}

function normalizeNeverUseFor(entries: Array<string | NeverUseForEntry>): NeverUseForEntry[] {
  return entries.map((entry) => {
    if (typeof entry === "string") {
      return { task: entry, use_instead: "" }
    }
    return entry
  })
}

function extractSuggestedAlternatives(tool: RegistryTool): string[] {
  const alternatives = new Set<string>()

  for (const alt of tool.routing?.prefer_over || []) {
    alternatives.add(alt)
  }

  for (const entry of tool.routing?.never_use_for || []) {
    if (typeof entry !== "string" && entry.use_instead) {
      const useInstead = Array.isArray(entry.use_instead) ? entry.use_instead : [entry.use_instead]
      for (const alt of useInstead) {
        if (alt) alternatives.add(alt)
      }
    }
  }

  return Array.from(alternatives)
}

function formatToolResult(toolId: string, tool: RegistryTool, warning?: string): ToolResult {
  const methods: ToolMethodResult[] = []

  if (tool.methods) {
    for (const [methodName, method] of Object.entries(tool.methods)) {
      methods.push({
        name: methodName,
        description: method.description,
        when_to_use: method.when_to_use,
        next_step: method.next_step,
        params: method.params || {},
        returns: method.returns,
      })
    }
  }

  return {
    tool: toolId,
    name: tool.name,
    description: tool.description,
    image: tool.image,
    routing: {
      use_for: tool.routing?.use_for || [],
      triggers: tool.routing?.triggers,
      never_use_for: tool.routing?.never_use_for ? normalizeNeverUseFor(tool.routing.never_use_for) : undefined,
      prefer_over: tool.routing?.prefer_over,
    },
    suggested_alternatives: extractSuggestedAlternatives(tool),
    capabilities: tool.capabilities || [],
    phases: tool.phases || [],
    requirements: tool.requirements,
    methods,
    warning,
  }
}

/**
 * Format tool result with suggested method ordering.
 * Places the suggested method first in the methods list.
 */
function formatToolResultWithSuggestion(
  toolId: string,
  tool: RegistryTool,
  suggestedMethod: string,
  seeAlso: string[],
  warning?: string
): ToolResult {
  const result = formatToolResult(toolId, tool, warning)

  // Reorder methods so suggested is first
  if (suggestedMethod && result.methods.length > 1) {
    const suggestedIdx = result.methods.findIndex((m) => m.name === suggestedMethod)
    if (suggestedIdx > 0) {
      const [method] = result.methods.splice(suggestedIdx, 1)
      result.methods.unshift(method)
    }
  }

  // Mark suggested method
  result.suggested_method = suggestedMethod

  // Add see_also that aren't already in suggested_alternatives
  if (seeAlso.length > 0) {
    const existingAlts = new Set(result.suggested_alternatives ?? [])
    for (const toolRef of seeAlso) {
      if (!existingAlts.has(toolRef)) {
        result.suggested_alternatives = result.suggested_alternatives ?? []
        result.suggested_alternatives.push(toolRef)
      }
    }
  }

  return result
}

// =============================================================================
// Search Logic — LanceDB Hybrid Search
// =============================================================================

interface LocalScoredTool {
  toolId: string
  tool: RegistryTool
  score: number
  warning?: string
}

interface SearchToolsResult {
  results: ToolResult[]
  warnings: string[]
  scoredResults: Array<{ tool: string; score: number; description: string; suggestedMethod?: string }>
}

/**
 * Search tools using LanceDB method-level search with sparse re-scoring.
 *
 * Flow:
 * 1. Dense ANN retrieval on method_vector (over-fetch 8x for method grouping)
 * 2. Sparse re-scoring: dense * 0.6 + sparse * 0.4 per method
 * 3. Routing bonuses at tool level (trigger/use_for/never_use_for/phase)
 * 4. Group by tool: tool score = best method score + routing adjustment
 * 5. Return top N tools with suggested_method
 *
 * Falls back to FTS-only or in-memory when vectors unavailable.
 */
async function searchToolsLance(
  registry: Registry,
  query: string,
  phase?: string,
  capability?: string,
  limit: number = 5
): Promise<SearchToolsResult> {
  const warnings: string[] = []

  try {
    const db = await getConnection()
    const tables = await db.tableNames()

    if (!tables.includes(TOOLS_TABLE_NAME)) {
      return searchToolsInMemory(registry, query, phase, capability, limit)
    }

    const table = await db.openTable(TOOLS_TABLE_NAME)

    // Use cached value (reset on registry import)
    if (_vectorsAvailable === null) {
      _vectorsAvailable = await hasVectors()
    }
    const vectorsAvailable = _vectorsAvailable

    let rawResults: any[]
    let querySparse: Record<string, number> | null = null

    if (vectorsAvailable) {
      const embeddingService = getEmbeddingService()
      const embedding = await embeddingService.embed(query)
      const queryVector = embedding?.dense ?? null
      querySparse = embedding?.sparse ?? null

      if (queryVector) {
        // Dense ANN retrieval — over-fetch for method grouping
        // Use method_vector column name for v7.0 schema
        try {
          rawResults = await table
            .search(queryVector, "method_vector")
            .select(["id", "tool_id", "method_name", "tool_name", "tool_description",
                     "method_description", "when_to_use", "phases_json",
                     "capabilities_json", "routing_json", "methods_json", "raw_json",
                     "see_also_json", "sparse_json"])
            .limit(limit * 8)
            .toArray()
        } catch {
          // method_vector column may not exist (legacy v6.1) — try tool_vector
          try {
            rawResults = await table
              .search(queryVector, "tool_vector")
              .select(["id", "tool_id", "method_name", "tool_name", "tool_description",
                       "method_description", "when_to_use", "phases_json",
                       "capabilities_json", "routing_json", "methods_json", "raw_json",
                       "see_also_json", "sparse_json"])
              .limit(limit * 8)
              .toArray()
          } catch {
            // Fall back to unqualified search (LanceDB picks the vector column)
            rawResults = await table
              .search(queryVector)
              .select(["id", "tool_id", "method_name", "tool_name", "tool_description",
                       "method_description", "when_to_use", "phases_json",
                       "capabilities_json", "routing_json", "methods_json", "raw_json",
                       "see_also_json", "sparse_json"])
              .limit(limit * 8)
              .toArray()
          }
        }
      } else {
        // Embedding unavailable — FTS only
        log.warn("embedding unavailable for tool search, using FTS-only")
        rawResults = await searchFTSOnly(table, query, limit * 8)
      }
    } else {
      // No vectors (YAML import) — FTS only on method-level search_text
      rawResults = await searchFTSOnly(table, query, limit * 8)
    }

    // Score and group methods by tool
    const toolsWithMethods = scoreAndGroupMethods(
      rawResults, registry, query, phase, capability, querySparse, warnings
    )

    // Sort by tool score
    toolsWithMethods.sort((a, b) => b.score - a.score)

    // Take top results
    const topResults = toolsWithMethods.slice(0, limit)

    log.debug("method-level search scores", {
      query,
      phase,
      hybrid: vectorsAvailable,
      topResults: topResults.slice(0, 5).map((t) => ({
        tool: t.toolId,
        suggested: t.suggestedMethod,
        score: t.score.toFixed(3),
      })),
    })

    const formattedResults = topResults.map((twm) =>
      formatToolResultWithSuggestion(twm.toolId, twm.tool, twm.suggestedMethod, twm.seeAlso, twm.warning)
    )
    const scoredResults = topResults.map((twm) => ({
      tool: twm.toolId,
      score: twm.score,
      description: twm.tool.description,
      suggestedMethod: twm.suggestedMethod,
    }))

    return { results: formattedResults, warnings: [...new Set(warnings)], scoredResults }
  } catch (error) {
    log.warn("LanceDB search failed, falling back to in-memory", { error: String(error) })
    return searchToolsInMemory(registry, query, phase, capability, limit)
  }
}

/**
 * Score method-level results and group by tool.
 *
 * For each method row:
 * 1. Compute combined score: dense * 0.6 + sparse * 0.4
 * 2. Apply routing bonuses (once per tool, shared across methods)
 * 3. Group methods by tool_id
 * 4. Tool score = best method combined score + routing adjustment
 */
function scoreAndGroupMethods(
  results: any[],
  registry: Registry,
  query: string,
  phase: string | undefined,
  capability: string | undefined,
  querySparse: Record<string, number> | null,
  warnings: string[]
): ToolWithMethods[] {
  // Group method rows by tool_id
  const toolGroups = new Map<string, {
    methods: ScoredMethod[]
    tool: RegistryTool
    routing: number
    warning?: string
    seeAlso: string[]
  }>()

  for (const row of results) {
    // Method-level rows have tool_id; legacy tool-level rows use id
    const toolId = (row.tool_id ?? row.id) as string
    const methodName = (row.method_name ?? "default") as string
    const tool = registry.tools[toolId]
    if (!tool) continue

    // Capability filter
    if (capability && !tool.capabilities?.includes(capability)) continue

    // Dense score from LanceDB
    let denseScore = 0
    if (row._distance != null) {
      // Vector distance → similarity (cosine: lower = more similar)
      denseScore = 1 / (1 + row._distance)
    } else if (row._score != null) {
      // FTS BM25 score — normalize to 0-1 range
      denseScore = Math.min(row._score / 20, 1)
    } else {
      denseScore = 0.05
    }

    // Sparse re-scoring
    let sparseScore = 0
    if (querySparse && row.sparse_json) {
      const docSparse = parseSparseJson(row.sparse_json as string)
      sparseScore = sparseCosineSimilarity(querySparse, docSparse)
    }

    // Combined method score: dense * 0.6 + sparse * 0.4 (BGE-M3 paper default)
    const methodScore = querySparse
      ? (denseScore * 0.6 + sparseScore * 0.4)
      : denseScore

    const method: ScoredMethod = {
      toolId,
      methodName,
      methodDescription: (row.method_description ?? row.description ?? "") as string,
      whenToUse: (row.when_to_use ?? "") as string,
      score: methodScore,
    }

    if (!toolGroups.has(toolId)) {
      // Compute routing bonuses once per tool
      const triggerBonus = calculateTriggerBonus(query, tool)
      const useForBonus = calculateUseForBonus(query, tool)
      const neverUseForPenalty = calculateNeverUseForPenalty(query, tool)
      const phaseBonus = (phase && tool.phases?.includes(phase)) ? 0.15 : 0

      // Normalize bonuses to 0-1 range instead of raw +35/-15
      const routingAdjustment = Math.min(
        (triggerBonus / 35 * 0.3) + (useForBonus / 8 * 0.15) + (neverUseForPenalty / 15 * 0.2) + phaseBonus,
        0.5
      )

      const antiPatternWarning = checkAntiPatterns(query, tool)
      if (antiPatternWarning) warnings.push(antiPatternWarning)

      // Parse see_also from row or tool
      let seeAlso: string[] = []
      try {
        if (row.see_also_json) {
          seeAlso = JSON.parse(row.see_also_json as string)
        } else if ((tool as any).see_also) {
          seeAlso = (tool as any).see_also
        }
      } catch { /* ignore */ }

      toolGroups.set(toolId, {
        methods: [],
        tool,
        routing: routingAdjustment,
        warning: antiPatternWarning,
        seeAlso,
      })
    }

    toolGroups.get(toolId)!.methods.push(method)
  }

  // Build ToolWithMethods from groups
  const toolResults: ToolWithMethods[] = []

  for (const [toolId, group] of toolGroups) {
    // Sort methods by score descending
    group.methods.sort((a, b) => b.score - a.score)

    const bestMethod = group.methods[0]
    const toolScore = bestMethod.score + group.routing

    if (toolScore > 0) {
      toolResults.push({
        toolId,
        tool: group.tool,
        score: toolScore,
        suggestedMethod: bestMethod.methodName,
        suggestedMethodDescription: bestMethod.methodDescription,
        rankedMethods: group.methods,
        warning: group.warning,
        seeAlso: group.seeAlso,
      })
    }
  }

  return toolResults
}

/**
 * FTS-only search on the method-level tools table.
 */
async function searchFTSOnly(table: lancedb.Table, query: string, limit: number): Promise<any[]> {
  const selectColumns = ["id", "tool_id", "method_name", "tool_name", "tool_description",
                         "method_description", "when_to_use", "phases_json",
                         "capabilities_json", "routing_json", "methods_json", "raw_json",
                         "see_also_json", "sparse_json"]
  try {
    return await table
      .search(query, "fts")
      .select(selectColumns)
      .limit(limit)
      .toArray()
  } catch (error) {
    // FTS index may not exist — fall back to full scan
    log.warn("FTS search failed, using full scan", { error: String(error) })
    return await table.query()
      .select(selectColumns)
      .limit(10000)
      .toArray()
  }
}

/**
 * In-memory fallback search (when LanceDB is completely unavailable).
 * Uses the original keyword matching algorithm.
 */
function searchToolsInMemory(
  registry: Registry,
  query: string,
  phase?: string,
  capability?: string,
  limit: number = 5
): SearchToolsResult {
  const scoredTools: LocalScoredTool[] = []
  const warnings: string[] = []

  for (const [toolId, tool] of Object.entries(registry.tools)) {
    if (capability && !tool.capabilities?.includes(capability)) {
      continue
    }

    // Simple keyword matching
    const searchText = [
      tool.name, tool.description,
      ...(tool.capabilities || []),
    ].join(" ").toLowerCase()

    const queryWords = query.toLowerCase().split(/\s+/).filter((w) => w.length > 1)
    let score = 0
    for (const word of queryWords) {
      const regex = new RegExp(`\\b${word}\\b`, "g")
      score += (searchText.match(regex) || []).length * 3
      if (searchText.includes(word)) score += 1
    }
    if (searchText.includes(query.toLowerCase())) score += 5

    // Routing bonuses
    score += calculateTriggerBonus(query, tool)
    score += calculateUseForBonus(query, tool)
    score += calculateNeverUseForPenalty(query, tool)

    if (phase && tool.phases?.includes(phase)) {
      score += 5
    }

    const antiPatternWarning = checkAntiPatterns(query, tool)
    if (antiPatternWarning) warnings.push(antiPatternWarning)

    if (score > 0) {
      scoredTools.push({ toolId, tool, score, warning: antiPatternWarning })
    }
  }

  scoredTools.sort((a, b) => b.score - a.score)

  const topScoredTools = scoredTools.slice(0, limit)
  const results = topScoredTools.map((st) => formatToolResult(st.toolId, st.tool, st.warning))
  const scoredResults = topScoredTools.map((st) => ({
    tool: st.toolId,
    score: st.score,
    description: st.tool.description,
  }))

  return { results, warnings: [...new Set(warnings)], scoredResults }
}

// =============================================================================
// Output Formatting
// =============================================================================

function formatOutput(result: ToolSearchResult): string {
  const lines: string[] = []

  lines.push(`# Tool Registry Search Results`)
  lines.push(``)
  lines.push(`**Query:** ${result.query}`)
  if (result.phase) lines.push(`**Phase Filter:** ${result.phase}`)
  if (result.capability) lines.push(`**Capability Filter:** ${result.capability}`)
  lines.push(`**Results:** ${result.results.length} tools found`)
  lines.push(`**Registry Hash:** ${result.registry_hash.slice(0, 16)}...`)
  if (result.cache_status === "stale") {
    lines.push(`**Warning:** Using cached registry. Run 'opensploit update' to refresh.`)
  }
  lines.push(``)

  if (result.anti_pattern_warnings.length > 0) {
    lines.push(`## Warnings`)
    for (const warning of result.anti_pattern_warnings) {
      lines.push(`- ⚠️ ${warning}`)
    }
    lines.push(``)
  }

  if (result.results.length === 0) {
    lines.push(`No tools found matching your query. Try different keywords or remove filters.`)
    lines.push(``)
    lines.push(`**Valid phases:** ${VALID_PHASES.join(", ")}`)
    return lines.join("\n")
  }

  lines.push(`---`)
  lines.push(``)

  for (const tool of result.results) {
    lines.push(`## ${tool.name}${tool.warning ? " ⚠️" : ""}`)
    lines.push(``)
    lines.push(`${tool.description}`)
    lines.push(``)

    // Show suggested method prominently when available
    if (tool.suggested_method && tool.suggested_method !== "default") {
      const suggestedMethodDef = tool.methods.find((m) => m.name === tool.suggested_method)
      if (suggestedMethodDef) {
        lines.push(`> **Suggested method:** \`${tool.suggested_method}\` — ${suggestedMethodDef.description}`)
        lines.push(``)
      }
    }

    if (tool.warning) {
      lines.push(`> **Warning:** ${tool.warning}`)
      lines.push(``)
    }

    lines.push(`- **Tool ID:** \`${tool.tool}\``)
    if (tool.image) lines.push(`- **Image:** \`${tool.image}\``)
    lines.push(`- **Phases:** ${tool.phases.join(", ") || "any"}`)
    lines.push(`- **Capabilities:** ${tool.capabilities.join(", ") || "general"}`)

    if (tool.requirements) {
      const reqs: string[] = []
      if (tool.requirements.network) reqs.push("network")
      if (tool.requirements.privileged) {
        reqs.push(`privileged${tool.requirements.privileged_reason ? ` (${tool.requirements.privileged_reason})` : ""}`)
      }
      if (reqs.length > 0) {
        lines.push(`- **Requirements:** ${reqs.join(", ")}`)
      }
    }

    if (tool.routing.use_for && tool.routing.use_for.length > 0) {
      lines.push(`- **Use for:** ${tool.routing.use_for.join(", ")}`)
    }

    if (tool.suggested_alternatives && tool.suggested_alternatives.length > 0) {
      lines.push(`- **See also:** ${tool.suggested_alternatives.join(", ")}`)
    }

    if (tool.methods.length > 0) {
      lines.push(``)
      lines.push(`### Methods`)
      lines.push(``)

      for (const method of tool.methods) {
        lines.push(`#### \`${method.name}\``)
        lines.push(``)
        lines.push(`${method.description}`)
        if (method.when_to_use) {
          lines.push(``)
          lines.push(`*When to use:* ${method.when_to_use}`)
        }

        if (method.params && Object.keys(method.params).length > 0) {
          lines.push(``)
          lines.push(`**Parameters:**`)
          for (const [paramName, param] of Object.entries(method.params)) {
            const required = param.required ? " (required)" : ""
            const defaultVal = param.default !== undefined ? ` [default: ${param.default}]` : ""
            lines.push(`- \`${paramName}\`${required}: ${param.description || param.type}${defaultVal}`)
          }
        }

        if (method.returns && Object.keys(method.returns).length > 0) {
          lines.push(``)
          lines.push(`**Returns:**`)
          for (const [returnName, ret] of Object.entries(method.returns)) {
            lines.push(`- \`${returnName}\`: ${ret.description || ret.type}`)
          }
        }

        if (method.next_step) {
          lines.push(``)
          lines.push(`*Next step:* ${method.next_step}`)
        }

        lines.push(``)
      }
    }

    lines.push(`---`)
    lines.push(``)
  }

  lines.push(`*To use a tool, invoke it via MCP with the tool ID and method name.*`)

  return lines.join("\n")
}

// =============================================================================
// Tool Definition
// =============================================================================

// =============================================================================
// Exports for testing
// =============================================================================

export {
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
  RegistrySchema,
  RegistryToolSchema,
  VALID_PHASES,
  REGISTRY_CONFIG,
}
export type {
  Registry,
  RegistryTool,
  ToolResult,
  ToolSearchResult,
  ToolMethodResult,
  NeverUseForEntry,
  ToolWithMethods,
  ScoredMethod,
}

export function createToolRegistrySearchTool() {
  return tool({
    description: DESCRIPTION,
    args: {
      query: z.string().describe("Natural language query to search for tools (e.g., 'port scanning', 'SQL injection')"),
      phase: z
        .enum(VALID_PHASES)
        .optional()
        .describe("Filter by security phase: reconnaissance, enumeration, exploitation, post-exploitation"),
      capability: z
        .string()
        .optional()
        .describe("Filter by specific capability (e.g., 'sql_injection', 'port_scanning', 'web_fuzzing')"),
      limit: z.number().optional().default(5).describe("Maximum number of results to return (default: 5)"),
      explain: z.boolean().optional().default(false).describe("Include detailed score breakdown for debugging ranking decisions"),
    },
    async execute(params, ctx: ToolContext): Promise<string> {
      const { query, phase, capability, limit = 5, explain = false } = params

      log.info("searching tool registry", { query, phase, capability, limit, explain })

      // Get registry with hash-based freshness
      const { registry, hash, cacheStatus } = await getRegistry()

      // Merge dynamic recipes from /session/tool_recipes/ into registry
      mergeSessionRecipes(registry, ctx.sessionID)

      // Search tools via LanceDB hybrid search
      const { results, warnings, scoredResults } = await searchToolsLance(registry, query, phase, capability, limit)

      // Update tool context for experience tracking
      try {
        const searchResultsForContext: SearchResult[] = scoredResults.map((sr) => ({
          tool: sr.tool,
          score: sr.score,
          description: sr.description,
        }))
        updateSearchContext(ctx.sessionID, query, searchResultsForContext)
      } catch (error) {
        log.warn("failed to update search context", { error: String(error) })
      }

      // Build result
      const searchResult: ToolSearchResult = {
        query,
        phase,
        capability,
        results,
        anti_pattern_warnings: warnings,
        registry_hash: hash,
        cache_status: cacheStatus,
      }

      // Format base output
      let output = formatOutput(searchResult)

      // Phase 5: Unified Search with experiences and insights
      try {
        const toolContext = getToolContext(ctx.sessionID)
        const scoredToolsForUnified: ScoredTool[] = scoredResults.map((sr) => {
          const fullResult = results.find((r) => r.tool === sr.tool)
          return {
            id: sr.tool,
            name: fullResult?.name ?? sr.tool,
            score: sr.score,
            description: sr.description,
            phases: fullResult?.phases,
            capabilities: fullResult?.capabilities,
            suggestedMethod: sr.suggestedMethod,
            routing: fullResult?.routing
              ? {
                  use_for: fullResult.routing.use_for,
                  triggers: fullResult.routing.triggers,
                  never_use_for: fullResult.routing.never_use_for,
                }
              : undefined,
          }
        })

        const searchContext: SearchContext = {
          phase: toolContext?.currentPhase ?? phase,
          toolsTried: toolContext?.toolsTried,
          recentSuccesses: toolContext?.recentSuccesses,
        }

        const unifiedResult = await unifiedSearch(query, scoredToolsForUnified, searchContext, explain)

        const memoryOutput = formatUnifiedResults(unifiedResult)
        if (memoryOutput.trim()) {
          output += "\n" + memoryOutput
        }
      } catch (error) {
        log.warn("unified search failed, returning tool-only results", { error: String(error) })
      }

      // Cache results in engagement state for cross-agent dedup (RC6)
      try {
        const rootId = getRootSession(ctx.sessionID)
        const { loadEngagementState, mergeState: mergeEngState, saveEngagementState } = await import("./engagement-state")
        const state = await loadEngagementState(rootId).catch(() => ({}))
        if (Object.keys(state).length > 0) {
          await saveEngagementState(rootId, mergeEngState(state as any, {
            toolSearchCache: [{
              query,
              phase,
              results: scoredResults.slice(0, 3).map((r: any) => ({
                tool: r.tool,
                method: r.suggestedMethod,
              })),
              timestamp: new Date().toISOString(),
            }],
          }))
        }
      } catch { /* non-critical */ }

      // Set metadata for TUI display
      ctx.metadata({
        title: `Tool search: ${query} (${results.length} results)`,
        metadata: {
          query,
          phase,
          capability,
          results_count: results.length,
          registry_hash: hash,
          cache_status: cacheStatus,
          warnings: warnings.length > 0 ? warnings : undefined,
        },
      })

      return output
    },
  })
}
