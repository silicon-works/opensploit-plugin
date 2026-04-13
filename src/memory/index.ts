/**
 * Memory System Module
 *
 * Implements Doc 22 §Part 4-6 - LanceDB-based memory for tool selection learning
 * Extended by Doc 13 - Pattern learning for attack methodologies
 *
 * Usage:
 *   import { initializeMemorySystem, getEmbeddingService } from "./memory"
 *
 * The memory system stores:
 * - Experiences: Records of tool executions and outcomes (Doc 22)
 * - Insights: Extracted rules from experience patterns (Doc 22)
 * - Patterns: Successful attack methodologies for learning (Doc 13)
 *
 * Embedding service provides:
 * - Dense embeddings (1024 dims) for vector search
 * - Sparse embeddings for hybrid scoring
 * - On-demand startup (saves RAM when not pentesting)
 * - Fallback to keyword-only when unavailable
 */

// Database connection and initialization
export {
  OPENSPLOIT_LANCE_PATH,
  initializeMemorySystem,
  getConnection,
  closeConnection,
  getExperiencesTable,
  getInsightsTable,
  getPatternsTable,
  getToolsTable,
  getMemoryStatus,
  resetMemorySystem,
} from "./database"

// Schema definitions and types
export {
  // Types
  type Experience,
  type Insight,
  type AttackPhase,
  type AttackPattern,
  type MemoryMetadata,
  type MethodRow,
  // Apache Arrow schemas
  experienceSchema,
  insightSchema,
  patternSchema,
  // ID generators
  generateExperienceId,
  generateInsightId,
  generatePatternId,
  // Factory functions (handle LanceDB nullable field limitations)
  createExperience,
  createInsight,
  createPattern,
  parsePattern,
  // Constants
  VECTOR_DIMENSIONS,
  EXPERIENCE_DEDUP_THRESHOLD,
  INSIGHT_DEDUP_THRESHOLD,
  PATTERN_DEDUP_THRESHOLD,
} from "./schema"

// Embedding service
export {
  EmbeddingService,
  getEmbeddingService,
  shutdownEmbeddingService,
  type EmbeddingResult,
} from "./embedding"

// Tool context (session-scoped state)
export {
  type ToolContext,
  type PreviousFailure,
  type SearchResult,
  createToolContext,
  getToolContext,
  updateSearchContext,
  recordToolTried,
  recordToolSuccess,
  recordToolFailure,
  clearPreviousFailure,
  getPreviousFailure,
  setCurrentPhase,
  clearToolContext,
  stopCleanupInterval,
  getContextSummary,
} from "./context"

// Experience recording
export {
  type ToolResult,
  type ToolParams,
  type RecordExperienceResult,
  recordExperience,
  evaluateSuccess,
  detectFailureReason,
  summarizeResult,
  formatExperienceForEmbedding,
  inferCharacteristics,
  getExperiencesByTool,
  getRecentExperiences,
  searchExperiences,
  getRecoveryPatterns,
} from "./experience"

// Unified search (Phase 5 + Cross-Table Architecture)
export {
  type ScoredTool,
  type ScoredExperience,
  type ScoredInsight,
  type RankedItem,
  type ResultType,
  type SearchContext,
  type UnifiedSearchResult,
  type AnnotatedToolResult,
  type ExperienceAnnotation,
  type InsightAnnotation,
  searchExperiencesLance,
  searchInsightsLance,
  reciprocalRankFusion,
  formatExplanation,
  formatExperienceForDisplay,
  formatInsightForDisplay,
  unifiedSearch,
  formatUnifiedResults,
} from "./search"

// Tool registry storage (LanceDB with hybrid search support)
export {
  type ToolRow,
  toolSchema,
  TOOLS_TABLE_NAME,
  importFromLance,
  importFromYAML,
  loadRegistry as loadToolsFromLanceDB,
  getStoredHash,
  needsUpdate as toolsNeedUpdate,
  hasVectors as toolsHaveVectors,
  buildMethodSearchText,
} from "./tools"

// Sparse vector scoring utilities
export {
  type SparseVector,
  sparseDotProduct,
  sparseCosineSimilarity,
  parseSparseJson,
  serializeSparse,
} from "./sparse"

// Insight extraction and management (Phase 6)
export {
  // Types
  type RecoveryPattern,
  type ExportedBatch,
  type InsightSuggestion,
  type ImportedInsights,
  type ConfidenceUpdateResult,
  type DecayResult,
  // Constants
  PENDING_ANALYSIS_DIR,
  MIN_PATTERN_OCCURRENCES,
  CONFIDENCE_INITIAL,
  CONFIDENCE_REINFORCE_DELTA,
  CONFIDENCE_CONTRADICT_DELTA,
  CONFIDENCE_MIN,
  CONFIDENCE_MAX,
  CONFIDENCE_DELETE_THRESHOLD,
  CONTRADICTIONS_DELETE_THRESHOLD,
  DECAY_FACTOR,
  DECAY_INTERVAL_MS,
  // Export/Import functions
  exportForAnalysis,
  getAnalysisPrompt,
  importInsights,
  // Confidence management
  patternReinforcesInsight,
  updateInsightConfidences,
  applyConfidenceDecay,
  // Automated insight generation
  autoConvertRecoveryToInsights,
  preSeedInsightsFromRegistry,
  // Query functions
  getAllInsights,
  getInsightsForTool,
  getPendingAnalysisFiles,
  deletePendingAnalysisFile,
} from "./insight"
