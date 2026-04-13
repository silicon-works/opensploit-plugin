/**
 * Pattern Learning Module
 *
 * Implements Doc 13 - Strategic layer for attack pattern learning.
 *
 * This module provides:
 * - Pattern search: Find similar successful attack methodologies
 * - Pattern capture: Extract patterns from successful engagements (Phase 3)
 * - Anonymization: Remove PII before storage (Phase 4)
 *
 * Key distinction (Doc 13 §lines 38-46):
 * - Document 22 (Tactical): "I need to scan ports" → Tool recommendation
 * - Document 13 (Strategic): "Linux with HTTP+SSH, what worked?" → Attack methodology
 */

// Pattern search (Phase 2)
export {
  // Types
  type PatternQuery,
  type PatternSearchResult,
  // Functions
  searchPatterns,
  formatQueryForEmbedding,
  formatPatternForEmbedding,
  formatPatternResults,
} from "./search"

// Pattern capture (Phase 3)
export {
  // Types
  type CaptureOptions,
  type CaptureResult,
  // Functions
  capturePattern,
  checkAutoCapturePattern,
} from "./capture"

// Pattern extraction helpers (Phase 3)
export {
  detectOS,
  extractTechnologies,
  inferCharacteristics,
  deriveVulnType,
  severityToScore,
  extractPrimaryVulnerability,
  detectPivotalSteps,
  generateMethodologySummary,
  extractPhases,
  extractToolSequence,
  extractInsights,
  calculateDuration,
} from "./extract"

// Anonymization (Phase 4)
export {
  // Types
  type AnonymizeOptions,
  // Functions
  anonymizeText,
  anonymizePattern,
  containsSensitiveData,
  getAnonymizationStats,
} from "./anonymize"
