/**
 * Sparse Vector Scoring Utilities
 *
 * BGE-M3 produces learned sparse vectors (token weights) alongside dense
 * embeddings. These are more effective than BM25 for semantic matching
 * because the weights are learned, not just frequency-based.
 *
 * Sparse vectors are stored as JSON Record<string, number> where keys
 * are token IDs and values are learned weights.
 */

/** Sparse vector type: token ID → learned weight */
export type SparseVector = Record<string, number>

/**
 * Compute dot product of two sparse vectors.
 *
 * Only iterates over the smaller vector's keys, making this
 * O(min(|a|, |b|)) rather than O(|a| + |b|).
 */
export function sparseDotProduct(a: SparseVector, b: SparseVector): number {
  // Iterate over the smaller vector for efficiency
  const [smaller, larger] = Object.keys(a).length <= Object.keys(b).length
    ? [a, b]
    : [b, a]

  let dot = 0
  for (const key in smaller) {
    if (key in larger) {
      dot += smaller[key] * larger[key]
    }
  }
  return dot
}

/**
 * Compute magnitude (L2 norm) of a sparse vector.
 */
function sparseMagnitude(v: SparseVector): number {
  let sum = 0
  for (const key in v) {
    sum += v[key] * v[key]
  }
  return Math.sqrt(sum)
}

/**
 * Compute cosine similarity between two sparse vectors.
 *
 * Returns a value in [0, 1] (BGE-M3 sparse weights are non-negative).
 * Returns 0 if either vector is empty or has zero magnitude.
 */
export function sparseCosineSimilarity(a: SparseVector, b: SparseVector): number {
  const dot = sparseDotProduct(a, b)
  if (dot === 0) return 0

  const magA = sparseMagnitude(a)
  const magB = sparseMagnitude(b)

  if (magA === 0 || magB === 0) return 0

  return dot / (magA * magB)
}

/**
 * Parse sparse vector from JSON string.
 *
 * Returns empty object on parse failure (safe for missing/corrupt data).
 */
export function parseSparseJson(json: string | null | undefined): SparseVector {
  if (!json) return {}
  try {
    const parsed = JSON.parse(json)
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      return {}
    }
    return parsed as SparseVector
  } catch {
    return {}
  }
}

/**
 * Serialize sparse vector to JSON string.
 */
export function serializeSparse(sparse: SparseVector | null | undefined): string {
  if (!sparse || Object.keys(sparse).length === 0) return ""
  return JSON.stringify(sparse)
}
