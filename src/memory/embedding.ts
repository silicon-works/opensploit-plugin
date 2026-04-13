/**
 * Embedding Service
 *
 * Implements Doc 22 §Part 5 (lines 1256-1366)
 *
 * Manages the BGE-M3 embedding MCP server lifecycle:
 * - On-demand startup (saves ~1.5-2GB RAM when not pentesting)
 * - Periodic health checks for long-running sessions
 * - Fallback to keyword-only search when unavailable
 *
 * The embedding server produces:
 * - Dense embeddings (1024 dimensions) - stored in LanceDB for vector search
 * - Sparse embeddings (token weights) - for hybrid search scoring
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js"
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js"
import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js"
import { VECTOR_DIMENSIONS } from "./schema"

/** Embedding result with both dense and sparse vectors */
export interface EmbeddingResult {
  /** Dense embedding vector (1024 dimensions for BGE-M3) */
  dense: number[]
  /** Sparse embedding as token -> weight mapping */
  sparse: Record<string, number>
}

/** Response structure from embed tool */
interface EmbedResponse {
  dense: number[][]
  sparse?: Record<string, number>[]
  dimensions: number
  count: number
}

/** Response structure from health tool */
interface HealthResponse {
  status: "ok" | "error"
  model: string
  dimensions: number
  hybrid: boolean
}

/** Configuration constants */
const CONFIG = {
  /** Docker image for embedding server */
  DOCKER_IMAGE: "ghcr.io/silicon-works/mcp-tools-embedding:latest",
  /** Memory limit for Docker container (BGE-M3 FP16 needs ~2.5GB during loading) */
  DOCKER_MEMORY: "3g",
  /** Connection timeout in milliseconds */
  CONNECT_TIMEOUT_MS: 60_000,
  /** Tool call timeout in milliseconds */
  CALL_TIMEOUT_MS: 30_000,
  /** Health check interval in milliseconds */
  HEALTH_CHECK_INTERVAL_MS: 60_000,
} as const

/**
 * Embedding Service - manages BGE-M3 MCP server lifecycle
 *
 * Uses the official MCP SDK client for protocol handling.
 *
 * Usage:
 *   const embedding = await embeddingService.embed("scan open ports")
 *   if (embedding) {
 *     // Use embedding.dense for LanceDB storage
 *     // Use embedding.sparse for hybrid scoring
 *   } else {
 *     // Fallback to keyword-only search
 *   }
 */
export class EmbeddingService {
  private client: Client | null = null
  private transport: StdioClientTransport | null = null
  private serverAvailable: boolean = false
  private lastHealthCheck: number = 0
  private startupPromise: Promise<void> | null = null

  /**
   * Generate embedding for text.
   *
   * Returns both dense and sparse embeddings from BGE-M3.
   * - Dense embeddings (1024 dims) are stored in LanceDB for vector search
   * - Sparse embeddings are returned for hybrid scoring but NOT stored
   * - LanceDB's native FTS provides keyword matching instead of sparse vectors
   *
   * @param text - Text to embed (query, experience summary, etc.)
   * @returns EmbeddingResult or null if embedding unavailable (fallback to keyword search)
   */
  async embed(text: string): Promise<EmbeddingResult | null> {
    // Start server on first use
    if (!this.client) {
      await this.ensureServerStarted()
    }

    // Periodic health check for long-running sessions
    await this.checkHealthIfNeeded()

    if (!this.serverAvailable) {
      return null // Fallback to keyword-only search
    }

    try {
      const response = await this.callTool<EmbedResponse>("embed", {
        texts: [text],
        return_sparse: true,
      })

      if (!response) {
        return null
      }

      return {
        dense: response.dense[0],
        sparse: response.sparse?.[0] || {},
      }
    } catch (error) {
      console.error("Embedding failed:", error)
      this.serverAvailable = false
      return null
    }
  }

  /**
   * Convenience method for storage - returns only dense embeddings.
   *
   * Use this when storing to LanceDB (which only stores the dense vector).
   * Returns a zero vector if embedding is unavailable.
   */
  async embedForStorage(text: string): Promise<number[]> {
    const result = await this.embed(text)
    return result?.dense ?? Array(VECTOR_DIMENSIONS).fill(0)
  }

  /**
   * Batch embed multiple texts.
   *
   * More efficient than calling embed() multiple times.
   */
  async embedBatch(texts: string[]): Promise<Array<EmbeddingResult | null>> {
    if (texts.length === 0) return []

    // Start server on first use
    if (!this.client) {
      await this.ensureServerStarted()
    }

    // Periodic health check for long-running sessions
    await this.checkHealthIfNeeded()

    if (!this.serverAvailable) {
      return texts.map(() => null)
    }

    try {
      const response = await this.callTool<EmbedResponse>("embed", {
        texts,
        return_sparse: true,
      })

      if (!response) {
        return texts.map(() => null)
      }

      return texts.map((_, i) => ({
        dense: response.dense[i],
        sparse: response.sparse?.[i] || {},
      }))
    } catch (error) {
      console.error("Batch embedding failed:", error)
      return texts.map(() => null)
    }
  }

  /**
   * Check if the embedding server is available.
   *
   * Use this to determine whether to use semantic search or fallback to keyword search.
   */
  async isAvailable(): Promise<boolean> {
    if (!this.client) {
      return false
    }

    await this.checkHealthIfNeeded()
    return this.serverAvailable
  }

  /**
   * Shutdown the embedding server.
   *
   * Gracefully closes the MCP client and terminates the Docker container.
   */
  async shutdown(): Promise<void> {
    if (this.client) {
      try {
        await this.client.close()
      } catch (error) {
        console.error("Error closing MCP client:", error)
      }
      this.client = null
    }

    if (this.transport) {
      try {
        await this.transport.close()
      } catch (error) {
        console.error("Error closing transport:", error)
      }
      this.transport = null
    }

    this.serverAvailable = false
    console.log("Embedding server stopped")
  }

  /**
   * Ensure the server is started (idempotent).
   */
  private async ensureServerStarted(): Promise<void> {
    if (this.client) return

    // Prevent multiple concurrent startups
    if (this.startupPromise) {
      await this.startupPromise
      return
    }

    this.startupPromise = this.startServer()
    try {
      await this.startupPromise
    } finally {
      this.startupPromise = null
    }
  }

  /**
   * Start the embedding MCP server via Docker.
   */
  private async startServer(): Promise<void> {
    console.log("Starting embedding MCP server (first use)...")

    try {
      // Create stdio transport to Docker container
      this.transport = new StdioClientTransport({
        command: "docker",
        args: [
          "run",
          "--rm",
          "-i",
          `--memory=${CONFIG.DOCKER_MEMORY}`,
          CONFIG.DOCKER_IMAGE,
        ],
        stderr: "pipe", // Capture stderr for debugging
      })

      // Create MCP client
      this.client = new Client({
        name: "opensploit-embedding",
        version: "1.0.0",
      })

      // Connect with timeout
      await this.withTimeout(
        this.client.connect(this.transport),
        CONFIG.CONNECT_TIMEOUT_MS,
        "MCP connection timeout"
      )

      // Verify server is healthy
      const healthy = await this.checkHealth()
      if (!healthy) {
        throw new Error("Server health check failed after connection")
      }

      this.serverAvailable = true
      this.lastHealthCheck = Date.now()
      console.log("Embedding server ready")

    } catch (error) {
      // Clean up on failure
      await this.shutdown()
      throw error
    }
  }

  /**
   * Call an MCP tool and parse the JSON response.
   */
  private async callTool<T>(
    name: string,
    args: Record<string, unknown>
  ): Promise<T | null> {
    if (!this.client) {
      throw new Error("Client not connected")
    }

    try {
      const result = await this.client.callTool(
        { name, arguments: args },
        CallToolResultSchema,
        { timeout: CONFIG.CALL_TIMEOUT_MS }
      )

      // Type the content array properly
      const content = result.content as Array<{ type: string; text?: string }>

      // Check for tool error
      if (result.isError) {
        const errorText = content?.[0]?.type === "text"
          ? content[0].text
          : "Unknown error"
        console.error(`Tool ${name} error:`, errorText)
        return null
      }

      // Parse JSON from text content
      const textContent = content?.find((c) => c.type === "text")
      if (!textContent || !textContent.text) {
        console.error(`Tool ${name} returned no text content`)
        return null
      }

      return JSON.parse(textContent.text) as T

    } catch (error) {
      console.error(`Tool ${name} call failed:`, error)
      throw error
    }
  }

  /**
   * Check server health if interval has passed.
   */
  private async checkHealthIfNeeded(): Promise<void> {
    if (
      this.serverAvailable &&
      Date.now() - this.lastHealthCheck > CONFIG.HEALTH_CHECK_INTERVAL_MS
    ) {
      this.serverAvailable = await this.checkHealth()
      this.lastHealthCheck = Date.now()
    }
  }

  /**
   * Check server health.
   */
  private async checkHealth(): Promise<boolean> {
    try {
      const response = await this.callTool<HealthResponse>("health", {})
      return response?.status === "ok"
    } catch {
      return false
    }
  }

  /**
   * Promise timeout utility.
   */
  private async withTimeout<T>(
    promise: Promise<T>,
    ms: number,
    message: string
  ): Promise<T> {
    let timeoutId: ReturnType<typeof setTimeout>

    const timeoutPromise = new Promise<never>((_, reject) => {
      timeoutId = setTimeout(() => reject(new Error(message)), ms)
    })

    try {
      return await Promise.race([promise, timeoutPromise])
    } finally {
      clearTimeout(timeoutId!)
    }
  }
}

// Singleton instance
let _embeddingService: EmbeddingService | null = null

/**
 * Get the singleton EmbeddingService instance.
 *
 * The service starts the embedding server on first embed() call,
 * not at application startup (saves ~1.5-2GB RAM when not pentesting).
 */
export function getEmbeddingService(): EmbeddingService {
  if (!_embeddingService) {
    _embeddingService = new EmbeddingService()
  }
  return _embeddingService
}

/**
 * Shutdown the embedding service.
 *
 * Call this during application shutdown to clean up resources.
 */
export async function shutdownEmbeddingService(): Promise<void> {
  if (_embeddingService) {
    await _embeddingService.shutdown()
    _embeddingService = null
  }
}
