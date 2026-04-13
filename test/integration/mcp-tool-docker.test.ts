/**
 * Integration tests for mcp_tool -> Docker -> nmap pipeline.
 *
 * These tests actually start Docker containers and run real nmap scans.
 * They are slow by nature (container startup, scan execution) but validate
 * the full tool invocation path end-to-end.
 *
 * Prerequisites:
 *   - Docker daemon running
 *   - ghcr.io/silicon-works/mcp-tools-nmap:latest available locally
 *
 * Skipped automatically when Docker or the nmap image is not available.
 *
 * Run:
 *   cd /home/nightshade/silicon-works/opensploit-plugin
 *   bun test test/integration/mcp-tool-docker.test.ts --timeout 120000
 */
import { describe, test, expect, afterAll } from "bun:test"
import { spawnSync } from "bun"
import { createMcpTool } from "../../src/tools/mcp-tool"
import { ContainerManager } from "../../src/container/manager"
import * as SessionDirectory from "../../src/session/directory"
import type { ToolContext } from "@opencode-ai/plugin"

// ---------------------------------------------------------------------------
// Prerequisite checks — synchronous so test.skipIf() sees the real values
// ---------------------------------------------------------------------------
const NMAP_IMAGE = "ghcr.io/silicon-works/mcp-tools-nmap:latest"

let dockerAvailable = false
let nmapImageAvailable = false

try {
  dockerAvailable = spawnSync(["docker", "info"], { stdout: "ignore", stderr: "ignore" }).exitCode === 0
} catch { dockerAvailable = false }

if (dockerAvailable) {
  try {
    nmapImageAvailable = spawnSync(["docker", "image", "inspect", NMAP_IMAGE], {
      stdout: "ignore",
      stderr: "ignore",
    }).exitCode === 0
  } catch { nmapImageAvailable = false }
}

afterAll(async () => {
  // Clean up any containers started during tests
  await ContainerManager.stopAll()
})

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function canRun(): boolean {
  return dockerAvailable && nmapImageAvailable
}

/**
 * Create a temp directory for the test session, with automatic cleanup
 * registered in afterAll. Also pre-creates the session directory structure
 * so mcp_tool's SessionDirectory.exists() check passes.
 */
function createTestSession(): {
  sessionId: string
  sessionDir: string
  cleanup: () => void
} {
  const sessionId = `integration-test-${Date.now()}`
  const sessionDir = SessionDirectory.create(sessionId)
  return {
    sessionId,
    sessionDir,
    cleanup: () => {
      SessionDirectory.cleanup(sessionId)
    },
  }
}

function makeContext(sessionId: string): ToolContext {
  return {
    sessionID: sessionId,
    messageID: `msg-${Date.now()}`,
    agent: "pentest",
    directory: "/tmp",
    worktree: "/tmp",
    abort: new AbortController().signal,
    metadata: () => {},
    // Auto-approve all permission requests
    ask: async () => {},
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe("mcp_tool -> Docker integration", () => {
  const mcpTool = createMcpTool()

  // -------------------------------------------------------------------------
  // 1. Prerequisites reported correctly
  // -------------------------------------------------------------------------
  test("Docker daemon is accessible", () => {
    if (!dockerAvailable) {
      console.log("SKIP: Docker not available — all integration tests will be skipped")
    }
    // Always passes; the real skip logic is on subsequent tests
    expect(true).toBe(true)
  })

  test("nmap image is available locally", () => {
    if (!nmapImageAvailable) {
      console.log(
        `SKIP: ${NMAP_IMAGE} not found — pull it with: docker pull ${NMAP_IMAGE}`,
      )
    }
    expect(true).toBe(true)
  })

  // -------------------------------------------------------------------------
  // 2. Basic invocation: nmap port_scan against localhost
  // -------------------------------------------------------------------------
  test.skipIf(!canRun())(
    "nmap port_scan returns scan results for localhost",
    async () => {
      const session = createTestSession()
      try {
        const ctx = makeContext(session.sessionId)
        const result = await mcpTool.execute(
          {
            tool: "nmap",
            method: "port_scan",
            arguments: JSON.stringify({ target: "127.0.0.1", ports: "22,80" }),
            timeout: 60,
          },
          ctx,
        )

        // The result should contain scan data: port numbers, states (open/closed/filtered)
        // It may also be stored externally if large, but for a 2-port scan it should be inline
        expect(result).toBeDefined()
        expect(typeof result).toBe("string")
        expect(result.length).toBeGreaterThan(0)

        // Should contain nmap result header
        expect(result).toContain("nmap")

        // Should reference ports or states (the exact format depends on the MCP server)
        const hasPortInfo =
          result.includes("22") ||
          result.includes("80") ||
          result.includes("open") ||
          result.includes("closed") ||
          result.includes("filtered")
        expect(hasPortInfo).toBe(true)

        // Should NOT contain error indicators
        expect(result).not.toContain("Failed to invoke")
        expect(result).not.toContain("not found in registry")
        expect(result).not.toContain("Docker is not available")
      } finally {
        session.cleanup()
      }
    },
    60_000,
  )

  // -------------------------------------------------------------------------
  // 3. Registry lookup: verify tool definition is fetched
  // -------------------------------------------------------------------------
  test.skipIf(!canRun())(
    "registry lookup resolves nmap tool definition",
    async () => {
      const session = createTestSession()
      try {
        const ctx = makeContext(session.sessionId)
        // A successful call proves the registry resolved nmap.
        // An unknown tool would return "not found in registry".
        const result = await mcpTool.execute(
          {
            tool: "nmap",
            method: "port_scan",
            arguments: JSON.stringify({ target: "127.0.0.1", ports: "22" }),
            timeout: 60,
          },
          ctx,
        )

        expect(result).not.toContain("not found in registry")
        expect(result).not.toContain("does not have a Docker image")
      } finally {
        session.cleanup()
      }
    },
    60_000,
  )

  // -------------------------------------------------------------------------
  // 4. Error handling: non-existent tool
  // -------------------------------------------------------------------------
  test.skipIf(!canRun())(
    "non-existent tool returns helpful error message",
    async () => {
      const session = createTestSession()
      try {
        const ctx = makeContext(session.sessionId)
        const result = await mcpTool.execute(
          {
            tool: "completely_fake_tool_12345",
            method: "run",
            arguments: "{}",
          },
          ctx,
        )

        expect(result).toContain("not found in registry")
        expect(result).toContain("tool_registry_search")
      } finally {
        session.cleanup()
      }
    },
    10_000,
  )

  // -------------------------------------------------------------------------
  // 5. Invalid method: forwarded to container, container responds
  // -------------------------------------------------------------------------
  test.skipIf(!canRun())(
    "invalid method is forwarded to container and returns error with available methods",
    async () => {
      const session = createTestSession()
      try {
        const ctx = makeContext(session.sessionId)
        const result = await mcpTool.execute(
          {
            tool: "nmap",
            method: "totally_fake_method_xyz",
            arguments: JSON.stringify({ target: "127.0.0.1" }),
            timeout: 60,
          },
          ctx,
        )

        // The container should respond with an error that includes available methods
        // or at minimum indicate the method is not recognized.
        // The exact format depends on the MCP server implementation (BaseMCPServer).
        expect(result).toBeDefined()

        // Should contain some indication of failure or method listing
        const indicatesMethodIssue =
          result.includes("Unknown tool") ||
          result.includes("not found") ||
          result.includes("available") ||
          result.includes("port_scan") || // lists available methods
          result.includes("Failed to invoke") ||
          result.includes("Method not found") ||
          result.includes("error")
        expect(indicatesMethodIssue).toBe(true)
      } finally {
        session.cleanup()
      }
    },
    60_000,
  )

  // -------------------------------------------------------------------------
  // 6. Target validation: external IP triggers warning but does not block
  // -------------------------------------------------------------------------
  test.skipIf(!canRun())(
    "external IP (8.8.8.8) triggers warning but scan is not blocked",
    async () => {
      const session = createTestSession()
      try {
        const ctx = makeContext(session.sessionId)
        const result = await mcpTool.execute(
          {
            tool: "nmap",
            method: "port_scan",
            arguments: JSON.stringify({ target: "8.8.8.8", ports: "53" }),
            timeout: 60,
          },
          ctx,
        )

        // Should contain external target warning
        expect(result).toContain("EXTERNAL TARGET")

        // Should NOT be blocked — the scan should still run
        expect(result).not.toContain("not found in registry")
        expect(result).not.toContain("Permission denied")

        // Should have some scan output after the warning
        // (even if the port is filtered, nmap will produce output)
        const hasScanOutput =
          result.includes("53") ||
          result.includes("open") ||
          result.includes("closed") ||
          result.includes("filtered") ||
          result.includes("nmap") ||
          result.includes("Result")
        expect(hasScanOutput).toBe(true)
      } finally {
        session.cleanup()
      }
    },
    60_000,
  )

  // -------------------------------------------------------------------------
  // 7. Container reuse: second call reuses the running container
  // -------------------------------------------------------------------------
  test.skipIf(!canRun())(
    "second invocation reuses the running nmap container",
    async () => {
      const session = createTestSession()
      try {
        const ctx = makeContext(session.sessionId)

        // First call — starts container
        const result1 = await mcpTool.execute(
          {
            tool: "nmap",
            method: "port_scan",
            arguments: JSON.stringify({ target: "127.0.0.1", ports: "22" }),
            timeout: 60,
          },
          ctx,
        )
        expect(result1).not.toContain("Failed to invoke")

        // Check container is tracked
        const statusBefore = ContainerManager.getStatus()
        const nmapEntry = statusBefore.find((s) => s.toolName === "nmap")
        expect(nmapEntry).toBeDefined()
        const startedAt = nmapEntry!.startedAt

        // Second call — should reuse
        const result2 = await mcpTool.execute(
          {
            tool: "nmap",
            method: "port_scan",
            arguments: JSON.stringify({ target: "127.0.0.1", ports: "80" }),
            timeout: 60,
          },
          ctx,
        )
        expect(result2).not.toContain("Failed to invoke")

        // Verify same container (startedAt unchanged)
        const statusAfter = ContainerManager.getStatus()
        const nmapAfter = statusAfter.find((s) => s.toolName === "nmap")
        expect(nmapAfter).toBeDefined()
        expect(nmapAfter!.startedAt).toBe(startedAt)

        // lastUsed should have advanced
        expect(nmapAfter!.lastUsed).toBeGreaterThan(startedAt)
      } finally {
        // Stop nmap container explicitly so subsequent tests get a fresh one
        await ContainerManager.stopContainer("nmap")
        session.cleanup()
      }
    },
    90_000,
  )
})
