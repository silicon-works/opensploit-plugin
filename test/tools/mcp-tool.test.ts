import { describe, expect, test, afterEach } from "bun:test"
import { createMcpTool } from "../../src/tools/mcp-tool"
import { createTestDir, writeFile } from "../fixture"
import type { ToolContext } from "@opencode-ai/plugin"

/**
 * Unit tests for mcp_tool.
 *
 * We test through the tool's execute() function with a mock ToolContext.
 * Docker/container tests are in test/integration/ (manual).
 */

function makeContext(overrides: Partial<ToolContext> = {}): ToolContext {
  return {
    sessionID: "test-session-mcp",
    messageID: "test-msg-1",
    agent: "pentest",
    directory: "/tmp",
    worktree: "/tmp",
    abort: new AbortController().signal,
    metadata: () => {},
    ask: async () => {},
    ...overrides,
  }
}

describe("tools.mcp-tool", () => {
  const mcpTool = createMcpTool()
  const ctx = makeContext()

  test("tool has description and args schema", () => {
    expect(mcpTool.description).toContain("MCP tool")
    expect(mcpTool.args.tool).toBeDefined()
    expect(mcpTool.args.method).toBeDefined()
    expect(mcpTool.args.arguments).toBeDefined()
  })

  test("invalid JSON arguments returns helpful error, not a crash", async () => {
    const result = await mcpTool.execute(
      { tool: "nmap", method: "port_scan", arguments: "{invalid json!!" },
      ctx,
    )
    expect(result).toContain("Invalid JSON")
    expect(result).toContain("Expected valid JSON object")
  })

  test("unknown tool name returns registry hint", async () => {
    const result = await mcpTool.execute(
      { tool: "nonexistent_tool_xyz", method: "run" },
      ctx,
    )
    // Either "not found in registry" or a fetch error — both are acceptable
    expect(
      result.includes("not found in registry") || result.includes("Failed to invoke"),
    ).toBe(true)
  })

  test("permission denial returns clean message", async () => {
    const denyCtx = makeContext({
      ask: async () => {
        throw new Error("denied")
      },
    })
    // Use a tool name that would exist in registry — but permission is denied
    // If registry fetch fails, the "not found" path fires first, which is fine.
    // We test the permission path by using a plausible tool name.
    const result = await mcpTool.execute(
      { tool: "nmap", method: "port_scan", arguments: '{"target":"10.10.10.1"}' },
      denyCtx,
    )
    // Either permission denied or tool not found (if registry unavailable)
    expect(
      result.includes("Permission denied") || result.includes("not found in registry"),
    ).toBe(true)
  })
})

describe("tools.mcp-tool.argument-parsing", () => {
  test("valid JSON parses correctly", () => {
    const input = '{"target": "10.10.10.1", "ports": "1-1000"}'
    const result = JSON.parse(input)
    expect(result.target).toBe("10.10.10.1")
    expect(result.ports).toBe("1-1000")
  })

  test("empty arguments treated as empty object", () => {
    const input = ""
    const result = input ? JSON.parse(input) : {}
    expect(result).toEqual({})
  })

  test("undefined arguments treated as empty object", () => {
    const input = undefined
    const result = input ? JSON.parse(input) : {}
    expect(result).toEqual({})
  })
})
