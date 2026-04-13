import { describe, test, expect } from "bun:test"
import { createBrowserHeadedTool } from "../../src/tools/browser-headed"

/**
 * Tests for the browser-headed tool.
 *
 * This tool switches Playwright MCP containers between headless and headed (VNC) mode.
 * Actual container operations are integration tests (require Docker + Playwright image).
 * Here we test the tool definition and argument validation.
 */

describe("tools.browser-headed", () => {
  const tool = createBrowserHeadedTool()

  test("tool has correct args schema", () => {
    expect(tool.args.enable).toBeDefined()
    expect(tool.args.vpn_target).toBeDefined()
    expect(tool.args.vpn_hostname).toBeDefined()
    expect(tool.args.vpn_https).toBeDefined()
  })

  test("tool description mentions VNC and headed mode", () => {
    expect(tool.description).toContain("VNC")
    expect(tool.description).toContain("headed")
  })

  test("tool description documents both enable and disable flows", () => {
    const desc = tool.description.toLowerCase()
    expect(desc).toContain("headless")
  })
})
