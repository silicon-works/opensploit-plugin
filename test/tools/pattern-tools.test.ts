import { describe, test, expect } from "bun:test"
import { createPatternSearchTool } from "../../src/tools/pattern-search"
import { createSavePatternTool } from "../../src/tools/save-pattern"

/**
 * Tests for pattern_search and save_pattern tools.
 *
 * Full integration tests require a populated LanceDB database with embeddings.
 * Here we test tool definitions and argument schemas.
 */

describe("tools.pattern-search", () => {
  const tool = createPatternSearchTool()

  test("tool has target_profile arg for matching similar targets", () => {
    expect(tool.args.target_profile).toBeDefined()
  })

  test("tool description references pattern or methodology", () => {
    const desc = tool.description.toLowerCase()
    expect(desc.includes("pattern") || desc.includes("methodology") || desc.includes("attack") || desc.includes("experience")).toBe(true)
  })
})

describe("tools.save-pattern", () => {
  const tool = createSavePatternTool()

  test("tool has args for describing the pattern", () => {
    expect(Object.keys(tool.args).length).toBeGreaterThan(0)
  })

  test("tool description mentions saving or recording", () => {
    const desc = tool.description.toLowerCase()
    expect(desc.includes("save") || desc.includes("record") || desc.includes("capture") || desc.includes("store")).toBe(true)
  })
})
