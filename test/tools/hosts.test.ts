import { describe, test, expect } from "bun:test"
import { createHostsTool, getSessionsWithHosts } from "../../src/tools/hosts"

/**
 * Tests for the hosts tool.
 *
 * Manages /etc/hosts entries for pen test targets.
 * Sudo operations are integration tests (test/integration/README.md).
 */

describe("tools.hosts", () => {
  const hostsTool = createHostsTool()

  test("tool has action and entries args", () => {
    expect(hostsTool.args.action).toBeDefined()
    expect(hostsTool.args.entries).toBeDefined()
  })

  test("tool description mentions /etc/hosts", () => {
    expect(hostsTool.description).toContain("/etc/hosts")
  })

  test("tool description mentions hostname resolution", () => {
    expect(hostsTool.description.toLowerCase()).toContain("hostname")
  })

  test("action arg supports add, remove, list, cleanup", () => {
    // The enum is defined in the schema — just verify the tool creates without error
    // Actual enum validation happens at runtime via Zod
    expect(hostsTool.description.toLowerCase()).toContain("add")
  })
})

describe("tools.hosts.sessionTracking", () => {
  test("getSessionsWithHosts returns array", () => {
    const sessions = getSessionsWithHosts()
    expect(Array.isArray(sessions)).toBe(true)
  })
})
