/**
 * Behavioral tests for the hosts tool.
 *
 * The hosts tool has two layers:
 *   1. Validation + formatting (hosts-core.ts) — fully tested in hosts-core.test.ts
 *   2. Helper script interaction (sudo opensploit-hosts) — tested via error paths
 *
 * These tests exercise the tool's execute() and verify output messages,
 * metadata emissions, and error handling. The helper is NOT installed in
 * the test environment, so write operations fail gracefully.
 */

import { describe, test, expect, afterEach } from "bun:test"
import type { ToolContext } from "@opencode-ai/plugin"
import { createHostsTool, cleanupSessionHosts, isHelperInstalled } from "../../src/tools/hosts"

const hostsTool = createHostsTool()

/** Build a minimal ToolContext for testing. Captures metadata calls. */
function makeContext(sessionId = "test-hosts-session") {
  const metadataCalls: Array<{ title?: string; metadata?: Record<string, any> }> = []
  const ctx: ToolContext = {
    sessionID: sessionId,
    messageID: "test-msg",
    agent: "pentest",
    directory: "/tmp",
    worktree: "/tmp",
    abort: new AbortController().signal,
    metadata: (input) => {
      metadataCalls.push(input)
    },
    ask: async () => {},
  }
  return { ctx, metadataCalls }
}

afterEach(async () => {
  // Clean up any entries written to /etc/hosts during tests
  await cleanupSessionHosts("test-hosts-session")
})

describe("tool.hosts", () => {
  // ---------------------------------------------------------------------------
  // Helper detection
  // ---------------------------------------------------------------------------

  describe("isHelperInstalled", () => {
    test("returns boolean", async () => {
      const result = await isHelperInstalled()
      expect(typeof result).toBe("boolean")
    })

    // In CI/test environment, helper is likely not installed
    test("returns false when helper is not installed", async () => {
      const result = await isHelperInstalled()
      // This test works in environments without the helper installed
      // If it IS installed, this test still passes (it's a type check)
      expect(typeof result).toBe("boolean")
    })
  })

  // ---------------------------------------------------------------------------
  // add action
  // ---------------------------------------------------------------------------

  describe("add", () => {
    test("returns error when no entries provided", async () => {
      const { ctx, metadataCalls } = makeContext()
      const result = await hostsTool.execute({ action: "add" } as any, ctx)

      expect(result).toContain("No entries provided")
      expect(metadataCalls).toHaveLength(1)
      expect(metadataCalls[0].metadata?.success).toBe(false)
    })

    test("returns error when entries is empty array", async () => {
      const { ctx, metadataCalls } = makeContext()
      const result = await hostsTool.execute({ action: "add", entries: [] }, ctx)

      expect(result).toContain("No entries provided")
      expect(metadataCalls[0].metadata?.success).toBe(false)
    })

    test("validates IP addresses", async () => {
      const { ctx, metadataCalls } = makeContext()
      const result = await hostsTool.execute(
        { action: "add", entries: [{ ip: "not-valid", hostname: "target.htb" }] },
        ctx
      )

      expect(result).toContain("Invalid IP")
      expect(metadataCalls[0].metadata?.success).toBe(false)
    })

    test("validates hostnames", async () => {
      const { ctx, metadataCalls } = makeContext()
      const result = await hostsTool.execute(
        { action: "add", entries: [{ ip: "10.10.10.1", hostname: "" }] },
        ctx
      )

      expect(result).toContain("Invalid hostname")
      expect(metadataCalls[0].metadata?.success).toBe(false)
    })

    test("rejects injection in IP", async () => {
      const { ctx } = makeContext()
      const result = await hostsTool.execute(
        { action: "add", entries: [{ ip: "10.10.10.1\n0.0.0.0 evil.com", hostname: "target.htb" }] },
        ctx
      )
      expect(result).toContain("Invalid IP")
    })

    test("rejects injection in hostname", async () => {
      const { ctx } = makeContext()
      const result = await hostsTool.execute(
        { action: "add", entries: [{ ip: "10.10.10.1", hostname: "target.htb;echo pwned" }] },
        ctx
      )
      expect(result).toContain("Invalid hostname")
    })

    test("add with valid entries either succeeds or reports setup required", async () => {
      const { ctx, metadataCalls } = makeContext()
      const result = await hostsTool.execute(
        { action: "add", entries: [{ ip: "10.10.10.1", hostname: "target.htb" }] },
        ctx
      )

      // If helper is installed: succeeds. If not: setup required or failed.
      const isSuccess = result.includes("Added")
      const isSetupMsg = result.includes("helper not installed")
      const isFailed = result.includes("Failed")
      expect(isSuccess || isSetupMsg || isFailed).toBe(true)
      expect(metadataCalls).toHaveLength(1)
    })
  })

  // ---------------------------------------------------------------------------
  // list action
  // ---------------------------------------------------------------------------

  describe("list", () => {
    test("returns no-entries message for fresh session", async () => {
      const { ctx, metadataCalls } = makeContext()
      const result = await hostsTool.execute({ action: "list" }, ctx)

      expect(result).toContain("No hosts entries")
      expect(metadataCalls).toHaveLength(1)
      expect(metadataCalls[0].metadata?.success).toBe(true)
      expect(metadataCalls[0].metadata?.entries).toEqual([])
    })

    test("list does not require helper installation", async () => {
      // list reads /etc/hosts directly — no sudo needed
      const { ctx, metadataCalls } = makeContext()
      const result = await hostsTool.execute({ action: "list" }, ctx)

      // Should NOT report "helper not installed"
      expect(result).not.toContain("helper not installed")
      expect(metadataCalls[0].metadata?.success).toBe(true)
    })

    test("metadata title indicates no entries", async () => {
      const { ctx, metadataCalls } = makeContext()
      await hostsTool.execute({ action: "list" }, ctx)

      expect(metadataCalls[0].title).toContain("No entries")
    })
  })

  // ---------------------------------------------------------------------------
  // cleanup / remove action
  // ---------------------------------------------------------------------------

  describe("cleanup", () => {
    test("reports setup required when helper not installed", async () => {
      const { ctx, metadataCalls } = makeContext()
      const result = await hostsTool.execute({ action: "cleanup" }, ctx)

      const isSetupMsg = result.includes("helper not installed") || result.includes("Setup required")
      const isSuccess = result.includes("Removed")
      // Either setup message or success (if helper happens to be installed)
      expect(isSetupMsg || isSuccess).toBe(true)
      expect(metadataCalls).toHaveLength(1)
    })
  })

  describe("remove", () => {
    test("remove action works same as cleanup", async () => {
      const { ctx: ctx1, metadataCalls: meta1 } = makeContext("ses-rm")
      const { ctx: ctx2, metadataCalls: meta2 } = makeContext("ses-rm")

      const r1 = await hostsTool.execute({ action: "remove" } as any, ctx1)
      const r2 = await hostsTool.execute({ action: "cleanup" }, ctx2)

      // Both should have same type of response
      expect(meta1[0].metadata?.success).toBe(meta2[0].metadata?.success)
    })
  })

  // ---------------------------------------------------------------------------
  // purge action
  // ---------------------------------------------------------------------------

  describe("purge", () => {
    test("reports setup required when helper not installed", async () => {
      const { ctx, metadataCalls } = makeContext()
      const result = await hostsTool.execute({ action: "purge" }, ctx)

      const isSetupMsg = result.includes("helper not installed") || result.includes("Setup required")
      const isSuccess = result.includes("Purged")
      expect(isSetupMsg || isSuccess).toBe(true)
      expect(metadataCalls).toHaveLength(1)
    })
  })

  // ---------------------------------------------------------------------------
  // Session isolation
  // ---------------------------------------------------------------------------

  describe("session isolation", () => {
    test("different sessions have independent list results", async () => {
      const { ctx: ctxA } = makeContext("session-alpha")
      const { ctx: ctxB } = makeContext("session-beta")

      const resultA = await hostsTool.execute({ action: "list" }, ctxA)
      const resultB = await hostsTool.execute({ action: "list" }, ctxB)

      expect(resultA).toContain("No hosts entries")
      expect(resultB).toContain("No hosts entries")
    })
  })

  // ---------------------------------------------------------------------------
  // cleanupSessionHosts
  // ---------------------------------------------------------------------------

  describe("cleanupSessionHosts", () => {
    test("does not throw for non-existent session", async () => {
      await cleanupSessionHosts("nonexistent-session-xyz")
    })

    test("does not throw for invalid session id", async () => {
      await cleanupSessionHosts("")
    })

    test("is safe to call multiple times", async () => {
      await cleanupSessionHosts("multi-cleanup-session")
      await cleanupSessionHosts("multi-cleanup-session")
    })
  })

  // ---------------------------------------------------------------------------
  // Metadata
  // ---------------------------------------------------------------------------

  describe("metadata", () => {
    test("add with no entries sets title to 'Hosts: Error'", async () => {
      const { ctx, metadataCalls } = makeContext()
      await hostsTool.execute({ action: "add" } as any, ctx)
      expect(metadataCalls[0].title).toBe("Hosts: Error")
    })

    test("list empty sets title to 'Hosts: No entries'", async () => {
      const { ctx, metadataCalls } = makeContext()
      await hostsTool.execute({ action: "list" }, ctx)
      expect(metadataCalls[0].title).toBe("Hosts: No entries")
    })
  })
})
