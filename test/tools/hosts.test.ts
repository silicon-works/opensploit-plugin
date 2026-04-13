import { describe, test, expect, afterEach } from "bun:test"
import type { ToolContext } from "@opencode-ai/plugin"
import { createHostsTool, getSessionsWithHosts, cleanupSessionHosts } from "../../src/tools/hosts"

/**
 * Behavioral tests for the hosts tool.
 *
 * The hosts tool has two layers:
 *   1. State tracking (in-memory Map) - fully testable
 *   2. sudo /etc/hosts writes - requires root, tested via error paths
 *
 * We exercise execute() directly and verify output messages, metadata
 * emissions, and state management through the exported helpers.
 */

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

describe("tool.hosts", () => {
  // Clean module-level state between tests by running cleanup for all sessions
  afterEach(async () => {
    for (const sessionId of getSessionsWithHosts()) {
      await cleanupSessionHosts(sessionId)
    }
  })

  // ---------------------------------------------------------------------------
  // add action
  // ---------------------------------------------------------------------------

  describe("add", () => {
    test("returns error when no entries provided", async () => {
      const { ctx, metadataCalls } = makeContext()
      const result = await hostsTool.execute({ action: "add" } as any, ctx)

      expect(result).toContain("No entries provided")
      expect(result).toContain("ip and hostname")
      expect(metadataCalls).toHaveLength(1)
      expect(metadataCalls[0].metadata?.success).toBe(false)
    })

    test("returns error when entries is empty array", async () => {
      const { ctx, metadataCalls } = makeContext()
      const result = await hostsTool.execute({ action: "add", entries: [] }, ctx)

      expect(result).toContain("No entries provided")
      expect(metadataCalls[0].metadata?.success).toBe(false)
    })

    test("attempts sudo and reports failure without root", async () => {
      const { ctx, metadataCalls } = makeContext()
      const result = await hostsTool.execute(
        {
          action: "add",
          entries: [{ ip: "10.10.10.1", hostname: "target.htb" }],
        },
        ctx
      )

      // Without sudo, the write fails. The tool should surface the failure.
      expect(result).toContain("Failed")
      expect(result).toContain("sudo")
      expect(metadataCalls).toHaveLength(1)
      expect(metadataCalls[0].metadata?.success).toBe(false)
    })

    test("does not track entries when sudo write fails", async () => {
      const { ctx } = makeContext("add-failure-session")
      await hostsTool.execute(
        {
          action: "add",
          entries: [{ ip: "10.10.10.1", hostname: "target.htb" }],
        },
        ctx
      )

      // The in-memory Map should NOT have this session because the write failed
      expect(getSessionsWithHosts()).not.toContain("add-failure-session")
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

    test("metadata title indicates no entries", async () => {
      const { ctx, metadataCalls } = makeContext()
      await hostsTool.execute({ action: "list" }, ctx)

      expect(metadataCalls[0].title).toContain("No entries")
    })
  })

  // ---------------------------------------------------------------------------
  // cleanup action
  // ---------------------------------------------------------------------------

  describe("cleanup", () => {
    test("succeeds on session with no entries", async () => {
      const { ctx, metadataCalls } = makeContext()
      const result = await hostsTool.execute({ action: "cleanup" }, ctx)

      expect(result).toContain("Successfully cleaned up")
      expect(metadataCalls).toHaveLength(1)
      expect(metadataCalls[0].metadata?.success).toBe(true)
      expect(metadataCalls[0].title).toContain("Cleanup complete")
    })

    test("is idempotent on empty session", async () => {
      const { ctx } = makeContext("cleanup-idem-session")
      const result1 = await hostsTool.execute({ action: "cleanup" }, ctx)
      const result2 = await hostsTool.execute({ action: "cleanup" }, ctx)

      expect(result1).toContain("Successfully cleaned up")
      expect(result2).toContain("Successfully cleaned up")
    })
  })

  // ---------------------------------------------------------------------------
  // remove action
  // ---------------------------------------------------------------------------

  describe("remove", () => {
    test("returns error when no entries specified", async () => {
      const { ctx, metadataCalls } = makeContext()
      const result = await hostsTool.execute({ action: "remove" } as any, ctx)

      expect(result).toContain("No entries provided")
      expect(result).toContain("cleanup")
      expect(metadataCalls[0].metadata?.success).toBe(false)
    })

    test("remove with empty entries returns error", async () => {
      const { ctx, metadataCalls } = makeContext()
      const result = await hostsTool.execute({ action: "remove", entries: [] }, ctx)

      expect(result).toContain("No entries provided")
      expect(metadataCalls[0].metadata?.success).toBe(false)
    })

    test("remove with entries on empty session succeeds (nothing to remove)", async () => {
      const { ctx, metadataCalls } = makeContext()
      const result = await hostsTool.execute(
        {
          action: "remove",
          entries: [{ ip: "10.10.10.1", hostname: "target.htb" }],
        },
        ctx
      )

      // No markers in /etc/hosts for this session, so removeSessionEntries returns success
      expect(result).toContain("Successfully removed")
      expect(metadataCalls[0].metadata?.success).toBe(true)
    })
  })

  // ---------------------------------------------------------------------------
  // Session isolation
  // ---------------------------------------------------------------------------

  describe("session isolation", () => {
    test("different sessions have independent list results", async () => {
      const { ctx: ctxA, metadataCalls: metaA } = makeContext("session-alpha")
      const { ctx: ctxB, metadataCalls: metaB } = makeContext("session-beta")

      const resultA = await hostsTool.execute({ action: "list" }, ctxA)
      const resultB = await hostsTool.execute({ action: "list" }, ctxB)

      // Both should show empty for their respective sessions
      expect(resultA).toContain("No hosts entries")
      expect(resultB).toContain("No hosts entries")
      // Metadata should be independent
      expect(metaA).toHaveLength(1)
      expect(metaB).toHaveLength(1)
    })

    test("cleanup on one session does not affect another", async () => {
      const { ctx: ctxA } = makeContext("session-one")
      const { ctx: ctxB } = makeContext("session-two")

      await hostsTool.execute({ action: "cleanup" }, ctxA)
      const result = await hostsTool.execute({ action: "list" }, ctxB)

      expect(result).toContain("No hosts entries")
    })
  })

  // ---------------------------------------------------------------------------
  // Exported helpers
  // ---------------------------------------------------------------------------

  describe("getSessionsWithHosts", () => {
    test("returns empty array initially", () => {
      const sessions = getSessionsWithHosts()
      expect(sessions).toEqual([])
    })

    test("returns array type", () => {
      const sessions = getSessionsWithHosts()
      expect(Array.isArray(sessions)).toBe(true)
    })
  })

  describe("cleanupSessionHosts", () => {
    test("does not throw for non-existent session", async () => {
      // cleanupSessionHosts checks sessionHosts.has() first, so this is a no-op
      await cleanupSessionHosts("nonexistent-session-xyz")
    })

    test("is safe to call multiple times", async () => {
      await cleanupSessionHosts("multi-cleanup-session")
      await cleanupSessionHosts("multi-cleanup-session")
      // No error means success
    })
  })

  // ---------------------------------------------------------------------------
  // Metadata emissions
  // ---------------------------------------------------------------------------

  describe("metadata", () => {
    test("add error sets title to 'Hosts: Error'", async () => {
      const { ctx, metadataCalls } = makeContext()
      await hostsTool.execute({ action: "add" } as any, ctx)

      expect(metadataCalls[0].title).toBe("Hosts: Error")
    })

    test("remove error sets title to 'Hosts: Error'", async () => {
      const { ctx, metadataCalls } = makeContext()
      await hostsTool.execute({ action: "remove" } as any, ctx)

      expect(metadataCalls[0].title).toBe("Hosts: Error")
    })

    test("list empty sets title to 'Hosts: No entries'", async () => {
      const { ctx, metadataCalls } = makeContext()
      await hostsTool.execute({ action: "list" }, ctx)

      expect(metadataCalls[0].title).toBe("Hosts: No entries")
    })

    test("cleanup success sets title to 'Hosts: Cleanup complete'", async () => {
      const { ctx, metadataCalls } = makeContext()
      await hostsTool.execute({ action: "cleanup" }, ctx)

      expect(metadataCalls[0].title).toBe("Hosts: Cleanup complete")
    })

    test("failed add sets title to 'Hosts: Failed'", async () => {
      const { ctx, metadataCalls } = makeContext()
      await hostsTool.execute(
        {
          action: "add",
          entries: [{ ip: "10.10.10.1", hostname: "target.htb" }],
        },
        ctx
      )

      expect(metadataCalls[0].title).toBe("Hosts: Failed")
    })
  })
})
