import { describe, test, expect } from "bun:test"
import { eventHook } from "../../src/hooks/event"

/**
 * Tests for the event hook.
 *
 * The event hook is currently a stub that receives bus events but takes
 * no action. These tests verify it handles all event shapes gracefully
 * without throwing, so future changes can build on a solid foundation.
 */

describe("hook.event", () => {
  test("does not crash on null event", async () => {
    await expect(eventHook({ event: null })).resolves.toBeUndefined()
  })

  test("does not crash on undefined event", async () => {
    await expect(eventHook({ event: undefined })).resolves.toBeUndefined()
  })

  test("does not crash on event with no type", async () => {
    await expect(eventHook({ event: {} })).resolves.toBeUndefined()
  })

  test("does not crash on unknown event type", async () => {
    await expect(
      eventHook({ event: { type: "unknown.event" } }),
    ).resolves.toBeUndefined()
  })

  test("handles session.compacted event", async () => {
    await expect(
      eventHook({
        event: {
          type: "session.compacted",
          sessionID: "test-session-001",
        },
      }),
    ).resolves.toBeUndefined()
  })

  test("handles message.updated event", async () => {
    await expect(
      eventHook({
        event: {
          type: "message.updated",
          sessionID: "test-session-001",
          message: { role: "assistant", parts: [{ type: "text", text: "hi" }] },
        },
      }),
    ).resolves.toBeUndefined()
  })

  test("handles tool.execute.after event", async () => {
    await expect(
      eventHook({
        event: {
          type: "tool.execute.after",
          sessionID: "test-session-001",
          tool: "bash",
          result: { output: "OK" },
        },
      }),
    ).resolves.toBeUndefined()
  })

  test("session.deleted triggers hosts cleanup without affecting real entries", async () => {
    // Uses a unique session ID that doesn't exist in /etc/hosts
    // cleanupSessionHosts checks for markers first — this is a safe no-op
    await expect(
      eventHook({
        event: {
          type: "session.deleted",
          properties: { id: "test-event-cleanup-nonexistent" },
        },
      }),
    ).resolves.toBeUndefined()
  })

  test("session.deleted with id at top level", async () => {
    await expect(
      eventHook({
        event: {
          type: "session.deleted",
          id: "test-event-cleanup-toplevel",
        },
      }),
    ).resolves.toBeUndefined()
  })

  test("handles event with extra properties", async () => {
    await expect(
      eventHook({
        event: {
          type: "session.compacted",
          sessionID: "test-session-001",
          metadata: { reason: "context_limit" },
          timestamp: Date.now(),
        },
      }),
    ).resolves.toBeUndefined()
  })
})
