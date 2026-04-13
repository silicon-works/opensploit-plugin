import { describe, test, expect, afterEach } from "bun:test"
import { compactionHook } from "../../src/hooks/compaction"
import * as SessionDirectory from "../../src/session/directory"
import { saveEngagementState } from "../../src/tools/engagement-state"
import { unregister } from "../../src/session/hierarchy"

const ROOT = "test-compaction-root"

afterEach(() => {
  SessionDirectory.cleanup(ROOT)
  unregister(ROOT)
})

describe("hook.compaction", () => {
  test("does nothing when no engagement state exists", async () => {
    const output = { context: ["existing context"], prompt: undefined }
    await compactionHook({ sessionID: ROOT }, output)
    expect(output.context).toHaveLength(1)
    expect(output.context[0]).toBe("existing context")
  })

  test("injects engagement state into compaction context", async () => {
    SessionDirectory.create(ROOT)
    await saveEngagementState(ROOT, {
      target: { ip: "10.10.10.1", hostname: "target.htb" },
      ports: [
        { port: 22, protocol: "tcp", service: "ssh", state: "open" },
      ],
      credentials: [
        { username: "admin", password: "pass123", service: "ssh" },
      ],
      accessLevel: "user",
    })

    const output = { context: [] as string[], prompt: undefined }
    await compactionHook({ sessionID: ROOT }, output)

    expect(output.context).toHaveLength(1)
    const injected = output.context[0]
    expect(injected).toContain("CRITICAL")
    expect(injected).toContain("PRESERVE")
    expect(injected).toContain("10.10.10.1")
    expect(injected).toContain("admin")
    expect(injected).toContain("22")
  })

  test("preserves existing context entries", async () => {
    SessionDirectory.create(ROOT)
    await saveEngagementState(ROOT, { target: { ip: "10.10.10.1" } })

    const output = { context: ["objective context", "todo context"], prompt: undefined }
    await compactionHook({ sessionID: ROOT }, output)

    expect(output.context[0]).toBe("objective context")
    expect(output.context[1]).toBe("todo context")
    expect(output.context.length).toBe(3) // 2 existing + 1 injected
  })

  test("does not replace prompt", async () => {
    SessionDirectory.create(ROOT)
    await saveEngagementState(ROOT, { target: { ip: "10.10.10.1" } })

    const output = { context: [], prompt: "custom prompt" as string | undefined }
    await compactionHook({ sessionID: ROOT }, output)

    expect(output.prompt).toBe("custom prompt") // Not modified
  })
})
