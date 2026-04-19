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

    // Should inject engagement state
    const stateEntry = output.context.find(c => c.includes("ENGAGEMENT STATE"))
    expect(stateEntry).toBeDefined()
    expect(stateEntry).toContain("PRESERVE ALL DISCOVERIES")
    expect(stateEntry).toContain("10.10.10.1")
    expect(stateEntry).toContain("admin")
    expect(stateEntry).toContain("22")
  })

  test("injects objective with strong anti-drift language", async () => {
    SessionDirectory.create(ROOT)
    await saveEngagementState(ROOT, {
      objective: "get root on target.htb",
      target: { ip: "10.10.10.1" },
    })

    const output = { context: [] as string[], prompt: undefined }
    await compactionHook({ sessionID: ROOT }, output)

    const objectiveEntry = output.context.find(c => c.includes("OBJECTIVE"))
    expect(objectiveEntry).toBeDefined()
    expect(objectiveEntry).toContain("CRITICAL")
    expect(objectiveEntry).toContain("MUST PRESERVE VERBATIM")
    expect(objectiveEntry).toContain("get root on target.htb")
    expect(objectiveEntry).toContain("MUST NOT deviate")
  })

  test("injects current phase", async () => {
    SessionDirectory.create(ROOT)
    await saveEngagementState(ROOT, {
      currentPhase: "enumeration",
      target: { ip: "10.10.10.1" },
    })

    const output = { context: [] as string[], prompt: undefined }
    await compactionHook({ sessionID: ROOT }, output)

    const phaseEntry = output.context.find(c => c.includes("CURRENT PHASE"))
    expect(phaseEntry).toBeDefined()
    expect(phaseEntry).toContain("enumeration")
  })

  test("objective + phase + state all injected together", async () => {
    SessionDirectory.create(ROOT)
    await saveEngagementState(ROOT, {
      objective: "get root on target.htb",
      currentPhase: "exploitation",
      target: { ip: "10.10.10.1", hostname: "target.htb" },
      ports: [{ port: 80, protocol: "tcp", service: "http" }],
      accessLevel: "user",
    })

    const output = { context: [] as string[], prompt: undefined }
    await compactionHook({ sessionID: ROOT }, output)

    // Should have objective, phase, and state entries
    expect(output.context.some(c => c.includes("OBJECTIVE"))).toBe(true)
    expect(output.context.some(c => c.includes("CURRENT PHASE"))).toBe(true)
    expect(output.context.some(c => c.includes("ENGAGEMENT STATE"))).toBe(true)
  })

  test("preserves existing context entries", async () => {
    SessionDirectory.create(ROOT)
    await saveEngagementState(ROOT, { target: { ip: "10.10.10.1" } })

    const output = { context: ["pre-existing context"], prompt: undefined }
    await compactionHook({ sessionID: ROOT }, output)

    expect(output.context[0]).toBe("pre-existing context")
    expect(output.context.length).toBeGreaterThan(1)
  })

  test("does not replace prompt", async () => {
    SessionDirectory.create(ROOT)
    await saveEngagementState(ROOT, { target: { ip: "10.10.10.1" } })

    const output = { context: [], prompt: "custom prompt" as string | undefined }
    await compactionHook({ sessionID: ROOT }, output)

    expect(output.prompt).toBe("custom prompt")
  })

  test("handles serverUrl for todo fetching gracefully when unavailable", async () => {
    SessionDirectory.create(ROOT)
    await saveEngagementState(ROOT, {
      objective: "test objective",
      target: { ip: "10.10.10.1" },
    })

    // Pass a serverUrl that won't respond — should not crash
    const fakeUrl = new URL("http://localhost:0")
    const output = { context: [] as string[], prompt: undefined }
    await compactionHook({ sessionID: ROOT }, output, fakeUrl)

    // Should still inject objective and state even if todos fail
    expect(output.context.some(c => c.includes("OBJECTIVE"))).toBe(true)
    expect(output.context.some(c => c.includes("ENGAGEMENT STATE"))).toBe(true)
  })
})
