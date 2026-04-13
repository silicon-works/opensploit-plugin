import { describe, test, expect, afterEach } from "bun:test"
import { permissionHook } from "../../src/hooks/permission"
import { setUltrasploit, isUltrasploitEnabled } from "../../src/hooks/ultrasploit"

describe("hook.permission", () => {
  afterEach(() => {
    setUltrasploit(false)
  })

  test("does not modify permission when ultrasploit is off", async () => {
    setUltrasploit(false)
    const output = { status: "ask" as const }
    await permissionHook({ permission: "bash", pattern: "nmap*" }, output)
    expect(output.status).toBe("ask")
  })

  test("auto-approves when ultrasploit is on", async () => {
    setUltrasploit(true)
    const output = { status: "ask" as const }
    await permissionHook({ permission: "bash", pattern: "nmap*" }, output)
    expect(output.status).toBe("allow")
  })

  test("auto-approves deny status when ultrasploit is on", async () => {
    setUltrasploit(true)
    const output = { status: "deny" as const }
    await permissionHook({ permission: "mcp_tool", pattern: "*" }, output)
    expect(output.status).toBe("allow")
  })

  test("does not change allow status (already allowed)", async () => {
    setUltrasploit(false)
    const output = { status: "allow" as const }
    await permissionHook({ permission: "read", pattern: "*" }, output)
    expect(output.status).toBe("allow")
  })
})

describe("ultrasploit state", () => {
  afterEach(() => {
    setUltrasploit(false)
  })

  test("starts disabled by default", () => {
    expect(isUltrasploitEnabled()).toBe(false)
  })

  test("can be enabled", () => {
    setUltrasploit(true)
    expect(isUltrasploitEnabled()).toBe(true)
  })

  test("can be toggled", () => {
    const { toggleUltrasploit } = require("../../src/hooks/ultrasploit")
    expect(isUltrasploitEnabled()).toBe(false)
    toggleUltrasploit()
    expect(isUltrasploitEnabled()).toBe(true)
    toggleUltrasploit()
    expect(isUltrasploitEnabled()).toBe(false)
  })
})
