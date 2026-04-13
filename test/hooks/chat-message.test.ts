import { describe, test, expect, afterEach } from "bun:test"
import { chatMessageHook } from "../../src/hooks/chat-message"
import { setUltrasploit, isUltrasploitEnabled } from "../../src/hooks/ultrasploit"

afterEach(() => {
  setUltrasploit(false)
})

const baseInput = {
  sessionID: "test-session",
  agent: "pentest",
  model: { providerID: "test", modelID: "test" },
  messageID: "msg-1",
}

describe("hook.chat-message", () => {
  test("enables ultrasploit when keyword found in message", async () => {
    expect(isUltrasploitEnabled()).toBe(false)

    const output = {
      message: {},
      parts: [{ type: "text", text: "ultrasploit scan 10.10.10.1" }],
    }
    await chatMessageHook(baseInput, output)

    expect(isUltrasploitEnabled()).toBe(true)
  })

  test("strips keyword from message text", async () => {
    const output = {
      message: {},
      parts: [{ type: "text", text: "ultrasploit scan 10.10.10.1" }],
    }
    await chatMessageHook(baseInput, output)

    expect(output.parts[0].text).toBe("scan 10.10.10.1")
    expect(output.parts[0].text).not.toContain("ultrasploit")
  })

  test("case insensitive detection", async () => {
    const output = {
      message: {},
      parts: [{ type: "text", text: "ULTRASPLOIT pentest target.htb" }],
    }
    await chatMessageHook(baseInput, output)

    expect(isUltrasploitEnabled()).toBe(true)
    expect(output.parts[0].text).toBe("pentest target.htb")
  })

  test("does not modify message without keyword", async () => {
    const output = {
      message: {},
      parts: [{ type: "text", text: "scan 10.10.10.1 for open ports" }],
    }
    await chatMessageHook(baseInput, output)

    expect(isUltrasploitEnabled()).toBe(false)
    expect(output.parts[0].text).toBe("scan 10.10.10.1 for open ports")
  })

  test("collapses extra whitespace after stripping", async () => {
    const output = {
      message: {},
      parts: [{ type: "text", text: "please ultrasploit scan the target" }],
    }
    await chatMessageHook(baseInput, output)

    expect(output.parts[0].text).toBe("please scan the target")
  })

  test("handles keyword as the entire message", async () => {
    const output = {
      message: {},
      parts: [{ type: "text", text: "ultrasploit" }],
    }
    await chatMessageHook(baseInput, output)

    expect(isUltrasploitEnabled()).toBe(true)
    expect(output.parts[0].text).toBe("")
  })

  test("does not re-enable if already enabled", async () => {
    setUltrasploit(true)

    const output = {
      message: {},
      parts: [{ type: "text", text: "ultrasploit again" }],
    }
    await chatMessageHook(baseInput, output)

    // Still enabled, keyword still stripped
    expect(isUltrasploitEnabled()).toBe(true)
    expect(output.parts[0].text).toBe("again")
  })

  test("ignores non-text parts", async () => {
    const output = {
      message: {},
      parts: [
        { type: "file", path: "/tmp/ultrasploit.txt" },
        { type: "text", text: "check this file" },
      ],
    }
    await chatMessageHook(baseInput, output)

    expect(isUltrasploitEnabled()).toBe(false)
    expect(output.parts[1].text).toBe("check this file")
  })
})
