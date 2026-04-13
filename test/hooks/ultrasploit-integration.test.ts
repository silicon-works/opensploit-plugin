/**
 * Integration test: full ultrasploit activation chain.
 *
 * Tests the end-to-end flow as OpenCode would invoke it:
 *   user types "ultrasploit" in chat → chat.message hook strips keyword + enables auto-approve
 *   → permission.ask hook auto-approves all subsequent requests.
 *
 * Unlike the unit tests (chat-message.test.ts, permission.test.ts) which test
 * each hook in isolation, these tests verify the hooks cooperate through
 * shared ultrasploit state.
 */
import { describe, test, expect, afterEach } from "bun:test"
import { chatMessageHook } from "../../src/hooks/chat-message"
import { permissionHook } from "../../src/hooks/permission"
import {
  setUltrasploit,
  isUltrasploitEnabled,
  toggleUltrasploit,
} from "../../src/hooks/ultrasploit"

afterEach(() => {
  setUltrasploit(false)
})

const baseInput = {
  sessionID: "integration-test-session",
  agent: "pentest",
  model: { providerID: "test", modelID: "test" },
  messageID: "msg-int-1",
}

// =============================================================================
// 1. Full activation chain
// =============================================================================

describe("full activation chain", () => {
  test("chat message with keyword activates ultrasploit, strips keyword, and permission hook auto-approves", async () => {
    // Start with ultrasploit disabled
    expect(isUltrasploitEnabled()).toBe(false)

    // User types "ultrasploit scan target"
    const chatOutput = {
      message: {},
      parts: [{ type: "text", text: "ultrasploit scan target" }],
    }
    await chatMessageHook(baseInput, chatOutput)

    // Keyword stripped from parts
    expect(chatOutput.parts[0].text).toBe("scan target")
    expect(chatOutput.parts[0].text).not.toContain("ultrasploit")

    // Ultrasploit is now enabled
    expect(isUltrasploitEnabled()).toBe(true)

    // Permission hook auto-approves
    const permOutput = { status: "ask" as "ask" | "deny" | "allow" }
    await permissionHook(
      { permission: "bash", pattern: "nmap -sV 10.10.10.1" },
      permOutput,
    )
    expect(permOutput.status).toBe("allow")
  })
})

// =============================================================================
// 2. Deactivation via /ultrasploit toggle
// =============================================================================

describe("deactivation via toggle", () => {
  test("toggleUltrasploit disables after activation, permission hook stops auto-approving", async () => {
    // Enable via chat message
    const chatOutput = {
      message: {},
      parts: [{ type: "text", text: "ultrasploit run nmap" }],
    }
    await chatMessageHook(baseInput, chatOutput)
    expect(isUltrasploitEnabled()).toBe(true)

    // Simulate /ultrasploit command toggling it off
    const result = toggleUltrasploit()
    expect(result).toBe(false)
    expect(isUltrasploitEnabled()).toBe(false)

    // Permission hook should NOT auto-approve anymore
    const permOutput = { status: "ask" as "ask" | "deny" | "allow" }
    await permissionHook(
      { permission: "bash", pattern: "sqlmap -u http://target/login" },
      permOutput,
    )
    expect(permOutput.status).toBe("ask")
  })
})

// =============================================================================
// 3. Keyword in subsequent messages doesn't break anything
// =============================================================================

describe("keyword persistence across messages", () => {
  test("ultrasploit persists across messages, keyword always stripped", async () => {
    // First message activates ultrasploit
    const chatOutput1 = {
      message: {},
      parts: [{ type: "text", text: "ultrasploit enumerate services" }],
    }
    await chatMessageHook(baseInput, chatOutput1)

    expect(isUltrasploitEnabled()).toBe(true)
    expect(chatOutput1.parts[0].text).toBe("enumerate services")

    // Second message also contains "ultrasploit" — still enabled, keyword still stripped
    const chatOutput2 = {
      message: {},
      parts: [{ type: "text", text: "ultrasploit try sql injection" }],
    }
    await chatMessageHook(baseInput, chatOutput2)

    expect(isUltrasploitEnabled()).toBe(true)
    expect(chatOutput2.parts[0].text).toBe("try sql injection")

    // Third message WITHOUT keyword — ultrasploit still enabled (persists)
    const chatOutput3 = {
      message: {},
      parts: [{ type: "text", text: "check for privilege escalation vectors" }],
    }
    await chatMessageHook(baseInput, chatOutput3)

    expect(isUltrasploitEnabled()).toBe(true)
    expect(chatOutput3.parts[0].text).toBe(
      "check for privilege escalation vectors",
    )
  })
})

// =============================================================================
// 4. Multiple parts with keyword
// =============================================================================

describe("multiple parts with keyword", () => {
  test("only the part containing the keyword gets modified", async () => {
    const chatOutput = {
      message: {},
      parts: [
        { type: "text", text: "first part without keyword" },
        { type: "text", text: "ultrasploit scan the network" },
      ],
    }
    await chatMessageHook(baseInput, chatOutput)

    // First part unchanged
    expect(chatOutput.parts[0].text).toBe("first part without keyword")

    // Second part has keyword stripped
    expect(chatOutput.parts[1].text).toBe("scan the network")

    // Auto-approve is enabled
    expect(isUltrasploitEnabled()).toBe(true)

    // Verify permission hook works after multi-part activation
    const permOutput = { status: "ask" as "ask" | "deny" | "allow" }
    await permissionHook(
      { permission: "mcp_tool", pattern: "nmap.port_scan" },
      permOutput,
    )
    expect(permOutput.status).toBe("allow")
  })
})
