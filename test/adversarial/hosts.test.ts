/**
 * Adversarial tests for the hosts tool.
 *
 * Tests injection attacks, edge cases, and security boundaries.
 * Focuses on the validation layer (hosts-core) since the bash helper
 * is not available in the test environment.
 */

import { describe, test, expect } from "bun:test"
import type { ToolContext } from "@opencode-ai/plugin"
import { createHostsTool } from "../../src/tools/hosts"
import {
  validateIP,
  validateHostname,
  validateSessionId,
  validateEntries,
  removeHostsBlock,
  removeAllBlocks,
  parseHostsBlock,
  formatHostsBlock,
  MAX_ENTRIES_PER_SESSION,
} from "../../src/tools/hosts-core"

const hostsTool = createHostsTool()

function makeContext(sessionId = "test-adv-session") {
  const metadataCalls: Array<{ title?: string; metadata?: Record<string, any> }> = []
  const ctx: ToolContext = {
    sessionID: sessionId,
    messageID: "test-msg",
    agent: "pentest",
    directory: "/tmp",
    worktree: "/tmp",
    abort: new AbortController().signal,
    metadata: (input) => { metadataCalls.push(input) },
    ask: async () => {},
  }
  return { ctx, metadataCalls }
}

// =============================================================================
// 1. SHELL INJECTION ATTACKS
// =============================================================================

describe("ATTACK: shell injection via IP field", () => {
  const attacks = [
    { name: "command substitution $()", value: "$(cat /etc/shadow)" },
    { name: "backtick command substitution", value: "`cat /etc/shadow`" },
    { name: "semicolon command chain", value: "10.10.10.1; rm -rf /" },
    { name: "pipe to shell", value: "10.10.10.1 | bash" },
    { name: "ampersand background", value: "10.10.10.1 & malware" },
    { name: "newline injection", value: "10.10.10.1\n0.0.0.0 google.com" },
    { name: "carriage return injection", value: "10.10.10.1\r\n0.0.0.0 evil.com" },
    { name: "null byte truncation", value: "10.10.10.1\0malicious" },
    { name: "tab injection for extra hostname", value: "10.10.10.1\tevil.com" },
    { name: "single quote escape", value: "10.10.10.1' ; echo pwned'" },
    { name: "double quote escape", value: '10.10.10.1" ; echo pwned"' },
    { name: "curly brace expansion", value: "10.10.10.{1..255}" },
    { name: "glob wildcard", value: "10.10.10.*" },
    { name: "redirect", value: "10.10.10.1 > /etc/shadow" },
    { name: "heredoc", value: "10.10.10.1 << EOF" },
  ]

  for (const attack of attacks) {
    test(`IP: ${attack.name} — rejected by validateIP`, () => {
      expect(validateIP(attack.value)).toBe(false)
    })

    test(`IP: ${attack.name} — rejected by tool execute`, async () => {
      const { ctx } = makeContext()
      const result = await hostsTool.execute(
        { action: "add", entries: [{ ip: attack.value, hostname: "target.htb" }] },
        ctx
      )
      expect(result).toContain("Invalid") // Validation catches it before helper is called
    })
  }
})

describe("ATTACK: shell injection via hostname field", () => {
  const attacks = [
    { name: "command substitution $()", value: "$(cat /etc/shadow).htb" },
    { name: "backtick command substitution", value: "`cat /etc/shadow`.htb" },
    { name: "semicolon command chain", value: "target.htb; rm -rf /" },
    { name: "pipe to shell", value: "target.htb | bash" },
    { name: "newline injection", value: "target.htb\n0.0.0.0 google.com" },
    { name: "null byte truncation", value: "target.htb\0malicious" },
    { name: "hash comment injection", value: "target.htb # comment" },
    { name: "single quote", value: "target'.htb" },
    { name: "double quote", value: 'target".htb' },
    { name: "slash path traversal", value: "target.htb/../../../etc/passwd" },
    { name: "backslash", value: "target\\htb" },
    { name: "redirect", value: "target.htb > /etc/shadow" },
  ]

  for (const attack of attacks) {
    test(`Hostname: ${attack.name} — rejected`, () => {
      expect(validateHostname(attack.value)).toBe(false)
    })
  }
})

describe("ATTACK: shell injection via session ID", () => {
  const attacks = [
    { name: "sed pattern injection", value: "ses/,/d;s/.*//;e id" },
    { name: "newline for multi-command", value: "ses\nid" },
    { name: "null byte", value: "ses\0id" },
    { name: "semicolon", value: "ses;id" },
    { name: "backtick", value: "ses`id`" },
    { name: "dollar paren", value: "ses$(id)" },
    { name: "space", value: "ses id" },
    { name: "dot dot slash", value: "../../etc/passwd" },
    { name: "pipe", value: "ses|id" },
    { name: "glob", value: "ses*" },
    { name: "regex dot", value: "ses.123" },
  ]

  for (const attack of attacks) {
    test(`Session: ${attack.name} — rejected`, () => {
      expect(validateSessionId(attack.value)).toBe(false)
    })
  }
})

// =============================================================================
// 2. HOSTS FILE CONTENT MANIPULATION
// =============================================================================

describe("ATTACK: hosts file content manipulation", () => {
  test("formatHostsBlock output contains no uncontrolled newlines", () => {
    const block = formatHostsBlock("ses_test", [
      { ip: "10.10.10.1", hostname: "target.htb" },
    ])
    const lines = block.split("\n")
    // Every line should be either a marker or an IP\thostname
    for (const line of lines) {
      expect(
        line.startsWith("# opensploit-session:") ||
        line.startsWith("# end-opensploit-session:") ||
        /^\d/.test(line) ||
        /^[0-9a-fA-F]/.test(line)
      ).toBe(true)
    }
  })

  test("removeHostsBlock preserves system-critical entries", () => {
    const content = [
      "127.0.0.1\tlocalhost",
      "127.0.1.1\tmy-machine",
      "::1\tlocalhost ip6-localhost ip6-loopback",
      "# opensploit-session:ses_test",
      "10.10.10.1\ttarget.htb",
      "# end-opensploit-session:ses_test",
      "10.10.10.5\tcustom-entry",
    ].join("\n")

    const result = removeHostsBlock(content, "ses_test")
    expect(result).toContain("127.0.0.1\tlocalhost")
    expect(result).toContain("127.0.1.1\tmy-machine")
    expect(result).toContain("::1\tlocalhost")
    expect(result).toContain("10.10.10.5\tcustom-entry")
    expect(result).not.toContain("target.htb")
  })

  test("removeAllBlocks preserves all non-opensploit content", () => {
    const content = [
      "127.0.0.1\tlocalhost",
      "# Company DNS entries",
      "192.168.1.100\tintranet.corp.local",
      "# opensploit-session:ses_1",
      "10.10.10.1\ttarget.htb",
      "# end-opensploit-session:ses_1",
      "192.168.1.200\tprinter.corp.local",
    ].join("\n")

    const result = removeAllBlocks(content)
    expect(result).toContain("127.0.0.1\tlocalhost")
    expect(result).toContain("# Company DNS entries")
    expect(result).toContain("intranet.corp.local")
    expect(result).toContain("printer.corp.local")
    expect(result).not.toContain("target.htb")
  })

  test("session ID in marker cannot match a different session via regex", () => {
    const content = [
      "# opensploit-session:ses_abc",
      "10.10.10.1\tabc.htb",
      "# end-opensploit-session:ses_abc",
      "# opensploit-session:ses_abc123",
      "10.10.10.2\tabc123.htb",
      "# end-opensploit-session:ses_abc123",
    ].join("\n")

    // Removing ses_abc should NOT affect ses_abc123
    const result = removeHostsBlock(content, "ses_abc")
    expect(result).not.toContain("abc.htb")
    expect(result).toContain("abc123.htb")
    expect(result).toContain("opensploit-session:ses_abc123")
  })
})

// =============================================================================
// 3. ENTRY LIMIT ENFORCEMENT
// =============================================================================

describe("ATTACK: entry limit enforcement", () => {
  test("exactly MAX entries is accepted", () => {
    const entries = Array.from({ length: MAX_ENTRIES_PER_SESSION }, (_, i) => ({
      ip: "10.10.10.1",
      hostname: `h${i}.htb`,
    }))
    expect(validateEntries(entries).valid).toBe(true)
  })

  test("MAX + 1 entries is rejected", () => {
    const entries = Array.from({ length: MAX_ENTRIES_PER_SESSION + 1 }, (_, i) => ({
      ip: "10.10.10.1",
      hostname: `h${i}.htb`,
    }))
    expect(validateEntries(entries).valid).toBe(false)
  })

  test("1000 entries is rejected", () => {
    const entries = Array.from({ length: 1000 }, (_, i) => ({
      ip: "10.10.10.1",
      hostname: `h${i}.htb`,
    }))
    const result = validateEntries(entries)
    expect(result.valid).toBe(false)
    expect(result.error).toContain("limit")
  })
})

// =============================================================================
// 4. CONCURRENT SESSION SAFETY
// =============================================================================

describe("ATTACK: concurrent session safety (block formatting)", () => {
  test("two sessions format independent blocks", () => {
    const block1 = formatHostsBlock("ses_1", [{ ip: "10.10.10.1", hostname: "first.htb" }])
    const block2 = formatHostsBlock("ses_2", [{ ip: "10.10.10.2", hostname: "second.htb" }])

    expect(block1).toContain("opensploit-session:ses_1")
    expect(block1).not.toContain("ses_2")
    expect(block2).toContain("opensploit-session:ses_2")
    expect(block2).not.toContain("ses_1")
  })

  test("removing one session from combined content preserves the other", () => {
    const content = [
      formatHostsBlock("ses_1", [{ ip: "10.10.10.1", hostname: "first.htb" }]),
      formatHostsBlock("ses_2", [{ ip: "10.10.10.2", hostname: "second.htb" }]),
    ].join("\n")

    const after = removeHostsBlock(content, "ses_1")
    expect(parseHostsBlock(after, "ses_2")).toEqual([{ ip: "10.10.10.2", hostname: "second.htb" }])
    expect(parseHostsBlock(after, "ses_1")).toEqual([])
  })
})

// =============================================================================
// 5. EDGE CASES
// =============================================================================

describe("edge cases", () => {
  test("empty /etc/hosts content — parse returns empty", () => {
    expect(parseHostsBlock("", "ses_abc")).toEqual([])
  })

  test("empty /etc/hosts content — remove is no-op", () => {
    expect(removeHostsBlock("", "ses_abc")).toBe("")
  })

  test("empty /etc/hosts content — purge is no-op", () => {
    expect(removeAllBlocks("")).toBe("")
  })

  test("IPv6 entries in block", () => {
    const block = formatHostsBlock("ses_v6", [{ ip: "::1", hostname: "target.htb" }])
    expect(block).toContain("::1\ttarget.htb")

    const entries = parseHostsBlock(block, "ses_v6")
    expect(entries).toEqual([{ ip: "::1", hostname: "target.htb" }])
  })

  test("single-character session ID", () => {
    expect(validateSessionId("a")).toBe(true)
    const block = formatHostsBlock("a", [{ ip: "10.10.10.1", hostname: "t.htb" }])
    expect(block).toContain("opensploit-session:a")
  })

  test("very long session ID (100 chars)", () => {
    const longId = "a".repeat(100)
    expect(validateSessionId(longId)).toBe(true)
  })

  test("hostname with many subdomains", () => {
    expect(validateHostname("a.b.c.d.e.f.g.h.target.htb")).toBe(true)
  })

  test("underscore in hostname (common in DNS)", () => {
    expect(validateHostname("_dmarc.target.htb")).toBe(true)
    expect(validateHostname("_tcp.target.htb")).toBe(true)
  })
})
