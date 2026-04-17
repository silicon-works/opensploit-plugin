/**
 * TDD tests for hosts tool core logic.
 *
 * Tests validation, block formatting/parsing, and helper detection.
 * All validation and formatting is pure TypeScript — no I/O, no sudo.
 * The bash helper is a thin I/O layer tested separately.
 */

import { describe, test, expect } from "bun:test"
import {
  validateIP,
  validateHostname,
  validateSessionId,
  validateEntries,
  formatHostsBlock,
  parseHostsBlock,
  removeHostsBlock,
  removeAllBlocks,
  MAX_ENTRIES_PER_SESSION,
  type HostEntry,
} from "../../src/tools/hosts-core"

// =============================================================================
// 1. IP VALIDATION
// =============================================================================

describe("validateIP", () => {
  // Valid IPv4
  test("10.10.10.1 is valid", () => expect(validateIP("10.10.10.1")).toBe(true))
  test("192.168.1.1 is valid", () => expect(validateIP("192.168.1.1")).toBe(true))
  test("0.0.0.0 is valid", () => expect(validateIP("0.0.0.0")).toBe(true))
  test("255.255.255.255 is valid", () => expect(validateIP("255.255.255.255")).toBe(true))
  test("127.0.0.1 is valid", () => expect(validateIP("127.0.0.1")).toBe(true))

  // Valid IPv6
  test("::1 is valid", () => expect(validateIP("::1")).toBe(true))
  test("fe80::1 is valid", () => expect(validateIP("fe80::1")).toBe(true))
  test("2001:db8::1 is valid", () => expect(validateIP("2001:db8::1")).toBe(true))
  test("full IPv6 is valid", () => expect(validateIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334")).toBe(true))

  // Invalid
  test("empty string is invalid", () => expect(validateIP("")).toBe(false))
  test("hostname is invalid", () => expect(validateIP("target.htb")).toBe(false))
  test("IP with port is invalid", () => expect(validateIP("10.10.10.1:8080")).toBe(false))
  test("CIDR is invalid", () => expect(validateIP("10.10.10.0/24")).toBe(false))
  test("spaces are invalid", () => expect(validateIP("10.10.10.1 ")).toBe(false))
  test("leading space invalid", () => expect(validateIP(" 10.10.10.1")).toBe(false))

  // Injection attempts
  test("newline injection rejected", () => expect(validateIP("10.10.10.1\n0.0.0.0 evil.com")).toBe(false))
  test("tab injection rejected", () => expect(validateIP("10.10.10.1\tevil.com")).toBe(false))
  test("null byte rejected", () => expect(validateIP("10.10.10.1\0")).toBe(false))
  test("semicolon rejected", () => expect(validateIP("10.10.10.1;echo pwned")).toBe(false))
  test("backtick rejected", () => expect(validateIP("`whoami`")).toBe(false))
  test("$() rejected", () => expect(validateIP("$(whoami)")).toBe(false))
  test("pipe rejected", () => expect(validateIP("10.10.10.1|cat /etc/passwd")).toBe(false))
})

// =============================================================================
// 2. HOSTNAME VALIDATION
// =============================================================================

describe("validateHostname", () => {
  // Valid
  test("target.htb is valid", () => expect(validateHostname("target.htb")).toBe(true))
  test("sub.target.htb is valid", () => expect(validateHostname("sub.target.htb")).toBe(true))
  test("dc01.corp.local is valid", () => expect(validateHostname("dc01.corp.local")).toBe(true))
  test("single label is valid", () => expect(validateHostname("localhost")).toBe(true))
  test("hyphenated is valid", () => expect(validateHostname("my-host.lab")).toBe(true))
  test("punycode is valid", () => expect(validateHostname("xn--80akhbyknj4f.htb")).toBe(true))
  test("numeric subdomain is valid", () => expect(validateHostname("123.target.htb")).toBe(true))
  test("underscore is valid", () => expect(validateHostname("_dmarc.target.htb")).toBe(true))

  // Invalid
  test("empty string is invalid", () => expect(validateHostname("")).toBe(false))
  test("just a dot is invalid", () => expect(validateHostname(".")).toBe(false))
  test("starts with hyphen is invalid", () => expect(validateHostname("-host.htb")).toBe(false))
  test("space in hostname is invalid", () => expect(validateHostname("target .htb")).toBe(false))

  // Injection attempts
  test("newline injection rejected", () => expect(validateHostname("target.htb\n0.0.0.0 evil.com")).toBe(false))
  test("tab injection rejected", () => expect(validateHostname("target\t.htb")).toBe(false))
  test("null byte rejected", () => expect(validateHostname("target.htb\0")).toBe(false))
  test("semicolon rejected", () => expect(validateHostname("target.htb;echo pwned")).toBe(false))
  test("backtick rejected", () => expect(validateHostname("`whoami`.htb")).toBe(false))
  test("$() rejected", () => expect(validateHostname("$(whoami).htb")).toBe(false))
  test("pipe rejected", () => expect(validateHostname("target.htb|cat")).toBe(false))
  test("hash rejected", () => expect(validateHostname("target.htb # comment")).toBe(false))
  test("slash rejected", () => expect(validateHostname("target.htb/path")).toBe(false))

  // Length
  test("253 char hostname is valid", () => {
    // Max DNS name length is 253
    const long = "a".repeat(60) + "." + "b".repeat(60) + "." + "c".repeat(60) + "." + "d".repeat(60) + ".htb"
    expect(long.length).toBeLessThanOrEqual(253)
    expect(validateHostname(long)).toBe(true)
  })

  test("254+ char hostname is invalid", () => {
    const tooLong = "a".repeat(250) + ".htb"
    expect(tooLong.length).toBeGreaterThan(253)
    expect(validateHostname(tooLong)).toBe(false)
  })
})

// =============================================================================
// 3. SESSION ID VALIDATION
// =============================================================================

describe("validateSessionId", () => {
  // Valid
  test("alphanumeric is valid", () => expect(validateSessionId("ses_abc123")).toBe(true))
  test("with hyphens is valid", () => expect(validateSessionId("ses-abc-123")).toBe(true))
  test("with underscores is valid", () => expect(validateSessionId("ses_abc_123")).toBe(true))
  test("plain string is valid", () => expect(validateSessionId("mysession")).toBe(true))

  // Invalid
  test("empty string is invalid", () => expect(validateSessionId("")).toBe(false))
  test("path traversal rejected", () => expect(validateSessionId("../../etc")).toBe(false))
  test("slash rejected", () => expect(validateSessionId("ses/123")).toBe(false))
  test("backslash rejected", () => expect(validateSessionId("ses\\123")).toBe(false))
  test("space rejected", () => expect(validateSessionId("ses 123")).toBe(false))

  // Injection via sed/shell
  test("newline rejected", () => expect(validateSessionId("ses\n123")).toBe(false))
  test("null byte rejected", () => expect(validateSessionId("ses\0123")).toBe(false))
  test("semicolon rejected", () => expect(validateSessionId("ses;rm -rf /")).toBe(false))
  test("backtick rejected", () => expect(validateSessionId("`whoami`")).toBe(false))
  test("$() rejected", () => expect(validateSessionId("$(id)")).toBe(false))
  test("pipe rejected", () => expect(validateSessionId("ses|cat")).toBe(false))
  test("dot rejected", () => expect(validateSessionId("ses.123")).toBe(false))
  test("asterisk rejected", () => expect(validateSessionId("ses*")).toBe(false))
  test("question mark rejected", () => expect(validateSessionId("ses?")).toBe(false))
  test("bracket rejected", () => expect(validateSessionId("ses[0]")).toBe(false))
})

// =============================================================================
// 4. ENTRY VALIDATION
// =============================================================================

describe("validateEntries", () => {
  test("valid single entry", () => {
    const result = validateEntries([{ ip: "10.10.10.1", hostname: "target.htb" }])
    expect(result.valid).toBe(true)
  })

  test("valid multiple entries", () => {
    const result = validateEntries([
      { ip: "10.10.10.1", hostname: "target.htb" },
      { ip: "10.10.10.1", hostname: "admin.target.htb" },
    ])
    expect(result.valid).toBe(true)
  })

  test("empty array is invalid", () => {
    const result = validateEntries([])
    expect(result.valid).toBe(false)
    expect(result.error).toBeDefined()
  })

  test("invalid IP in entry", () => {
    const result = validateEntries([{ ip: "not-an-ip", hostname: "target.htb" }])
    expect(result.valid).toBe(false)
    expect(result.error).toContain("IP")
  })

  test("invalid hostname in entry", () => {
    const result = validateEntries([{ ip: "10.10.10.1", hostname: "" }])
    expect(result.valid).toBe(false)
    expect(result.error).toContain("hostname")
  })

  test("injection in IP caught", () => {
    const result = validateEntries([{ ip: "10.10.10.1\n0.0.0.0 evil.com", hostname: "target.htb" }])
    expect(result.valid).toBe(false)
  })

  test("injection in hostname caught", () => {
    const result = validateEntries([{ ip: "10.10.10.1", hostname: "target.htb\n0.0.0.0 evil.com" }])
    expect(result.valid).toBe(false)
  })

  test(`max ${MAX_ENTRIES_PER_SESSION} entries is valid`, () => {
    const entries = Array.from({ length: MAX_ENTRIES_PER_SESSION }, (_, i) => ({
      ip: "10.10.10.1",
      hostname: `host${i}.htb`,
    }))
    const result = validateEntries(entries)
    expect(result.valid).toBe(true)
  })

  test(`${MAX_ENTRIES_PER_SESSION + 1} entries exceeds limit`, () => {
    const entries = Array.from({ length: MAX_ENTRIES_PER_SESSION + 1 }, (_, i) => ({
      ip: "10.10.10.1",
      hostname: `host${i}.htb`,
    }))
    const result = validateEntries(entries)
    expect(result.valid).toBe(false)
    expect(result.error).toContain("limit")
  })
})

// =============================================================================
// 5. BLOCK FORMATTING
// =============================================================================

describe("formatHostsBlock", () => {
  test("formats single entry correctly", () => {
    const block = formatHostsBlock("ses_abc", [{ ip: "10.10.10.1", hostname: "target.htb" }])
    const lines = block.split("\n")
    expect(lines[0]).toBe("# opensploit-session:ses_abc")
    expect(lines[1]).toBe("10.10.10.1\ttarget.htb")
    expect(lines[2]).toBe("# end-opensploit-session:ses_abc")
  })

  test("formats multiple entries", () => {
    const block = formatHostsBlock("ses_abc", [
      { ip: "10.10.10.1", hostname: "target.htb" },
      { ip: "10.10.10.1", hostname: "admin.target.htb" },
    ])
    const lines = block.split("\n")
    expect(lines.length).toBe(4) // start marker + 2 entries + end marker
    expect(lines[1]).toBe("10.10.10.1\ttarget.htb")
    expect(lines[2]).toBe("10.10.10.1\tadmin.target.htb")
  })

  test("uses tab separator", () => {
    const block = formatHostsBlock("s", [{ ip: "10.10.10.1", hostname: "target.htb" }])
    expect(block).toContain("10.10.10.1\ttarget.htb")
  })
})

// =============================================================================
// 6. BLOCK PARSING
// =============================================================================

describe("parseHostsBlock", () => {
  test("parses entries from content", () => {
    const content = [
      "127.0.0.1 localhost",
      "# opensploit-session:ses_abc",
      "10.10.10.1\ttarget.htb",
      "10.10.10.1\tadmin.target.htb",
      "# end-opensploit-session:ses_abc",
      "::1 localhost",
    ].join("\n")

    const entries = parseHostsBlock(content, "ses_abc")
    expect(entries).toEqual([
      { ip: "10.10.10.1", hostname: "target.htb" },
      { ip: "10.10.10.1", hostname: "admin.target.htb" },
    ])
  })

  test("returns empty for non-existent session", () => {
    const content = "127.0.0.1 localhost\n"
    expect(parseHostsBlock(content, "ses_xyz")).toEqual([])
  })

  test("ignores comment lines inside block", () => {
    const content = [
      "# opensploit-session:ses_abc",
      "# this is a comment",
      "10.10.10.1\ttarget.htb",
      "# end-opensploit-session:ses_abc",
    ].join("\n")

    const entries = parseHostsBlock(content, "ses_abc")
    expect(entries).toEqual([{ ip: "10.10.10.1", hostname: "target.htb" }])
  })

  test("ignores empty lines inside block", () => {
    const content = [
      "# opensploit-session:ses_abc",
      "",
      "10.10.10.1\ttarget.htb",
      "",
      "# end-opensploit-session:ses_abc",
    ].join("\n")

    const entries = parseHostsBlock(content, "ses_abc")
    expect(entries).toEqual([{ ip: "10.10.10.1", hostname: "target.htb" }])
  })

  test("handles multiple sessions, returns only requested one", () => {
    const content = [
      "# opensploit-session:ses_1",
      "10.10.10.1\tfirst.htb",
      "# end-opensploit-session:ses_1",
      "# opensploit-session:ses_2",
      "10.10.10.2\tsecond.htb",
      "# end-opensploit-session:ses_2",
    ].join("\n")

    expect(parseHostsBlock(content, "ses_1")).toEqual([{ ip: "10.10.10.1", hostname: "first.htb" }])
    expect(parseHostsBlock(content, "ses_2")).toEqual([{ ip: "10.10.10.2", hostname: "second.htb" }])
  })

  test("handles space-separated entries (not just tab)", () => {
    const content = [
      "# opensploit-session:ses_abc",
      "10.10.10.1 target.htb",
      "# end-opensploit-session:ses_abc",
    ].join("\n")

    const entries = parseHostsBlock(content, "ses_abc")
    expect(entries).toEqual([{ ip: "10.10.10.1", hostname: "target.htb" }])
  })

  test("orphaned start marker (no end) returns empty", () => {
    const content = [
      "# opensploit-session:ses_abc",
      "10.10.10.1\ttarget.htb",
      // no end marker
    ].join("\n")

    // Should not return entries from an incomplete block
    expect(parseHostsBlock(content, "ses_abc")).toEqual([])
  })
})

// =============================================================================
// 7. BLOCK REMOVAL
// =============================================================================

describe("removeHostsBlock", () => {
  test("removes session block, preserves other content", () => {
    const content = [
      "127.0.0.1 localhost",
      "# opensploit-session:ses_abc",
      "10.10.10.1\ttarget.htb",
      "# end-opensploit-session:ses_abc",
      "::1 localhost",
    ].join("\n")

    const result = removeHostsBlock(content, "ses_abc")
    expect(result).toContain("127.0.0.1 localhost")
    expect(result).toContain("::1 localhost")
    expect(result).not.toContain("opensploit-session:ses_abc")
    expect(result).not.toContain("target.htb")
  })

  test("no-op when session not present", () => {
    const content = "127.0.0.1 localhost\n::1 localhost"
    const result = removeHostsBlock(content, "ses_xyz")
    expect(result).toBe(content)
  })

  test("removes only targeted session, preserves others", () => {
    const content = [
      "# opensploit-session:ses_1",
      "10.10.10.1\tfirst.htb",
      "# end-opensploit-session:ses_1",
      "# opensploit-session:ses_2",
      "10.10.10.2\tsecond.htb",
      "# end-opensploit-session:ses_2",
    ].join("\n")

    const result = removeHostsBlock(content, "ses_1")
    expect(result).not.toContain("first.htb")
    expect(result).toContain("second.htb")
    expect(result).toContain("opensploit-session:ses_2")
  })

  test("handles duplicate blocks for same session (removes all)", () => {
    const content = [
      "# opensploit-session:ses_abc",
      "10.10.10.1\tfirst.htb",
      "# end-opensploit-session:ses_abc",
      "# opensploit-session:ses_abc",
      "10.10.10.2\tsecond.htb",
      "# end-opensploit-session:ses_abc",
    ].join("\n")

    const result = removeHostsBlock(content, "ses_abc")
    expect(result).not.toContain("first.htb")
    expect(result).not.toContain("second.htb")
    expect(result).not.toContain("opensploit-session")
  })

  test("does not leave excessive blank lines", () => {
    const content = [
      "127.0.0.1 localhost",
      "",
      "# opensploit-session:ses_abc",
      "10.10.10.1\ttarget.htb",
      "# end-opensploit-session:ses_abc",
      "",
      "::1 localhost",
    ].join("\n")

    const result = removeHostsBlock(content, "ses_abc")
    // Should not have 3+ consecutive blank lines
    expect(result).not.toMatch(/\n{4,}/)
  })

  test("orphaned start marker does NOT eat subsequent lines", () => {
    const content = [
      "127.0.0.1 localhost",
      "# opensploit-session:ses_broken",
      "10.10.10.1\torphan.htb",
      "::1 localhost",
    ].join("\n")

    const result = removeHostsBlock(content, "ses_broken")
    // The marker line is removed, but subsequent lines are preserved
    // because we can't tell if they're block entries or system entries
    expect(result).toContain("127.0.0.1 localhost")
    expect(result).toContain("::1 localhost")
    expect(result).not.toContain("opensploit-session")
  })

  test("orphaned end marker is left alone (not our session's problem)", () => {
    const content = [
      "127.0.0.1 localhost",
      "# end-opensploit-session:ses_abc",
      "::1 localhost",
    ].join("\n")

    const result = removeHostsBlock(content, "ses_abc")
    // Orphaned end marker with no matching start — left as-is
    // (removeHostsBlock only removes matched pairs for the target session)
    expect(result).toContain("127.0.0.1 localhost")
    expect(result).toContain("::1 localhost")
  })
})

// =============================================================================
// 8. PURGE (REMOVE ALL BLOCKS)
// =============================================================================

describe("removeAllBlocks", () => {
  test("removes all opensploit blocks", () => {
    const content = [
      "127.0.0.1 localhost",
      "# opensploit-session:ses_1",
      "10.10.10.1\tfirst.htb",
      "# end-opensploit-session:ses_1",
      "# opensploit-session:ses_2",
      "10.10.10.2\tsecond.htb",
      "# end-opensploit-session:ses_2",
      "::1 localhost",
    ].join("\n")

    const result = removeAllBlocks(content)
    expect(result).toContain("127.0.0.1 localhost")
    expect(result).toContain("::1 localhost")
    expect(result).not.toContain("opensploit-session")
    expect(result).not.toContain("first.htb")
    expect(result).not.toContain("second.htb")
  })

  test("no-op when no blocks present", () => {
    const content = "127.0.0.1 localhost\n::1 localhost"
    expect(removeAllBlocks(content)).toBe(content)
  })

  test("handles orphaned start marker (removes marker, preserves ambiguous lines)", () => {
    const content = [
      "127.0.0.1 localhost",
      "# opensploit-session:ses_orphan",
      "10.10.10.1\torphan.htb",
      "::1 localhost",
    ].join("\n")

    const result = removeAllBlocks(content)
    // Marker line itself is removed
    expect(result).not.toContain("opensploit-session")
    // Entries after orphaned marker are preserved (can't distinguish from legit entries)
    expect(result).toContain("127.0.0.1 localhost")
    expect(result).toContain("::1 localhost")
  })

  test("handles orphaned end marker (removes it)", () => {
    const content = [
      "127.0.0.1 localhost",
      "# end-opensploit-session:ses_orphan",
      "::1 localhost",
    ].join("\n")

    const result = removeAllBlocks(content)
    expect(result).not.toContain("opensploit-session")
    expect(result).toContain("127.0.0.1 localhost")
    expect(result).toContain("::1 localhost")
  })

  test("is idempotent", () => {
    const content = [
      "127.0.0.1 localhost",
      "# opensploit-session:ses_1",
      "10.10.10.1\ttarget.htb",
      "# end-opensploit-session:ses_1",
    ].join("\n")

    const first = removeAllBlocks(content)
    const second = removeAllBlocks(first)
    expect(second).toBe(first)
  })

  test("handles many stale blocks (254+ sessions)", () => {
    const lines = ["127.0.0.1 localhost"]
    for (let i = 0; i < 300; i++) {
      lines.push(`# opensploit-session:ses_stale_${i}`)
      lines.push(`10.10.${Math.floor(i / 256)}.${i % 256}\thost${i}.htb`)
      lines.push(`# end-opensploit-session:ses_stale_${i}`)
    }
    lines.push("::1 localhost")
    const content = lines.join("\n")

    const result = removeAllBlocks(content)
    expect(result).toContain("127.0.0.1 localhost")
    expect(result).toContain("::1 localhost")
    expect(result).not.toContain("opensploit-session")
    // Should be much shorter
    expect(result.split("\n").length).toBeLessThan(10)
  })
})
