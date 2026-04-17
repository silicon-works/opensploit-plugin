/**
 * Integration tests for the opensploit-hosts bash helper script.
 *
 * Since we can't run sudo in the test environment, these tests exercise
 * the script's validation logic (which exits before touching /etc/hosts)
 * and verify the script exists and is executable.
 */

import { describe, test, expect } from "bun:test"
import { spawn } from "bun"
import { existsSync } from "fs"
import { join } from "path"

const HELPER_PATH = join(import.meta.dir, "../../bin/opensploit-hosts")

async function runHelper(args: string[]): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const proc = spawn([HELPER_PATH, ...args], {
    stdout: "pipe",
    stderr: "pipe",
  })
  const stdout = await new Response(proc.stdout).text()
  const stderr = await new Response(proc.stderr).text()
  const exitCode = await proc.exited
  return { exitCode, stdout: stdout.trim(), stderr: stderr.trim() }
}

describe("opensploit-hosts helper script", () => {
  // ---------------------------------------------------------------------------
  // File existence and permissions
  // ---------------------------------------------------------------------------

  test("helper script exists", () => {
    expect(existsSync(HELPER_PATH)).toBe(true)
  })

  test("helper script is executable", async () => {
    const { exitCode } = await runHelper(["check"])
    expect(exitCode).toBe(0)
  })

  test("check action returns 'ok'", async () => {
    const { exitCode, stdout } = await runHelper(["check"])
    expect(exitCode).toBe(0)
    expect(stdout).toBe("ok")
  })

  // ---------------------------------------------------------------------------
  // Argument validation
  // ---------------------------------------------------------------------------

  test("no arguments — prints usage", async () => {
    const { exitCode, stderr } = await runHelper([])
    expect(exitCode).toBe(1)
    expect(stderr).toContain("Usage")
  })

  test("unknown action — error", async () => {
    const { exitCode, stderr } = await runHelper(["unknown"])
    expect(exitCode).toBe(1)
    expect(stderr).toContain("Unknown action")
  })

  test("add without session — prints usage", async () => {
    const { exitCode, stderr } = await runHelper(["add"])
    expect(exitCode).toBe(1)
    expect(stderr).toContain("Usage")
  })

  test("add with session but no entries — prints usage", async () => {
    const { exitCode, stderr } = await runHelper(["add", "ses_test"])
    expect(exitCode).toBe(1)
    expect(stderr).toContain("Usage")
  })

  test("remove without session — prints usage", async () => {
    const { exitCode, stderr } = await runHelper(["remove"])
    expect(exitCode).toBe(1)
    expect(stderr).toContain("Usage")
  })

  // ---------------------------------------------------------------------------
  // Session ID validation (defense in depth)
  // ---------------------------------------------------------------------------

  test("add with invalid session ID (semicolon) — rejected", async () => {
    const { exitCode, stderr } = await runHelper(["add", "ses;rm -rf /", "10.10.10.1 target.htb"])
    expect(exitCode).toBe(1)
    expect(stderr).toContain("Invalid session ID")
  })

  test("add with invalid session ID (backtick) — rejected", async () => {
    const { exitCode, stderr } = await runHelper(["add", "`id`", "10.10.10.1 target.htb"])
    expect(exitCode).toBe(1)
    expect(stderr).toContain("Invalid session ID")
  })

  test("add with invalid session ID (dollar paren) — rejected", async () => {
    const { exitCode, stderr } = await runHelper(["add", "$(id)", "10.10.10.1 target.htb"])
    expect(exitCode).toBe(1)
    expect(stderr).toContain("Invalid session ID")
  })

  test("add with invalid session ID (space) — rejected", async () => {
    const { exitCode, stderr } = await runHelper(["add", "ses test", "10.10.10.1 target.htb"])
    expect(exitCode).toBe(1)
    expect(stderr).toContain("Invalid session ID")
  })

  test("add with invalid session ID (dot) — rejected", async () => {
    const { exitCode, stderr } = await runHelper(["add", "ses.test", "10.10.10.1 target.htb"])
    expect(exitCode).toBe(1)
    expect(stderr).toContain("Invalid session ID")
  })

  test("remove with invalid session ID — rejected", async () => {
    const { exitCode, stderr } = await runHelper(["remove", "../../etc"])
    expect(exitCode).toBe(1)
    expect(stderr).toContain("Invalid session ID")
  })

  // ---------------------------------------------------------------------------
  // Entry validation (defense in depth)
  // ---------------------------------------------------------------------------

  test("add with invalid entry (no hostname) — rejected", async () => {
    const { exitCode, stderr } = await runHelper(["add", "ses_test", "10.10.10.1"])
    expect(exitCode).toBe(1)
    expect(stderr).toContain("Invalid entry")
  })

  test("add with invalid entry (shell injection) — rejected", async () => {
    const { exitCode, stderr } = await runHelper(["add", "ses_test", "10.10.10.1;id target.htb"])
    expect(exitCode).toBe(1)
    expect(stderr).toContain("Invalid entry")
  })

  test("add with valid entries passes validation", async () => {
    // This will fail at the /etc/hosts check (not root), not at validation
    const { exitCode, stderr } = await runHelper(["add", "ses_test", "10.10.10.1 target.htb"])
    // Exits with error because it can't write to /etc/hosts (not root)
    // But it should NOT be "Invalid session ID" or "Invalid entry"
    if (exitCode !== 0) {
      expect(stderr).not.toContain("Invalid session ID")
      expect(stderr).not.toContain("Invalid entry")
    }
  })

  test("remove with valid session passes validation", async () => {
    const { exitCode, stderr } = await runHelper(["remove", "ses_valid_test"])
    // May fail at /etc/hosts check, but validation should pass
    if (exitCode !== 0) {
      expect(stderr).not.toContain("Invalid session ID")
    }
  })

  // ---------------------------------------------------------------------------
  // IPv6 entry validation
  // ---------------------------------------------------------------------------

  test("add with IPv6 entry passes validation", async () => {
    const { exitCode, stderr } = await runHelper(["add", "ses_test", "::1 target.htb"])
    if (exitCode !== 0) {
      expect(stderr).not.toContain("Invalid entry")
    }
  })

  test("add with full IPv6 entry passes validation", async () => {
    const { exitCode, stderr } = await runHelper(["add", "ses_test", "2001:db8::1 target.htb"])
    if (exitCode !== 0) {
      expect(stderr).not.toContain("Invalid entry")
    }
  })
})
