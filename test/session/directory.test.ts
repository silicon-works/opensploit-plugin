import { describe, expect, test, afterEach } from "bun:test"
import { tmpdir } from "os"
import { join } from "path"
import { existsSync, writeFileSync, readFileSync } from "fs"
import * as SessionDirectory from "../../src/session/directory"

describe("session.directory", () => {
  const testSessionID = "test-session-12345"

  // Clean up after each test
  afterEach(() => {
    SessionDirectory.cleanup(testSessionID)
  })

  test("get returns correct path format", () => {
    const path = SessionDirectory.get(testSessionID)
    expect(path).toBe(join(tmpdir(), `opensploit-session-${testSessionID}`))
  })

  test("exists returns false for non-existent directory", () => {
    expect(SessionDirectory.exists(testSessionID)).toBe(false)
  })

  test("create creates directory with standard structure", () => {
    const dir = SessionDirectory.create(testSessionID)

    expect(existsSync(dir)).toBe(true)
    expect(existsSync(join(dir, "findings"))).toBe(true)
    expect(existsSync(join(dir, "artifacts"))).toBe(true)
    expect(existsSync(join(dir, "artifacts", "screenshots"))).toBe(true)
    expect(existsSync(join(dir, "artifacts", "loot"))).toBe(true)
  })

  test("exists returns true after create", () => {
    SessionDirectory.create(testSessionID)
    expect(SessionDirectory.exists(testSessionID)).toBe(true)
  })

  test("create is idempotent", () => {
    const dir1 = SessionDirectory.create(testSessionID)
    const dir2 = SessionDirectory.create(testSessionID)
    expect(dir1).toBe(dir2)
  })

  test("cleanup removes directory", () => {
    SessionDirectory.create(testSessionID)
    expect(SessionDirectory.exists(testSessionID)).toBe(true)

    SessionDirectory.cleanup(testSessionID)
    expect(SessionDirectory.exists(testSessionID)).toBe(false)
  })

  test("cleanup is safe on non-existent directory", () => {
    // Should not throw
    SessionDirectory.cleanup("non-existent-session")
  })

  test("filePath returns correct paths", () => {
    const path = SessionDirectory.filePath(testSessionID, "findings", "recon.md")
    expect(path).toBe(join(SessionDirectory.get(testSessionID), "findings", "recon.md"))
  })

  test("findingsDir returns correct path", () => {
    const dir = SessionDirectory.findingsDir(testSessionID)
    expect(dir).toBe(join(SessionDirectory.get(testSessionID), "findings"))
  })

  test("artifactsDir returns correct path", () => {
    const dir = SessionDirectory.artifactsDir(testSessionID)
    expect(dir).toBe(join(SessionDirectory.get(testSessionID), "artifacts"))
  })

  test("statePath returns correct path", () => {
    const path = SessionDirectory.statePath(testSessionID)
    expect(path).toBe(join(SessionDirectory.get(testSessionID), "state.yaml"))
  })

  test("writeFinding and readFinding work correctly", () => {
    SessionDirectory.create(testSessionID)

    const content = "# Reconnaissance Findings\n\nFound open ports: 22, 80, 443"
    SessionDirectory.writeFinding(testSessionID, "recon", content)

    const read = SessionDirectory.readFinding(testSessionID, "recon")
    expect(read).toBe(content)
  })

  test("readFinding returns null for non-existent file", () => {
    SessionDirectory.create(testSessionID)
    const read = SessionDirectory.readFinding(testSessionID, "non-existent")
    expect(read).toBeNull()
  })

  test("writeFinding creates findings directory if needed", () => {
    // Don't call create first - writeFinding should handle it
    const dir = SessionDirectory.get(testSessionID)

    // Manually create just the base directory
    const { mkdirSync } = require("fs")
    mkdirSync(dir, { recursive: true })

    const content = "test content"
    SessionDirectory.writeFinding(testSessionID, "test", content)

    const read = SessionDirectory.readFinding(testSessionID, "test")
    expect(read).toBe(content)
  })
})
