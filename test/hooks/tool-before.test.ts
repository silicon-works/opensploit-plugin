import { describe, test, expect, afterEach } from "bun:test"
import { toolBeforeHook } from "../../src/hooks/tool-before"
import { registerRootSession, unregister } from "../../src/session/hierarchy"
import * as SessionDirectory from "../../src/session/directory"

/**
 * Tests for the tool.execute.before hook.
 *
 * Verifies /session/ path rewriting for file tools and bash commands.
 * Uses real session directories for accurate path translation.
 */

const ROOT = "test-toolbefore-root"
const CHILD = "test-toolbefore-child"

afterEach(() => {
  SessionDirectory.cleanup(ROOT)
  unregister(CHILD)
  unregister(ROOT)
})

describe("hook.tool-before", () => {
  // ---------------------------------------------------------------------------
  // Path rewriting for file tools (read, write, edit, glob, grep, list)
  // ---------------------------------------------------------------------------

  describe("file tool path rewriting", () => {
    test("translates /session/ in filePath for read tool", async () => {
      SessionDirectory.create(ROOT)
      const sessionDir = SessionDirectory.get(ROOT)

      const output = { args: { filePath: "/session/findings/recon.md" } }
      await toolBeforeHook({ tool: "read", sessionID: ROOT, callID: "c1" }, output)

      expect(output.args.filePath).toBe(`${sessionDir}/findings/recon.md`)
      expect(output.args.filePath).not.toContain("/session/")
    })

    test("translates /session/ in filePath for write tool", async () => {
      SessionDirectory.create(ROOT)
      const sessionDir = SessionDirectory.get(ROOT)

      const output = { args: { filePath: "/session/artifacts/loot.txt" } }
      await toolBeforeHook({ tool: "write", sessionID: ROOT, callID: "c1" }, output)

      expect(output.args.filePath).toBe(`${sessionDir}/artifacts/loot.txt`)
    })

    test("translates /session/ in filePath for edit tool", async () => {
      SessionDirectory.create(ROOT)
      const sessionDir = SessionDirectory.get(ROOT)

      const output = { args: { filePath: "/session/state.yaml" } }
      await toolBeforeHook({ tool: "edit", sessionID: ROOT, callID: "c1" }, output)

      expect(output.args.filePath).toBe(`${sessionDir}/state.yaml`)
    })

    test("translates /session/ in path for glob tool", async () => {
      SessionDirectory.create(ROOT)
      const sessionDir = SessionDirectory.get(ROOT)

      const output = { args: { path: "/session/findings" } }
      await toolBeforeHook({ tool: "glob", sessionID: ROOT, callID: "c1" }, output)

      expect(output.args.path).toBe(`${sessionDir}/findings`)
    })

    test("does not translate non-session paths", async () => {
      const output = { args: { filePath: "/home/user/file.txt" } }
      await toolBeforeHook({ tool: "read", sessionID: ROOT, callID: "c1" }, output)

      expect(output.args.filePath).toBe("/home/user/file.txt")
    })

    test("does not modify args for non-file tools", async () => {
      const output = { args: { filePath: "/session/test.txt" } }
      await toolBeforeHook({ tool: "websearch", sessionID: ROOT, callID: "c1" }, output)

      // websearch is NOT a file tool — path should stay unchanged
      expect(output.args.filePath).toBe("/session/test.txt")
    })
  })

  // ---------------------------------------------------------------------------
  // Path rewriting for bash commands
  // ---------------------------------------------------------------------------

  describe("bash path rewriting", () => {
    test("translates /session/ in bash command", async () => {
      SessionDirectory.create(ROOT)
      const sessionDir = SessionDirectory.get(ROOT)

      const output = { args: { command: "cat /session/findings/recon.md" } }
      await toolBeforeHook({ tool: "bash", sessionID: ROOT, callID: "c1" }, output)

      expect(output.args.command).toBe(`cat ${sessionDir}/findings/recon.md`)
      expect(output.args.command).not.toContain("/session/")
    })

    test("translates multiple /session/ occurrences in one command", async () => {
      SessionDirectory.create(ROOT)
      const sessionDir = SessionDirectory.get(ROOT)

      const output = { args: { command: "cp /session/a.txt /session/b.txt" } }
      await toolBeforeHook({ tool: "bash", sessionID: ROOT, callID: "c1" }, output)

      expect(output.args.command).toBe(`cp ${sessionDir}/a.txt ${sessionDir}/b.txt`)
    })

    test("translates /session/ in bash workdir", async () => {
      SessionDirectory.create(ROOT)
      const sessionDir = SessionDirectory.get(ROOT)

      const output = { args: { command: "ls", workdir: "/session/findings" } }
      await toolBeforeHook({ tool: "bash", sessionID: ROOT, callID: "c1" }, output)

      expect(output.args.workdir).toBe(`${sessionDir}/findings`)
    })

    test("does not modify bash commands without /session/", async () => {
      const output = { args: { command: "echo hello" } }
      await toolBeforeHook({ tool: "bash", sessionID: ROOT, callID: "c1" }, output)

      expect(output.args.command).toBe("echo hello")
    })
  })

  // ---------------------------------------------------------------------------
  // Child session uses root session directory
  // ---------------------------------------------------------------------------

  describe("child session path resolution", () => {
    test("child session paths resolve to root session directory", async () => {
      registerRootSession(CHILD, ROOT)
      SessionDirectory.create(ROOT)
      const sessionDir = SessionDirectory.get(ROOT)

      const output = { args: { filePath: "/session/state.yaml" } }
      await toolBeforeHook({ tool: "read", sessionID: CHILD, callID: "c1" }, output)

      // Should resolve to ROOT's session dir, not child's
      expect(output.args.filePath).toBe(`${sessionDir}/state.yaml`)
      expect(output.args.filePath).toContain(ROOT)
    })
  })
})
