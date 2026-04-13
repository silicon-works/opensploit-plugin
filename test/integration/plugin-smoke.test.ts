/**
 * Integration smoke tests for the OpenSploit plugin.
 *
 * These tests exercise the plugin the way OpenCode loads it — through the
 * public API surface (default export, hooks, tool.execute()) — rather than
 * calling internal functions in isolation.
 *
 * They exist to catch three classes of bugs that slipped past 543 unit tests:
 *
 *   1. **stderr pollution** — log shim writes, LanceDB Rust warnings, or any
 *      other module-level side effects that write to stderr and corrupt the TUI.
 *
 *   2. **Zod validation failures on real data** — the RegistrySchema must
 *      accept the actual cached registry.yaml (which contains nulls in
 *      `values` arrays, extra fields, etc.).
 *
 *   3. **Tool execute() errors that only appear at runtime** — e.g. registry
 *      search returning "Registry unavailable" instead of results.
 *
 * Run:
 *   cd /home/nightshade/silicon-works/opensploit-plugin
 *   bun test test/integration/plugin-smoke.test.ts --timeout 60000
 */
import { describe, test, expect, afterEach, beforeAll } from "bun:test"
import { existsSync, readFileSync } from "fs"
import { spawn } from "bun"
import path from "path"
import os from "os"
import yaml from "js-yaml"
import type { ToolContext } from "@opencode-ai/plugin"
import * as SessionDirectory from "../../src/session/directory"
import { registerRootSession } from "../../src/session/hierarchy"

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PLUGIN_ROOT = "/home/nightshade/silicon-works/opensploit-plugin"
const TEST_SESSION_ID = "smoke-test-session-" + Date.now().toString(36)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Run a JS snippet in a child Bun process and capture its stderr.
 *
 * Bun's console.error() and native Rust writes bypass process.stderr.write,
 * so the only reliable way to detect stderr pollution is subprocess isolation.
 *
 * Returns only "real" stderr lines — filters out Bun's own package.json
 * parser warnings which are unrelated to our code.
 */
async function runAndCaptureStderr(script: string): Promise<{
  stdout: string
  stderr: string
  exitCode: number
}> {
  const proc = spawn({
    cmd: ["bun", "--no-install", "-e", script],
    cwd: PLUGIN_ROOT,
    stdout: "pipe",
    stderr: "pipe",
    env: {
      ...process.env,
      OPENSPLOIT_DEBUG: "",
      LANCE_LOG: "error",
    },
  })

  const [stdoutRaw, stderrRaw, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ])

  // Filter out Bun's own warnings about package.json fields that are
  // unrelated to our code (e.g., "This value must be a string" for the
  // exports config "enabled": true). These are Bun parser warnings, not
  // our stderr pollution.
  const stderr = stderrRaw
    .split("\n")
    .filter((line) => {
      const trimmed = line.trim()
      if (trimmed === "") return false
      if (trimmed.includes("package.json")) return false
      if (trimmed.startsWith("warn: This value must be")) return false
      if (/^\s*\d+\s*\|/.test(line)) return false // source line display
      if (/^\s*\^/.test(line)) return false // caret pointer
      return true
    })
    .join("\n")
    .trim()

  return { stdout: stdoutRaw.trim(), stderr, exitCode }
}

/** Minimal mock of PluginInput that satisfies the Plugin signature. */
const mockPluginInput = {
  client: {} as any,
  project: { name: "smoke-test" } as any,
  directory: "/tmp",
  worktree: "/tmp",
  serverUrl: new URL("http://localhost:4096"),
  $: (typeof Bun !== "undefined" ? Bun.$ : undefined) as any,
}

/** Minimal mock ToolContext for tool.execute() calls. */
function mockToolContext(sessionID: string = TEST_SESSION_ID): ToolContext {
  return {
    sessionID,
    messageID: "msg-smoke-001",
    agent: "pentest",
    directory: "/tmp",
    worktree: "/tmp",
    abort: new AbortController().signal,
    metadata: () => {},
    ask: async () => {},
  }
}

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

beforeAll(() => {
  // Map the test session to itself as root so engagement state tools work.
  registerRootSession(TEST_SESSION_ID, TEST_SESSION_ID)
})

afterEach(() => {
  // Clean up any session directory created during tests.
  SessionDirectory.cleanup(TEST_SESSION_ID)
})

// =============================================================================
// 1. No stderr pollution from module imports (subprocess-isolated)
//
// These tests spawn a child Bun process and verify zero stderr output.
// This catches:
//   - Log shim leaking to stderr (bug 1)
//   - LanceDB Rust warnings (bug 3)
//   - Any module-level console.error() or native fd(2) writes
// =============================================================================

describe("stderr pollution (subprocess-isolated)", () => {
  test("importing all plugin modules produces no stderr output", async () => {
    const result = await runAndCaptureStderr(`
      delete process.env.OPENSPLOIT_DEBUG;
      await import("./src/util/log");
      await import("./src/memory/database");
      await import("./src/memory/schema");
      await import("./src/memory/sparse");
      await import("./src/memory/embedding");
      await import("./src/session/hierarchy");
      await import("./src/session/directory");
      await import("./src/tools/engagement-state");
      await import("./src/tools/tool-registry-search");
      await import("./src/tools/mcp-tool");
      await import("./src/tools/browser-headed");
      await import("./src/tools/hosts");
      await import("./src/tools/output-store");
      await import("./src/tools/pattern-search");
      await import("./src/tools/save-pattern");
      await import("./src/container/manager");
      await import("./src/agents/index");
      console.log("OK");
    `)

    expect(result.exitCode).toBe(0)
    expect(result.stdout).toBe("OK")
    expect(result.stderr).toBe("")
  })

  test("plugin init and config hook produce no stderr output", async () => {
    const result = await runAndCaptureStderr(`
      delete process.env.OPENSPLOIT_DEBUG;
      const { default: plugin } = await import("./src/index");
      const hooks = await plugin({
        client: {},
        project: { name: "test" },
        directory: "/tmp",
        worktree: "/tmp",
        serverUrl: new URL("http://localhost:4096"),
        $: Bun.$,
      });
      const config = { agent: {} };
      await hooks.config(config);
      const agentCount = Object.keys(config.agent).length;
      console.log("agents:" + agentCount);
    `)

    expect(result.exitCode).toBe(0)
    expect(result.stderr).toBe("")
    // Verify config hook actually ran — agents were registered
    const agentCount = parseInt(result.stdout.split("agents:")[1], 10)
    expect(agentCount).toBeGreaterThan(0)
  })

  test("engagement state update+read in subprocess produces no stderr", async () => {
    const sid = "subprocess-" + Date.now().toString(36)
    const result = await runAndCaptureStderr(`
      delete process.env.OPENSPLOIT_DEBUG;
      const hierarchy = await import("./src/session/hierarchy");
      const tools = await import("./src/tools/engagement-state");
      const SD = await import("./src/session/directory");

      const sid = "${sid}";
      hierarchy.registerRootSession(sid, sid);

      const ctx = {
        sessionID: sid,
        messageID: "m1",
        agent: "pentest",
        directory: "/tmp",
        worktree: "/tmp",
        abort: new AbortController().signal,
        metadata: () => {},
        ask: async () => {},
      };

      const updateTool = tools.createUpdateEngagementStateTool();
      const readTool = tools.createReadEngagementStateTool();

      await updateTool.execute(
        { ports: [{ port: 22, protocol: "tcp", service: "ssh" }] },
        ctx,
      );
      const readResult = await readTool.execute({}, ctx);

      // Cleanup
      SD.cleanup(sid);

      console.log(readResult.includes("22") && readResult.includes("ssh") ? "OK" : "FAIL");
    `)

    expect(result.exitCode).toBe(0)
    expect(result.stdout).toBe("OK")
    expect(result.stderr).toBe("")
  })
})

// =============================================================================
// 2. Registry YAML validates against real cached file
//
// This catches bug 2: strict Zod validation rejecting real registry data
// (specifically, null values in `values` arrays).
// =============================================================================

describe("registry schema validation on real data", () => {
  const registryPath = path.join(os.homedir(), ".opensploit", "registry.yaml")
  const registryExists = existsSync(registryPath)

  test.skipIf(!registryExists)(
    "RegistrySchema.parse() succeeds on the real cached registry.yaml",
    () => {
      const { RegistrySchema } = require("../../src/tools/tool-registry-search")

      const text = readFileSync(registryPath, "utf-8")
      const parsed = yaml.load(text)

      // This is the exact code path that was failing — loadCacheFromDisk()
      // calls RegistrySchema.parse(parsed). If the schema is too strict
      // (e.g. does not allow null in `values` arrays), this throws.
      expect(() => RegistrySchema.parse(parsed)).not.toThrow()
    },
  )

  test.skipIf(!registryExists)(
    "real registry YAML contains the null-in-values pattern that caused the bug",
    () => {
      // This test documents the specific data shape. If the registry YAML is
      // ever regenerated without nulls in `values`, this test can be removed,
      // but the schema should still accept them defensively.
      const text = readFileSync(registryPath, "utf-8")
      const parsed = yaml.load(text) as any

      // Walk tools looking for any values array with a null entry
      let foundNull = false
      for (const tool of Object.values(parsed.tools ?? {})) {
        const t = tool as any
        for (const method of Object.values(t.methods ?? {})) {
          const m = method as any
          for (const param of Object.values(m.params ?? {})) {
            const p = param as any
            if (Array.isArray(p.values) && p.values.some((v: any) => v === null)) {
              foundNull = true
            }
          }
        }
      }
      expect(foundNull).toBe(true)
    },
  )

  test("ParamDef values field accepts arrays containing null", () => {
    // Minimal regression test that does not depend on a cache file existing.
    // This is the pure schema regression guard — if someone removes .nullable()
    // from the ParamDefSchema values field, this test fails.
    const { RegistryToolSchema } = require("../../src/tools/tool-registry-search")

    const tool = RegistryToolSchema.parse({
      name: "test-tool",
      description: "Regression test for null-in-values",
      methods: {
        scan: {
          description: "test method",
          params: {
            scan_type: {
              type: "string",
              values: ["syn", "connect", null, "udp"],
            },
          },
        },
      },
    })

    expect(tool.methods!.scan.params!.scan_type.values).toContain(null)
  })

  test("RegistrySchema accepts tools with extra/passthrough fields", () => {
    // Registry tools often contain fields like see_also, warnings, internal
    // that aren't in the strict schema. The schema must use .passthrough().
    const { RegistrySchema } = require("../../src/tools/tool-registry-search")

    const registry = RegistrySchema.parse({
      version: "2.0",
      custom_metadata: "should be kept",
      tools: {
        nmap: {
          name: "nmap",
          description: "Network scanner",
          see_also: ["masscan"],
          internal: true,
          custom_field: 42,
        },
      },
    })

    expect((registry as any).custom_metadata).toBe("should be kept")
    expect((registry.tools.nmap as any).see_also).toEqual(["masscan"])
    expect((registry.tools.nmap as any).internal).toBe(true)
    expect((registry.tools.nmap as any).custom_field).toBe(42)
  })
})

// =============================================================================
// 3. Tool execute() calls produce correct results
//
// These run in-process (not subprocess) because we need to verify return
// values and behavior, not just stderr.
// =============================================================================

describe("tool execute() integration", () => {
  test("engagement state round-trip: update then read returns consistent data", async () => {
    const {
      createUpdateEngagementStateTool,
      createReadEngagementStateTool,
    } = await import("../../src/tools/engagement-state")

    const updateTool = createUpdateEngagementStateTool()
    const readTool = createReadEngagementStateTool()
    const ctx = mockToolContext()

    // Update
    const updateResult = await updateTool.execute(
      {
        target: { ip: "10.10.10.42", hostname: "smoke.htb" },
        ports: [
          { port: 22, protocol: "tcp", service: "ssh" },
          { port: 80, protocol: "tcp", service: "http" },
        ],
        accessLevel: "none",
      } as any,
      ctx,
    )

    expect(updateResult).toContain("Engagement State Updated")
    expect(updateResult).toContain("10.10.10.42")
    expect(updateResult).toContain("ports: +2")

    // Read back
    const readResult = await readTool.execute({} as any, ctx)

    expect(readResult).toContain("10.10.10.42")
    expect(readResult).toContain("smoke.htb")
    expect(readResult).toContain("22")
    expect(readResult).toContain("ssh")
    expect(readResult).toContain("80")
    expect(readResult).toContain("http")
    expect(readResult).not.toContain("No engagement state")
  })

  test("engagement state merge: second update appends, does not replace", async () => {
    const {
      createUpdateEngagementStateTool,
      createReadEngagementStateTool,
    } = await import("../../src/tools/engagement-state")

    const updateTool = createUpdateEngagementStateTool()
    const readTool = createReadEngagementStateTool()
    const ctx = mockToolContext()

    // First update
    await updateTool.execute(
      { ports: [{ port: 22, protocol: "tcp", service: "ssh" }] } as any,
      ctx,
    )

    // Second update — should merge, not replace
    await updateTool.execute(
      { ports: [{ port: 80, protocol: "tcp", service: "http" }] } as any,
      ctx,
    )

    const readResult = await readTool.execute({} as any, ctx)
    expect(readResult).toContain("22")
    expect(readResult).toContain("80")
  })

  test("read_engagement_state on empty session returns guidance, not error", async () => {
    const { createReadEngagementStateTool } = await import(
      "../../src/tools/engagement-state"
    )
    const readTool = createReadEngagementStateTool()

    // Use a unique session that has never been written to
    const emptyCtx = mockToolContext("empty-session-" + Date.now().toString(36))
    const result = await readTool.execute({} as any, emptyCtx)

    // Should get a helpful message, not an error or stack trace
    expect(result).toContain("update_engagement_state")
    expect(result).not.toContain("Error")
    expect(result).not.toContain("error")
  })
})

// =============================================================================
// 4. Plugin tool registration is complete and structurally sound
// =============================================================================

describe("plugin structure", () => {
  test("plugin registers all expected tools", async () => {
    const { default: plugin } = await import("../../src/index")
    const hooks = await plugin(mockPluginInput)

    const expectedTools = [
      "mcp_tool",
      "update_engagement_state",
      "read_engagement_state",
      "browser_headed_mode",
      "hosts",
      "tool_registry_search",
      "pattern_search",
      "save_pattern",
    ]

    for (const toolName of expectedTools) {
      expect(hooks.tool).toHaveProperty(toolName)
    }
  })

  test("plugin registers all expected hooks", async () => {
    const { default: plugin } = await import("../../src/index")
    const hooks = await plugin(mockPluginInput)

    expect(hooks.config).toBeTypeOf("function")
    expect(hooks.event).toBeTypeOf("function")
    expect(hooks["experimental.chat.system.transform"]).toBeTypeOf("function")
    expect(hooks["tool.execute.before"]).toBeTypeOf("function")
    expect(hooks["tool.execute.after"]).toBeTypeOf("function")
    expect(hooks["permission.ask"]).toBeTypeOf("function")
    expect(hooks["experimental.session.compacting"]).toBeTypeOf("function")
  })

  test("each tool has a description and execute function", async () => {
    const { default: plugin } = await import("../../src/index")
    const hooks = await plugin(mockPluginInput)

    for (const [name, toolDef] of Object.entries(hooks.tool!)) {
      expect(toolDef.description).toBeTypeOf("string")
      expect(toolDef.description.length).toBeGreaterThan(10)
      expect(toolDef.execute).toBeTypeOf("function")
    }
  })

  test("config hook sets default_agent to pentest", async () => {
    const { default: plugin } = await import("../../src/index")
    const hooks = await plugin(mockPluginInput)

    const config: any = { agent: {} }
    await hooks.config!(config)

    expect(config.default_agent).toBe("pentest")
  })
})

// =============================================================================
// 5. Log shim design verification
// =============================================================================

describe("log shim", () => {
  test("createLog returns no-op functions when OPENSPLOIT_DEBUG is unset", async () => {
    // Verify via subprocess — the log module reads env at module load time,
    // so in-process testing is unreliable due to module caching.
    const result = await runAndCaptureStderr(`
      delete process.env.OPENSPLOIT_DEBUG;

      // Force fresh module load by importing the source directly
      const { createLog } = await import("./src/util/log");
      const log = createLog("test-component");

      // Call every method — none should produce output
      log.info("should not appear");
      log.warn("should not appear");
      log.error("should not appear");
      log.debug("should not appear");

      console.log("OK");
    `)

    expect(result.exitCode).toBe(0)
    expect(result.stdout).toBe("OK")
    expect(result.stderr).toBe("")
  })

  test("createLog writes to stderr when OPENSPLOIT_DEBUG=true", async () => {
    const result = await runAndCaptureStderr(`
      process.env.OPENSPLOIT_DEBUG = "true";

      const { createLog } = await import("./src/util/log");
      const log = createLog("test-component");

      log.info("visible message");
      console.log("OK");
    `)

    // When debug is on, the message should appear on stderr
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toBe("OK")
    expect(result.stderr).toContain("visible message")
    expect(result.stderr).toContain("test-component")
  })
})

// =============================================================================
// 6. LanceDB env suppression
// =============================================================================

describe("LanceDB stderr suppression", () => {
  test("LANCE_LOG is set to error after importing database module", async () => {
    const result = await runAndCaptureStderr(`
      // Clear LANCE_LOG to test the guard
      delete process.env.LANCE_LOG;

      await import("./src/memory/database");
      console.log("LANCE_LOG=" + process.env.LANCE_LOG);
    `)

    expect(result.exitCode).toBe(0)
    expect(result.stdout).toBe("LANCE_LOG=error")
    expect(result.stderr).toBe("")
  })

  test("LANCE_LOG is not overwritten if already set by user", async () => {
    const result = await runAndCaptureStderr(`
      // User explicitly sets a different level
      process.env.LANCE_LOG = "debug";

      await import("./src/memory/database");
      console.log("LANCE_LOG=" + process.env.LANCE_LOG);
    `)

    expect(result.exitCode).toBe(0)
    // The guard is: if (!process.env["LANCE_LOG"]) { ... }
    // So user's value should be preserved.
    expect(result.stdout).toBe("LANCE_LOG=debug")
  })
})
