import { describe, test, expect, afterEach } from "bun:test"
import type { ToolContext } from "@opencode-ai/plugin"
import { createBrowserHeadedTool } from "../../src/tools/browser-headed"
import { ContainerManager } from "../../src/container/manager"

/**
 * Behavioral tests for the browser-headed tool.
 *
 * The tool switches Playwright MCP containers between headed (VNC) and headless mode
 * by setting/clearing env overrides on ContainerManager. No Docker containers are
 * running in tests — ContainerManager.stopContainer() is a no-op when no container
 * exists, and env override functions work purely in-memory.
 *
 * We exercise execute() directly and verify:
 *   - Output messages for each code path (enable/disable, with/without VPN)
 *   - Metadata emissions (title, mode, vnc_url)
 *   - Env overrides actually applied/cleared on ContainerManager
 *   - VNC URL format
 */

const PLAYWRIGHT_NAMES = ["playwright-mcp", "playwright"]
const VNC_URL = "http://localhost:6080/vnc_lite.html?autoconnect=true&resize=scale"

const headedTool = createBrowserHeadedTool()

/** Build a minimal ToolContext that captures metadata calls. */
function makeContext(sessionId = "test-browser-session") {
  const metadataCalls: Array<{ title?: string; metadata?: Record<string, any> }> = []
  const ctx: ToolContext = {
    sessionID: sessionId,
    messageID: "test-msg",
    agent: "pentest",
    directory: "/tmp",
    worktree: "/tmp",
    abort: new AbortController().signal,
    metadata: (input) => {
      metadataCalls.push(input)
    },
    ask: async () => {},
  }
  return { ctx, metadataCalls }
}

describe("tool.browser-headed", () => {
  // Clean env overrides between tests so state doesn't leak
  afterEach(() => {
    for (const name of PLAYWRIGHT_NAMES) {
      ContainerManager.clearEnvOverrides(name)
    }
  })

  // ---------------------------------------------------------------------------
  // enable=true — basic headed mode
  // ---------------------------------------------------------------------------

  describe("enable=true (headed mode)", () => {
    test("returns VNC URL in output", async () => {
      const { ctx } = makeContext()
      const result = await headedTool.execute({ enable: true }, ctx)

      expect(result).toContain(VNC_URL)
    })

    test("output confirms headed mode switch", async () => {
      const { ctx } = makeContext()
      const result = await headedTool.execute({ enable: true }, ctx)

      expect(result).toContain("HEADED mode")
    })

    test("output includes next-steps guidance", async () => {
      const { ctx } = makeContext()
      const result = await headedTool.execute({ enable: true }, ctx)

      expect(result).toContain("Next steps")
      expect(result).toContain("CAPTCHA")
    })

    test("sets HEADED=1 env override on all playwright tool names", async () => {
      const { ctx } = makeContext()
      await headedTool.execute({ enable: true }, ctx)

      for (const name of PLAYWRIGHT_NAMES) {
        const overrides = ContainerManager.getEnvOverrides(name)
        expect(overrides).toBeDefined()
        expect(overrides!.HEADED).toBe("1")
      }
    })

    test("does not set VPN env vars when vpn params omitted", async () => {
      const { ctx } = makeContext()
      await headedTool.execute({ enable: true }, ctx)

      for (const name of PLAYWRIGHT_NAMES) {
        const overrides = ContainerManager.getEnvOverrides(name)
        expect(overrides).toBeDefined()
        expect(overrides!.VPN_TARGET).toBeUndefined()
        expect(overrides!.VPN_HOSTNAME).toBeUndefined()
      }
    })

    test("output does NOT contain VPN proxy info when no vpn params", async () => {
      const { ctx } = makeContext()
      const result = await headedTool.execute({ enable: true }, ctx)

      expect(result).not.toContain("VPN proxy")
      expect(result).not.toContain("socat")
    })
  })

  // ---------------------------------------------------------------------------
  // enable=true with VPN parameters
  // ---------------------------------------------------------------------------

  describe("enable=true with VPN params", () => {
    test("sets VPN_TARGET env override", async () => {
      const { ctx } = makeContext()
      await headedTool.execute(
        { enable: true, vpn_target: "10.129.221.199", vpn_hostname: "target.htb" },
        ctx
      )

      for (const name of PLAYWRIGHT_NAMES) {
        const overrides = ContainerManager.getEnvOverrides(name)
        expect(overrides!.VPN_TARGET).toBe("10.129.221.199")
      }
    })

    test("sets VPN_HOSTNAME env override", async () => {
      const { ctx } = makeContext()
      await headedTool.execute(
        { enable: true, vpn_target: "10.129.221.199", vpn_hostname: "target.htb" },
        ctx
      )

      for (const name of PLAYWRIGHT_NAMES) {
        const overrides = ContainerManager.getEnvOverrides(name)
        expect(overrides!.VPN_HOSTNAME).toBe("target.htb")
      }
    })

    test("output includes VPN proxy info line", async () => {
      const { ctx } = makeContext()
      const result = await headedTool.execute(
        { enable: true, vpn_target: "10.129.221.199", vpn_hostname: "target.htb" },
        ctx
      )

      expect(result).toContain("VPN proxy")
      expect(result).toContain("target.htb")
      expect(result).toContain("10.129.221.199")
      expect(result).toContain("socat")
    })

    test("sets VPN_TARGET_HTTPS when vpn_https=true", async () => {
      const { ctx } = makeContext()
      await headedTool.execute(
        { enable: true, vpn_target: "10.129.1.1", vpn_hostname: "ssl.htb", vpn_https: true },
        ctx
      )

      for (const name of PLAYWRIGHT_NAMES) {
        const overrides = ContainerManager.getEnvOverrides(name)
        expect(overrides!.VPN_TARGET_HTTPS).toBe("1")
      }
    })

    test("does not set VPN_TARGET_HTTPS when vpn_https is false or absent", async () => {
      const { ctx } = makeContext()
      await headedTool.execute(
        { enable: true, vpn_target: "10.129.1.1", vpn_hostname: "nohttps.htb" },
        ctx
      )

      for (const name of PLAYWRIGHT_NAMES) {
        const overrides = ContainerManager.getEnvOverrides(name)
        expect(overrides!.VPN_TARGET_HTTPS).toBeUndefined()
      }
    })

    test("VPN proxy info shows hostname-to-target mapping", async () => {
      const { ctx } = makeContext()
      const result = await headedTool.execute(
        { enable: true, vpn_target: "10.129.50.50", vpn_hostname: "box.htb" },
        ctx
      )

      // The format is: "VPN proxy: box.htb → 127.0.0.1 → socat → 10.129.50.50"
      expect(result).toContain("box.htb")
      expect(result).toContain("127.0.0.1")
      expect(result).toContain("10.129.50.50")
    })
  })

  // ---------------------------------------------------------------------------
  // enable=false — headless mode
  // ---------------------------------------------------------------------------

  describe("enable=false (headless mode)", () => {
    test("returns headless confirmation", async () => {
      const { ctx } = makeContext()
      const result = await headedTool.execute({ enable: false }, ctx)

      expect(result).toContain("HEADLESS mode")
    })

    test("output does not contain VNC URL", async () => {
      const { ctx } = makeContext()
      const result = await headedTool.execute({ enable: false }, ctx)

      expect(result).not.toContain("6080")
      expect(result).not.toContain("vnc_lite")
    })

    test("clears env overrides that were previously set", async () => {
      const { ctx } = makeContext()

      // First enable headed mode to set overrides
      await headedTool.execute(
        { enable: true, vpn_target: "10.129.1.1", vpn_hostname: "target.htb" },
        ctx
      )

      // Verify overrides are set
      for (const name of PLAYWRIGHT_NAMES) {
        expect(ContainerManager.getEnvOverrides(name)).toBeDefined()
      }

      // Now disable — should clear
      await headedTool.execute({ enable: false }, ctx)

      for (const name of PLAYWRIGHT_NAMES) {
        expect(ContainerManager.getEnvOverrides(name)).toBeUndefined()
      }
    })

    test("clears overrides on all known playwright tool names", async () => {
      // Manually set overrides on both names
      for (const name of PLAYWRIGHT_NAMES) {
        ContainerManager.setEnvOverrides(name, { HEADED: "1" })
      }

      const { ctx } = makeContext()
      await headedTool.execute({ enable: false }, ctx)

      for (const name of PLAYWRIGHT_NAMES) {
        expect(ContainerManager.getEnvOverrides(name)).toBeUndefined()
      }
    })

    test("is safe to call disable when no overrides are set", async () => {
      const { ctx } = makeContext()
      // Should not throw
      const result = await headedTool.execute({ enable: false }, ctx)
      expect(result).toContain("HEADLESS")
    })
  })

  // ---------------------------------------------------------------------------
  // Metadata emissions
  // ---------------------------------------------------------------------------

  describe("metadata", () => {
    test("enable emits title 'Browser: Headed Mode'", async () => {
      const { ctx, metadataCalls } = makeContext()
      await headedTool.execute({ enable: true }, ctx)

      expect(metadataCalls).toHaveLength(1)
      expect(metadataCalls[0].title).toBe("Browser: Headed Mode")
    })

    test("enable emits metadata with mode=headed and vnc_url", async () => {
      const { ctx, metadataCalls } = makeContext()
      await headedTool.execute({ enable: true }, ctx)

      expect(metadataCalls[0].metadata?.success).toBe(true)
      expect(metadataCalls[0].metadata?.mode).toBe("headed")
      expect(metadataCalls[0].metadata?.vnc_url).toBe(VNC_URL)
    })

    test("disable emits title 'Browser: Headless Mode'", async () => {
      const { ctx, metadataCalls } = makeContext()
      await headedTool.execute({ enable: false }, ctx)

      expect(metadataCalls).toHaveLength(1)
      expect(metadataCalls[0].title).toBe("Browser: Headless Mode")
    })

    test("disable emits metadata with mode=headless and success=true", async () => {
      const { ctx, metadataCalls } = makeContext()
      await headedTool.execute({ enable: false }, ctx)

      expect(metadataCalls[0].metadata?.success).toBe(true)
      expect(metadataCalls[0].metadata?.mode).toBe("headless")
    })

    test("disable metadata does not include vnc_url", async () => {
      const { ctx, metadataCalls } = makeContext()
      await headedTool.execute({ enable: false }, ctx)

      expect(metadataCalls[0].metadata?.vnc_url).toBeUndefined()
    })

    test("exactly one metadata call per execute", async () => {
      const { ctx: ctx1, metadataCalls: meta1 } = makeContext()
      const { ctx: ctx2, metadataCalls: meta2 } = makeContext()

      await headedTool.execute({ enable: true }, ctx1)
      await headedTool.execute({ enable: false }, ctx2)

      expect(meta1).toHaveLength(1)
      expect(meta2).toHaveLength(1)
    })
  })

  // ---------------------------------------------------------------------------
  // Round-trip: headed → headless cycle
  // ---------------------------------------------------------------------------

  describe("round-trip cycle", () => {
    test("enable then disable restores clean state", async () => {
      const { ctx } = makeContext()

      await headedTool.execute(
        { enable: true, vpn_target: "10.129.1.1", vpn_hostname: "cycle.htb" },
        ctx
      )

      // Overrides should be set
      const overrides = ContainerManager.getEnvOverrides("playwright-mcp")
      expect(overrides).toBeDefined()
      expect(overrides!.HEADED).toBe("1")
      expect(overrides!.VPN_TARGET).toBe("10.129.1.1")

      await headedTool.execute({ enable: false }, ctx)

      // Overrides should be cleared
      for (const name of PLAYWRIGHT_NAMES) {
        expect(ContainerManager.getEnvOverrides(name)).toBeUndefined()
      }
    })

    test("re-enabling with different VPN target overwrites previous overrides", async () => {
      const { ctx } = makeContext()

      await headedTool.execute(
        { enable: true, vpn_target: "10.129.1.1", vpn_hostname: "first.htb" },
        ctx
      )
      await headedTool.execute(
        { enable: true, vpn_target: "10.129.2.2", vpn_hostname: "second.htb" },
        ctx
      )

      for (const name of PLAYWRIGHT_NAMES) {
        const overrides = ContainerManager.getEnvOverrides(name)
        expect(overrides!.VPN_TARGET).toBe("10.129.2.2")
        expect(overrides!.VPN_HOSTNAME).toBe("second.htb")
      }
    })
  })

  // ---------------------------------------------------------------------------
  // VNC URL format
  // ---------------------------------------------------------------------------

  describe("VNC URL format", () => {
    test("URL uses localhost:6080", async () => {
      const { ctx } = makeContext()
      const result = await headedTool.execute({ enable: true }, ctx)

      expect(result).toContain("localhost:6080")
    })

    test("URL includes autoconnect parameter", async () => {
      const { ctx } = makeContext()
      const result = await headedTool.execute({ enable: true }, ctx)

      expect(result).toContain("autoconnect=true")
    })

    test("URL includes resize=scale parameter", async () => {
      const { ctx } = makeContext()
      const result = await headedTool.execute({ enable: true }, ctx)

      expect(result).toContain("resize=scale")
    })

    test("URL uses vnc_lite.html endpoint", async () => {
      const { ctx } = makeContext()
      const result = await headedTool.execute({ enable: true }, ctx)

      expect(result).toContain("vnc_lite.html")
    })

    test("metadata vnc_url matches output URL exactly", async () => {
      const { ctx, metadataCalls } = makeContext()
      const result = await headedTool.execute({ enable: true }, ctx)

      const metaUrl = metadataCalls[0].metadata?.vnc_url as string
      expect(result).toContain(metaUrl)
    })
  })
})
