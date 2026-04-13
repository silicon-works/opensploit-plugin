import z from "zod"
import { tool, type ToolContext } from "@opencode-ai/plugin"
import { ContainerManager } from "../container/manager"
import { createLog } from "../util/log"

const log = createLog("tool.browser-headed")

const DESCRIPTION = `Switch the Playwright browser between headed (VNC-visible) and headless modes.

Use this tool when a CAPTCHA or interactive challenge requires human intervention:
- Headed mode: Browser renders on a virtual display accessible via VNC at http://localhost:6080/vnc_lite.html?autoconnect=true&resize=scale
- Headless mode: Default, no display (faster, VPN-compatible without proxy)

When switching to headed mode with a VPN target, a socat proxy is automatically configured
so the headed Chromium browser can reach VPN IPs (works around a known Chromium bug).

This tool stops the existing Playwright container and configures the next one to start
in the requested mode. The next mcp_tool call to Playwright will use the new mode.

Example workflow:
1. browser_headed_mode(enable=true, vpn_target="10.129.x.x", vpn_hostname="target.htb")
2. mcp_tool(tool="playwright-mcp", method="browser_navigate", args={url: "http://target.htb/register"})
3. Fill form fields with mcp_tool calls
4. Tell user: "Open http://localhost:6080/vnc_lite.html?autoconnect=true&resize=scale to solve the CAPTCHA and submit the form"
5. After user confirms, continue with headless: browser_headed_mode(enable=false)`

// Tool name pattern used for playwright in the container map
// This must match what agents pass as the "tool" parameter to mcp_tool
const PLAYWRIGHT_TOOL_NAMES = ["playwright-mcp", "playwright"]

function findPlaywrightToolName(): string | undefined {
  const status = ContainerManager.getStatus()
  for (const name of PLAYWRIGHT_TOOL_NAMES) {
    if (status.some((c) => c.toolName === name)) {
      return name
    }
  }
  return undefined
}

export function createBrowserHeadedTool() {
  return tool({
    description: DESCRIPTION,
    args: {
      enable: z
        .boolean()
        .describe("true to switch to headed mode (VNC visible), false to switch back to headless"),
      vpn_target: z
        .string()
        .optional()
        .describe("VPN target IP address (e.g., '10.129.221.199'). Required for VPN targets in headed mode."),
      vpn_hostname: z
        .string()
        .optional()
        .describe("VPN hostname(s) comma-separated (e.g., 'target.htb' or 'host1.htb,host2.htb'). Required for VPN targets in headed mode."),
      vpn_https: z
        .boolean()
        .optional()
        .describe("Whether the VPN target also serves HTTPS (port 443). Default: false."),
    },
    async execute(params, ctx: ToolContext): Promise<string> {
      const enable = params.enable as boolean
      const vpn_target = params.vpn_target as string | undefined
      const vpn_hostname = params.vpn_hostname as string | undefined
      const vpn_https = params.vpn_https as boolean | undefined

      // Find the running playwright container (try known names)
      const runningName = findPlaywrightToolName()

      if (enable) {
        // Switch to headed mode
        log.info("switching to headed mode", { vpn_target, vpn_hostname })

        // Stop existing headless container if running
        if (runningName) {
          log.info("stopping existing container", { toolName: runningName })
          await ContainerManager.stopContainer(runningName)
        }

        // Set env overrides for next container start
        const env: Record<string, string> = { HEADED: "1" }
        if (vpn_target) env.VPN_TARGET = vpn_target
        if (vpn_hostname) env.VPN_HOSTNAME = vpn_hostname
        if (vpn_https) env.VPN_TARGET_HTTPS = "1"

        // Apply overrides to all known playwright tool names
        for (const name of PLAYWRIGHT_TOOL_NAMES) {
          ContainerManager.setEnvOverrides(name, env)
        }

        const vncUrl = "http://localhost:6080/vnc_lite.html?autoconnect=true&resize=scale"
        const proxyInfo = vpn_target && vpn_hostname
          ? `\nVPN proxy: ${vpn_hostname} → 127.0.0.1 → socat → ${vpn_target}`
          : ""

        ctx.metadata({
          title: "Browser: Headed Mode",
          metadata: { success: true, mode: "headed", vnc_url: vncUrl },
        })

        return `Browser switched to HEADED mode.\n\nVNC URL: ${vncUrl}\nThe browser will be visible via VNC when the next Playwright tool call is made.${proxyInfo}\n\nNext steps:\n1. Use mcp_tool to navigate and fill the form\n2. Tell the user to open ${vncUrl} to solve the CAPTCHA\n3. After the user confirms, continue normally`
      } else {
        // Switch back to headless mode
        log.info("switching to headless mode")

        // Stop existing headed container if running
        if (runningName) {
          log.info("stopping headed container", { toolName: runningName })
          await ContainerManager.stopContainer(runningName)
        }

        // Clear env overrides (back to default headless config)
        for (const name of PLAYWRIGHT_TOOL_NAMES) {
          ContainerManager.clearEnvOverrides(name)
        }

        ctx.metadata({
          title: "Browser: Headless Mode",
          metadata: { success: true, mode: "headless" },
        })

        return "Browser switched back to HEADLESS mode.\nThe next Playwright tool call will use the default headless configuration."
      }
    },
  })
}
