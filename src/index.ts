import type { Plugin, Config } from "@opencode-ai/plugin"
import { loadAgents } from "./agents/index.js"

/**
 * OpenSploit - Autonomous penetration testing plugin for OpenCode.
 *
 * Server-side entry point. Registers pentest agents, custom tools, and hooks.
 *
 * IMPORTANT: Only export `default` — the plugin loader calls every export.
 */
const OpenSploitPlugin: Plugin = async (ctx, options) => {
  const shell = ctx.$
  console.error("[opensploit-plugin] Plugin loaded successfully")

  return {
    config: async (config: Config) => {
      console.error("[opensploit-plugin] Config hook called, registering agents")
      // Register pentest agents via config mutation (proven pattern: orchestrator, magic-context, beads)
      const agents = loadAgents()
      config.agent = { ...config.agent, ...agents }

      // Set default agent to pentest if not explicitly configured.
      // The runtime config object has default_agent but the SDK type doesn't expose it.
      const cfg = config as Record<string, unknown>
      if (!cfg.default_agent) {
        cfg.default_agent = "pentest"
      }
    },

    tool: {
      // TODO Phase 3: custom tools (mcp_tool, tool_registry_search, engagement_state, etc.)
    },

    event: async ({ event }) => {
      // TODO Phase 5: trajectory recording, post-compaction re-injection
    },

    "experimental.chat.system.transform": async (input, output) => {
      // TODO Phase 5: inject engagement state into all agent prompts
    },

    "tool.execute.before": async (input, output) => {
      // TODO Phase 5: /session/ path rewriting, bash blocking, target validation
    },

    "tool.execute.after": async (input, output) => {
      // TODO Phase 5: output store interception
    },

    "permission.ask": async (input, output) => {
      // TODO Phase 5: ultrasploit auto-approve
    },

    "experimental.session.compacting": async (input, output) => {
      // TODO Phase 5: preserve objective + todos
    },
  }
}

export default OpenSploitPlugin
