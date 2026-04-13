import type { Plugin, Config } from "@opencode-ai/plugin"
import { loadAgents } from "./agents/index.js"
import { createMcpTool } from "./tools/mcp-tool.js"
import { createUpdateEngagementStateTool, createReadEngagementStateTool } from "./tools/engagement-state.js"
import { createBrowserHeadedTool } from "./tools/browser-headed.js"
import { createHostsTool } from "./tools/hosts.js"
import { createToolRegistrySearchTool } from "./tools/tool-registry-search.js"
import { createPatternSearchTool } from "./tools/pattern-search.js"
import { createSavePatternTool } from "./tools/save-pattern.js"
import { systemTransformHook } from "./hooks/system-transform.js"
import { toolBeforeHook } from "./hooks/tool-before.js"
import { permissionHook } from "./hooks/permission.js"
import { compactionHook } from "./hooks/compaction.js"
import { eventHook } from "./hooks/event.js"
import { chatMessageHook } from "./hooks/chat-message.js"

/**
 * OpenSploit - Autonomous penetration testing plugin for OpenCode.
 *
 * Server-side entry point. Registers pentest agents, custom tools, and hooks.
 *
 * IMPORTANT: Only export `default` — the plugin loader calls every export.
 */
const OpenSploitPlugin: Plugin = async (ctx, options) => {
  const shell = ctx.$

  return {
    config: async (config: Config) => {
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
      mcp_tool: createMcpTool(),
      update_engagement_state: createUpdateEngagementStateTool(),
      read_engagement_state: createReadEngagementStateTool(),
      browser_headed_mode: createBrowserHeadedTool(),
      hosts: createHostsTool(),
      tool_registry_search: createToolRegistrySearchTool(),
      pattern_search: createPatternSearchTool(),
      save_pattern: createSavePatternTool(),
    },

    event: eventHook,

    "chat.message": chatMessageHook,

    "experimental.chat.system.transform": systemTransformHook,

    "tool.execute.before": toolBeforeHook,

    // tool.execute.after: Output store interception is handled INSIDE mcp_tool.execute()
    // directly (line 395 of mcp-tool.ts). No separate hook needed.

    "permission.ask": permissionHook,

    "experimental.session.compacting": compactionHook,
  }
}

export default OpenSploitPlugin
