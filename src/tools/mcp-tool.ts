/**
 * mcp_tool — Invoke MCP security tools from the OpenSploit registry.
 *
 * Adapted from packages/opencode/src/tool/mcp-tool.ts in the fat fork.
 * Logic is identical. Only the tool registration wrapper and imports changed
 * for the plugin API.
 */
import { tool, type ToolContext } from "@opencode-ai/plugin"
import { Effect } from "effect"
import { ContainerManager } from "../container/manager"
import { store as storeOutput } from "./output-store"
import { TargetValidation } from "../util/target-validation"
import { PhaseGating } from "../util/phase-gating"
import { getRootSession } from "../session/hierarchy"
import * as SessionDirectory from "../session/directory"
import { createLog } from "../util/log"
import path from "path"
import os from "os"
import fs from "fs/promises"
import yaml from "js-yaml"

const log = createLog("tool.mcp")

// --- Everything below is copied from the fat fork with minimal changes ---

const TARGET_PARAM_NAMES = ["target", "host", "hostname", "url", "ip", "address", "target_host", "rhost", "rhosts"]

function summarizeTargetArgs(args: Record<string, unknown>): string {
  const keys = TARGET_PARAM_NAMES.concat(["port", "ports", "wordlist", "method"])
  const parts: string[] = []
  for (const key of keys) {
    if (args[key] !== undefined) {
      const val = String(args[key])
      parts.push(`${key}=${val.length > 50 ? val.slice(0, 50) + "..." : val}`)
    }
  }
  return parts.join(", ") || "(no target params)"
}

const REGISTRY_URL = "https://opensploit.ai/registry.yaml"
const REGISTRY_DIR = path.join(os.homedir(), ".opensploit")
const REGISTRY_PATH = path.join(REGISTRY_DIR, "registry.yaml")

interface RegistryTool {
  name: string
  image?: string
  local?: {
    host: string
    port: number
    setup_url?: string
    setup_instructions?: string
  }
  methods?: Record<string, {
    description: string
    params?: Record<string, unknown>
    required_ports?: number[]
    timeout_seconds?: number
  }>
  timeout_seconds?: number
  requirements?: {
    network?: boolean
    privileged?: boolean
    local_only?: boolean
  }
  service?: boolean
  service_name?: string
  use_service?: string
  see_also?: Array<{ tool: string; reason: string }>
  resources?: { memory_mb?: number; cpu?: number }
  idle_timeout?: number
}

interface Registry {
  tools: Record<string, RegistryTool>
}

let cachedRegistry: Registry | null = null
let cacheTimestamp = 0
const CACHE_MAX_AGE_MS = 5 * 60 * 1000

async function callLocalMcpServer(
  host: string,
  port: number,
  method: string,
  args: Record<string, unknown>
): Promise<unknown> {
  const url = `http://${host}:${port}`
  const request = {
    jsonrpc: "2.0",
    id: Date.now(),
    method: "tools/call",
    params: { name: method, arguments: args },
  }
  log.info("calling local MCP server", { url, method })
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  })
  if (!response.ok) {
    throw new Error(`Local MCP server returned ${response.status}: ${response.statusText}`)
  }
  const result = await response.json()
  if (result.error) {
    throw new Error(result.error.message || "Local MCP server error")
  }
  return result.result
}

async function isLocalMcpServerAvailable(host: string, port: number): Promise<boolean> {
  try {
    const response = await fetch(`http://${host}:${port}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
      signal: AbortSignal.timeout(2000),
    })
    return response.ok || response.status === 400
  } catch {
    return false
  }
}

async function getRegistry(): Promise<Registry> {
  const now = Date.now()
  if (cachedRegistry && now - cacheTimestamp < CACHE_MAX_AGE_MS) {
    return cachedRegistry
  }
  try {
    const response = await fetch(REGISTRY_URL)
    if (response.ok) {
      const text = await response.text()
      cachedRegistry = yaml.load(text) as Registry
      cacheTimestamp = now
      await fs.mkdir(REGISTRY_DIR, { recursive: true }).catch(() => {})
      await fs.writeFile(REGISTRY_PATH, text).catch(() => {})
      return cachedRegistry
    }
  } catch { /* Fall through to cache */ }
  try {
    const text = await fs.readFile(REGISTRY_PATH, "utf-8")
    cachedRegistry = yaml.load(text) as Registry
    cacheTimestamp = now
    return cachedRegistry
  } catch {
    return { tools: {} }
  }
}

const DESCRIPTION = `Invoke an MCP tool from the OpenSploit tool registry.

This tool spawns a Docker container running the specified security tool and executes the given method.

Usage:
- First use tool_registry_search to find available tools and their methods
- Then use this tool to invoke specific methods with parameters

Example:
  tool: "nmap"
  method: "port_scan"
  args: {"target": "10.10.10.1", "ports": "1-1000"}

Clock offset:
  Some Kerberos/AD operations fail if the container clock differs from the target by >5 minutes.
  Use clock_offset to shift the container's perceived time:
  tool: "impacket"
  method: "get_tgt"
  args: {"domain": "corp.local", "username": "admin", "password": "pass"}
  clock_offset: "+7h"

The container will be automatically started if not running, and will be stopped after idle timeout.`

/**
 * Create the mcp_tool as a plugin tool.
 * Wraps the same logic as the fat fork's McpToolInvoke.
 */
export function createMcpTool() {
  return tool({
    description: DESCRIPTION,
    args: {
      tool: tool.schema.string().describe("The tool name from the registry (e.g., 'nmap', 'sqlmap', 'ffuf')"),
      method: tool.schema.string().describe("The method to call on the tool (e.g., 'port_scan', 'test_injection')"),
      arguments: tool.schema.string().optional().describe("JSON arguments to pass to the method"),
      timeout: tool.schema.number().optional().describe("Timeout in seconds. Overrides the registry default."),
      clock_offset: tool.schema.string().optional().describe(
        "Time offset for the container (e.g., '+7h', '-30m', '+2h30m'). " +
        "Uses libfaketime to shift the container's clock. " +
        "Required for Kerberos operations when target has clock skew."
      ),
    },
    async execute(params, ctx: ToolContext): Promise<string> {
      const toolName = params.tool
      const method = params.method
      let args: Record<string, unknown> = {}
      if (params.arguments) {
        try {
          args = JSON.parse(params.arguments)
        } catch (e) {
          return `Invalid JSON in arguments: ${e instanceof Error ? e.message : String(e)}\n\nExpected valid JSON object, e.g.: {"target": "10.10.10.1", "ports": "1-1000"}`
        }
      }
      const agentTimeout = params.timeout
      const clock_offset = params.clock_offset
      const sessionId = ctx.sessionID
      const rootSessionId = getRootSession(sessionId)

      // Ensure session directory exists
      if (!SessionDirectory.exists(rootSessionId)) {
        SessionDirectory.create(rootSessionId)
      }
      const sessionDir = SessionDirectory.get(rootSessionId)

      log.info("invoking mcp tool", { toolName, method, args, sessionId, rootSessionId })

      // Get registry
      const registry = await getRegistry()
      const toolDef = registry.tools[toolName]

      if (!toolDef) {
        return `Tool "${toolName}" not found in registry.\n\nUse tool_registry_search to find available tools.`
      }

      if (!toolDef.image && !toolDef.local) {
        return `Tool "${toolName}" does not have a Docker image or local server configured.`
      }

      // Method validation — forward to container for dynamic recipes
      if (toolDef.methods && !toolDef.methods[method]) {
        log.info(`Method "${method}" not in registry for "${toolName}", forwarding to container`)
      }

      // Timeout chain
      const methodDefForTimeout = toolDef.methods?.[method]
      const methodTimeout = methodDefForTimeout?.timeout_seconds
      const toolTimeout = toolDef.timeout_seconds
      const timeoutMs = agentTimeout ? agentTimeout * 1000
        : methodTimeout ? methodTimeout * 1000
        : toolTimeout ? toolTimeout * 1000
        : 300_000

      try {
        // Validate targets
        let targetWarning = ""
        for (const paramName of TARGET_PARAM_NAMES) {
          const value = args[paramName]
          if (typeof value === "string" && value) {
            const validation = TargetValidation.validateTarget(value)
            if (validation.highRisk && !targetWarning) {
              targetWarning = `${validation.highRiskWarning}\n\n`
              log.warn("high-risk target detected", { toolName, method, target: value })
            } else if (validation.info.isExternal && !targetWarning) {
              targetWarning = `⚠️  EXTERNAL TARGET: ${value}\nType: ${validation.info.type.toUpperCase()}\nEnsure you have authorization to scan this target.\n\n`
              log.warn("external target detected", { toolName, method, target: value })
            }
          }
        }

        // Phase gating
        const phaseCheck = PhaseGating.checkToolInvocation(sessionId, toolName)
        let phaseWarning = ""
        if (phaseCheck.warning) {
          phaseWarning = phaseCheck.warning + "\n\n"
        }

        // Ask permission — ctx.ask() returns Effect.Effect<void> or Promise<void>
        // depending on plugin SDK version. Handle both via runPromise with fallback.
        try {
          const askResult = ctx.ask({
            permission: "mcp_tool",
            patterns: [`mcp:${toolName}:${method}`],
            always: [`mcp:${toolName}:*`],
            metadata: { tool: toolName, method, args },
          })
          // Effect or Promise — resolve either way
          if (askResult && typeof (askResult as any)[Symbol.iterator] === "function") {
            await Effect.runPromise(askResult as any)
          } else {
            await (askResult as any)
          }
        } catch {
          return `Permission denied to run ${toolName}.${method}`
        }

        // Pre-flight: skip tools with repeated failures
        try {
          const stateFile = path.join(sessionDir, "state.yaml")
          const stateText = await fs.readFile(stateFile, "utf-8").catch(() => "")
          if (stateText) {
            const state = yaml.load(stateText) as any
            const toolFailures = state?.toolFailures || []
            const threshold = 3
            const match = toolFailures.find(
              (f: any) => f.tool === toolName && (!f.method || f.method === method) && (f.count || 0) >= threshold
            )
            if (match) {
              return `**SKIPPED**: \`${toolName}.${method}\` has failed ${match.count} times.\n\n` +
                `Last error: ${match.error}\n\n` +
                `Use \`tool_registry_search\` to find an alternative tool.`
            }

            // Port pre-flight
            const methodEntry = toolDef.methods?.[method]
            const requiredPorts: number[] = methodEntry?.required_ports ?? []
            if (requiredPorts.length > 0 && Array.isArray(state?.ports) && state.ports.length > 0) {
              const portChecks = requiredPorts.map((rp: number) => {
                const entry = state.ports.find((p: any) => p.port === rp)
                return { port: rp, scanned: !!entry, state: entry?.state as string | undefined }
              })
              const allBlocked = portChecks.every((p: any) => p.scanned && (p.state === "filtered" || p.state === "closed"))
              const anyUnscanned = portChecks.some((p: any) => !p.scanned)
              if (allBlocked && !anyUnscanned) {
                const blockedList = portChecks.map((p: any) => `${p.port} (${p.state})`).join(", ")
                return `**ALL REQUIRED PORTS BLOCKED**: \`${toolName}.${method}\` needs port(s) ${requiredPorts.join(", ")} ` +
                  `but all are ${blockedList} on the target.`
              }
            }
          }
        } catch { /* Non-critical pre-flight */ }

        // Execute: local server or Docker
        let result: unknown
        let usedLocal = false

        if (toolDef.local) {
          const { host, port, setup_url, setup_instructions } = toolDef.local
          const available = await isLocalMcpServerAvailable(host, port)
          if (available) {
            log.info("using local MCP server", { toolName, host, port })
            result = await callLocalMcpServer(host, port, method, args)
            usedLocal = true
          } else if (toolDef.requirements?.local_only) {
            return `⚠️  LOCAL MCP SERVER NOT AVAILABLE\n\nTool "${toolName}" requires a local MCP server at ${host}:${port}.\n\n${setup_instructions || `See ${setup_url || "tool documentation"} for setup instructions.`}`
          }
        }

        if (!usedLocal) {
          if (!toolDef.image) {
            return `Tool "${toolName}" requires a local MCP server which is not running. No Docker fallback available.`
          }
          const dockerAvailable = await ContainerManager.isDockerAvailable()
          if (!dockerAvailable) {
            return `Docker is not available.\n\nPlease ensure Docker is installed and running.`
          }

          // Service network routing
          let useServiceNetwork: string | undefined
          if (toolDef.use_service) {
            useServiceNetwork = toolDef.use_service
          } else if (!toolDef.service && ContainerManager.isServiceActive("vpn")) {
            useServiceNetwork = "vpn"
            log.info("routing through VPN service", { toolName })
          }

          result = await ContainerManager.callTool(
            toolName,
            toolDef.image,
            method,
            args,
            {
              privileged: toolDef.requirements?.privileged ?? false,
              sessionDir,
              isService: toolDef.service,
              serviceName: toolDef.service_name,
              useServiceNetwork,
              timeout: timeoutMs,
              clockOffset: clock_offset,
              resources: toolDef.resources,
              idleTimeout: toolDef.idle_timeout ? toolDef.idle_timeout * 1000 : undefined,
            }
          )
        }

        // Format result
        let rawOutput = ""
        if (typeof result === "object" && result !== null) {
          const r = result as Record<string, unknown>
          if ("content" in r && Array.isArray(r.content)) {
            for (const item of r.content as Array<{ type: string; text?: string }>) {
              if (item.type === "text" && item.text) {
                rawOutput += item.text + "\n"
              }
            }
          } else {
            rawOutput = JSON.stringify(result, null, 2)
          }
        } else {
          rawOutput = String(result)
        }

        // Detect MCP soft failures
        const isToolError = typeof result === "object" && result !== null &&
          (result as Record<string, unknown>).isError === true

        // Output store for large outputs
        const storeResult = await storeOutput({
          sessionId: rootSessionId,
          tool: toolName,
          method,
          data: typeof result === "object" ? result : null,
          rawOutput,
        })

        const warnings = phaseWarning + targetWarning
        let output: string
        if (storeResult.stored) {
          output = warnings + storeResult.output
        } else {
          output = `${warnings}# ${toolName}.${method} Result\n\n${storeResult.output}`
        }

        // Kerberos clock skew hint
        if (!clock_offset && /KRB_AP_ERR_SKEW|clock skew too great/i.test(rawOutput)) {
          output += "\n\n**HINT:** Kerberos clock skew detected. Use the `clock_offset` parameter."
        }

        // TODO: Record experience for learning (memory system not yet migrated)

        // Set metadata for TUI display
        ctx.metadata({
          title: `${toolName}.${method}${storeResult.stored ? " (output stored)" : ""}`,
          metadata: { tool: toolName, method, success: !isToolError },
        })

        return output
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error)
        log.error("mcp tool invocation failed", { toolName, method, error: errorMessage })

        // Auto-record failure to engagement state
        try {
          const stateFile = path.join(sessionDir, "state.yaml")
          const stateText = await fs.readFile(stateFile, "utf-8").catch(() => "")
          if (stateText) {
            const state = yaml.load(stateText) as any
            const toolFailures = state?.toolFailures || []
            const existing = toolFailures.find((f: any) => f.tool === toolName && f.method === method)
            if (existing) {
              existing.count = (existing.count || 1) + 1
              existing.lastSeen = new Date().toISOString()
              existing.error = errorMessage.slice(0, 200)
            } else {
              toolFailures.push({
                tool: toolName,
                method,
                error: errorMessage.slice(0, 200),
                count: 1,
                firstSeen: new Date().toISOString(),
                lastSeen: new Date().toISOString(),
                argsSummary: summarizeTargetArgs(args),
              })
            }
            state.toolFailures = toolFailures
            await fs.writeFile(stateFile, yaml.dump(state))
          }
        } catch { /* Don't fail tool execution if state recording fails */ }

        // Timeout-specific errors
        const isTimeout = /timeout|timed?\s*out|ETIMEDOUT/i.test(errorMessage)
        if (isTimeout) {
          const sec = Math.round(timeoutMs / 1000)
          return `**TIMEOUT**: \`${toolName}.${method}\` exceeded ${sec}s timeout.\n\n` +
            `Suggestions:\n- Use more targeted parameters\n- Break the task into smaller chunks\n- Use \`tool_registry_search\` for a faster alternative`
        }

        // Image pull failure
        const isPullFailure = /pull|manifest|denied|unauthorized|not found/i.test(errorMessage) &&
          /image|docker|container/i.test(errorMessage)
        if (isPullFailure) {
          const seeAlso = toolDef?.see_also
          let altMsg = ""
          if (Array.isArray(seeAlso) && seeAlso.length > 0) {
            altMsg = "\n\nAlternatives from registry:\n" +
              seeAlso.map((a) => `- **${a.tool}**: ${a.reason}`).join("\n")
          }
          return `**DOCKER IMAGE UNAVAILABLE**: \`${toolDef?.image}\` could not be pulled.\n\n${errorMessage}${altMsg}`
        }

        return `Failed to invoke ${toolName}.${method}:\n\n${errorMessage}`
      }
    },
  })
}
