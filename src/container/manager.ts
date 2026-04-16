import { spawn, type Subprocess } from "bun"
import { Client } from "@modelcontextprotocol/sdk/client/index.js"
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js"
import { createLog } from "../util/log"

const log = createLog("container")

// Hardcoded version string — in the fat fork this came from Installation.VERSION
const PLUGIN_VERSION = "0.1.0"

// Container lifecycle settings
const IDLE_TIMEOUT_MS = 5 * 60 * 1000 // 5 minutes idle timeout
const CLEANUP_INTERVAL_MS = 30 * 1000 // Check every 30 seconds

export namespace ContainerManager {
  interface ManagedContainer {
    id: string
    image: string
    toolName: string
    process: Subprocess
    client: Client
    transport: StdioClientTransport
    lastUsed: number
    startedAt: number
    isService?: boolean
    serviceName?: string
    dockerContainerId?: string // Actual Docker container ID for network sharing
    clockOffset?: string // libfaketime offset this container was started with
    callMutex: CallMutex // Serialize concurrent calls to the same stdio pipe
    activeCalls: number // Number of in-flight tool calls (skip idle timeout when > 0)
    idleTimeout?: number // Per-container override (milliseconds) from registry idle_timeout
  }

  /**
   * Simple mutex to serialize calls to a single MCP client.
   * The MCP SDK's stdio transport is not safe for concurrent callTool()
   * because JSON-RPC messages interleave on the pipe, corrupting the stream.
   */
  class CallMutex {
    private queue: Array<() => void> = []
    private locked = false
    private destroyed = false

    async acquire(): Promise<void> {
      if (this.destroyed) {
        throw new Error("CallMutex destroyed — container is shutting down")
      }
      if (!this.locked) {
        this.locked = true
        return
      }
      return new Promise<void>((resolve) => {
        this.queue.push(resolve)
      })
    }

    release(): void {
      const next = this.queue.shift()
      if (next) {
        next()
      } else {
        this.locked = false
      }
    }

    /**
     * Reject all queued waiters and mark the mutex as unusable.
     * Called during stopContainer() to unblock any calls waiting on a dying container.
     */
    destroy(): void {
      this.destroyed = true
      this.locked = false
      const pending = this.queue.splice(0)
      for (const waiter of pending) {
        // Resolve waiters so they proceed to callTool which will fail with
        // a transport error — cleaner than leaving them hanging forever.
        waiter()
      }
    }
  }

  // Track running containers
  const containers = new Map<string, ManagedContainer>()

  // Track active service containers by service name for network sharing
  const serviceContainers = new Map<string, string>() // serviceName -> toolName
  let cleanupInterval: ReturnType<typeof setInterval> | null = null

  // Environment variable overrides for next container start (used by browser_headed_mode)
  const envOverrides = new Map<string, Record<string, string>>()

  /**
   * Set environment variable overrides for a tool's next container start.
   * The existing container must be stopped first for these to take effect.
   */
  export function setEnvOverrides(toolName: string, env: Record<string, string>): void {
    envOverrides.set(toolName, env)
    log.info("env overrides set", { toolName, keys: Object.keys(env) })
  }

  /**
   * Clear environment variable overrides for a tool.
   */
  export function clearEnvOverrides(toolName: string): void {
    envOverrides.delete(toolName)
    log.info("env overrides cleared", { toolName })
  }

  /**
   * Get current environment variable overrides for a tool.
   */
  export function getEnvOverrides(toolName: string): Record<string, string> | undefined {
    return envOverrides.get(toolName)
  }

  /**
   * Check if Docker is available
   */
  export async function isDockerAvailable(): Promise<boolean> {
    try {
      const proc = spawn(["docker", "info"], {
        stdout: "ignore",
        stderr: "ignore",
      })
      const exitCode = await proc.exited
      return exitCode === 0
    } catch {
      return false
    }
  }

  /**
   * Check if an image exists locally
   */
  export async function imageExists(image: string): Promise<boolean> {
    try {
      // BUG-CM-3 fix: add "--" to prevent image names like "--help" being treated as flags
      const proc = spawn(["docker", "image", "inspect", "--", image], {
        stdout: "ignore",
        stderr: "ignore",
      })
      const exitCode = await proc.exited
      return exitCode === 0
    } catch {
      return false
    }
  }

  /**
   * Pull a Docker image with progress reporting
   */
  export async function pullImage(image: string): Promise<void> {
    log.info("pulling image", { image })

    const proc = spawn(["docker", "pull", image], {
      stdout: "pipe",
      stderr: "pipe",
    })

    // Read stdout for progress
    const reader = proc.stdout.getReader()
    const decoder = new TextDecoder()
    let buffer = ""

    try {
      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split("\n")
        buffer = lines.pop() || ""

        for (const line of lines) {
          if (line.trim()) {
            log.debug("pull progress", { image, line: line.trim() })
          }
        }
      }
    } finally {
      reader.releaseLock()
    }

    const exitCode = await proc.exited

    if (exitCode !== 0) {
      const stderr = await new Response(proc.stderr).text()
      const error = `Failed to pull image: ${stderr}`
      log.error("image pull failed", { image, error })
      throw new Error(error)
    }

    log.info("image pulled successfully", { image })
  }

  export interface ContainerOptions {
    privileged?: boolean
    /** Session directory to mount as /session/ inside container */
    sessionDir?: string
    /** Mark this as a service container that persists and shares network */
    isService?: boolean
    /** Service name for network sharing (e.g., "vpn") */
    serviceName?: string
    /** Use network from an existing service container */
    useServiceNetwork?: string
    /** Environment variables to pass to the container */
    env?: Record<string, string>
    /** Tool-specific timeout in milliseconds */
    timeout?: number
    /** Time offset for libfaketime (e.g., '+7h', '-30m'). Shifts container clock. */
    clockOffset?: string
    /** Docker resource limits from registry */
    resources?: { memory_mb?: number; cpu?: number }
    /** Per-tool idle timeout override in milliseconds (from registry idle_timeout) */
    idleTimeout?: number
  }

  /**
   * Get the Docker container ID for a running container
   */
  async function getDockerContainerId(containerName: string): Promise<string | undefined> {
    try {
      // List running containers and find the one running our image
      const proc = spawn(["docker", "ps", "--filter", `name=${containerName}`, "--format", "{{.ID}}"], {
        stdout: "pipe",
        stderr: "ignore",
      })
      const output = await new Response(proc.stdout).text()
      const containerId = output.trim().split("\n")[0]
      return containerId || undefined
    } catch {
      return undefined
    }
  }

  /**
   * Get the active service container's Docker ID for network sharing
   */
  export function getActiveServiceNetwork(serviceName: string): string | undefined {
    const toolName = serviceContainers.get(serviceName)
    if (!toolName) return undefined

    const container = containers.get(toolName)
    return container?.dockerContainerId
  }

  /**
   * Check if a service is currently active
   */
  export function isServiceActive(serviceName: string): boolean {
    return serviceContainers.has(serviceName)
  }

  /**
   * Start a container and return an MCP client connected to it
   */
  export async function getClient(toolName: string, image: string, options?: ContainerOptions): Promise<Client> {
    // Check if we already have a running container for this tool
    const existing = containers.get(toolName)
    if (existing) {
      existing.lastUsed = Date.now()
      log.debug("reusing existing container", { toolName, image })
      return existing.client
    }

    // Check Docker availability
    if (!(await isDockerAvailable())) {
      throw new Error("Docker is not available. Please ensure Docker is installed and running.")
    }

    // Pull image if not exists (with retry for transient failures)
    if (!(await imageExists(image))) {
      try {
        await pullImage(image)
      } catch (pullError) {
        log.warn("image pull failed, retrying in 3s", { image, error: String(pullError) })
        await new Promise(r => setTimeout(r, 3000))
        await pullImage(image) // Let this throw if it also fails
      }
    }

    // Start container with stdio
    const isService = options?.isService ?? false
    const serviceName = options?.serviceName
    log.info("starting container", { toolName, image, isService, serviceName })

    // Create a dummy proc reference for tracking (actual process is managed by transport)
    const dummyProc = spawn(["echo"], { stdout: "ignore", stderr: "ignore" })

    const client = new Client({
      name: "opensploit",
      version: PLUGIN_VERSION,
    })

    // Generate container name for service containers (needed for network sharing)
    const containerName = isService ? `opensploit-${serviceName || toolName}-${Date.now()}` : undefined

    // Build docker run args based on options
    const dockerArgs = ["run", "-i"]

    // Service containers persist (no --rm), regular containers are removed on exit
    if (!isService) {
      dockerArgs.push("--rm")
    }

    // Add container name for service containers
    if (containerName) {
      dockerArgs.push("--name", containerName)
    }

    // Build merged env early — needed for network decision
    const mergedEnv: Record<string, string> = {
      ...(envOverrides.get(toolName) ?? {}),
      ...(options?.env ?? {}),
      // Clock offset via libfaketime (for Kerberos clock skew)
      ...(options?.clockOffset ? {
        LD_PRELOAD: "/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1",
        FAKETIME: options.clockOffset,
        FAKETIME_DONT_FAKE_MONOTONIC: "1",
      } : {}),
    }

    // Network configuration
    // Headed mode (HEADED=1) forces --network=host so VNC port 6080 is accessible
    // on localhost. The entrypoint's socat proxy handles VPN connectivity for headed Chrome.
    const forceHostNetwork = mergedEnv.HEADED === "1"

    if (forceHostNetwork) {
      dockerArgs.push("--network=host")
      log.info("headed mode: forcing host network for VNC access", { toolName })
    } else if (options?.useServiceNetwork) {
      // Use network from existing service container
      const serviceDockerContainerId = getActiveServiceNetwork(options.useServiceNetwork)
      if (serviceDockerContainerId) {
        dockerArgs.push("--network", `container:${serviceDockerContainerId}`)
        log.info("using service network", { toolName, serviceName: options.useServiceNetwork, containerId: serviceDockerContainerId })
      } else {
        // Fall back to host network if service not available
        dockerArgs.push("--network=host")
        log.warn("service network not available, using host network", { toolName, serviceName: options.useServiceNetwork })
      }
    } else {
      // Default to host network
      dockerArgs.push("--network=host")
    }

    if (options?.privileged) {
      dockerArgs.push("--privileged")
      log.info("running container in privileged mode", { toolName, image })
    }
    // Docker resource limits
    // BUG-CM-1/CM-2 fix: validate resource limits are finite positive numbers
    if (options?.resources?.memory_mb != null) {
      const mem = options.resources.memory_mb
      if (typeof mem === "number" && mem > 0 && isFinite(mem)) {
        dockerArgs.push("--memory", `${Math.round(mem)}m`)
      }
    }
    if (options?.resources?.cpu != null) {
      const cpu = options.resources.cpu
      if (typeof cpu === "number" && cpu > 0 && isFinite(cpu)) {
        dockerArgs.push("--cpus", String(cpu))
      }
    }
    // Pass environment variables to container
    for (const [key, value] of Object.entries(mergedEnv)) {
      dockerArgs.push("-e", `${key}=${value}`)
    }
    // Mount session directory for wordlists, artifacts, etc.
    if (options?.sessionDir) {
      dockerArgs.push("-v", `${options.sessionDir}:/session:rw`)
      log.info("mounting session directory", { toolName, sessionDir: options.sessionDir })
    }
    dockerArgs.push(image)

    // Create stdio transport that will spawn docker run
    const stdioTransport = new StdioClientTransport({
      command: "docker",
      args: dockerArgs,
      stderr: "pipe",
    })

    try {
      await client.connect(stdioTransport)
    } catch (error) {
      log.error("failed to connect to container", { toolName, image, error: String(error) })
      // Clean up named container if it was created
      if (containerName) {
        spawn(["docker", "rm", "-f", containerName], { stdout: "ignore", stderr: "ignore" })
      }
      throw new Error(`Failed to connect to MCP server in container: ${error}`)
    }

    // Get container ID for tracking
    const containerId = `${toolName}-${Date.now()}`

    // For service containers, get the actual Docker container ID for network sharing
    let dockerContainerId: string | undefined
    if (isService && containerName) {
      // Wait a moment for container to be fully registered
      await new Promise((resolve) => setTimeout(resolve, 500))
      dockerContainerId = await getDockerContainerId(containerName)
      if (dockerContainerId) {
        log.info("service container started", { toolName, serviceName, dockerContainerId })
      } else {
        log.warn("could not get docker container ID for service", { toolName, containerName })
      }
    }

    const managed: ManagedContainer = {
      id: containerId,
      image,
      toolName,
      process: dummyProc,
      client,
      transport: stdioTransport,
      lastUsed: Date.now(),
      startedAt: Date.now(),
      isService,
      serviceName,
      dockerContainerId,
      clockOffset: options?.clockOffset,
      callMutex: new CallMutex(),
      activeCalls: 0,
      idleTimeout: options?.idleTimeout,
    }

    containers.set(toolName, managed)

    // Track service container for network sharing
    if (isService && serviceName) {
      serviceContainers.set(serviceName, toolName)
      log.info("registered service container", { serviceName, toolName, dockerContainerId })
    }

    // Ensure cleanup interval is running
    startCleanupInterval()

    log.info("container started", { toolName, image, containerId, isService, serviceName })

    return client
  }

  /**
   * Stop a specific container
   */
  export async function stopContainer(toolName: string): Promise<void> {
    const container = containers.get(toolName)
    if (!container) {
      return
    }

    log.info("stopping container", { toolName, image: container.image, isService: container.isService })

    // Drain the call mutex — unblocks any queued callers so they fail fast
    // instead of hanging forever on a dead container.
    container.callMutex.destroy()

    try {
      await container.client.close()
    } catch (error) {
      log.debug("error closing client", { toolName, error: String(error) })
    }

    // For service containers, we need to explicitly remove the Docker container
    // since they don't use --rm
    if (container.isService && container.dockerContainerId) {
      try {
        const proc = spawn(["docker", "rm", "-f", container.dockerContainerId], {
          stdout: "ignore",
          stderr: "ignore",
        })
        await proc.exited
        log.info("removed service container", { toolName, dockerContainerId: container.dockerContainerId })
      } catch (error) {
        log.debug("error removing service container", { toolName, error: String(error) })
      }
    }

    // Remove from service tracking
    if (container.isService && container.serviceName) {
      serviceContainers.delete(container.serviceName)
    }

    containers.delete(toolName)
  }

  /**
   * Stop all containers
   */
  export async function stopAll(): Promise<void> {
    log.info("stopping all containers", { count: containers.size })

    const promises = Array.from(containers.keys()).map((toolName) => stopContainer(toolName))
    await Promise.allSettled(promises)

    if (cleanupInterval) {
      clearInterval(cleanupInterval)
      cleanupInterval = null
    }
  }

  /**
   * Start the cleanup interval for idle containers
   */
  function startCleanupInterval(): void {
    if (cleanupInterval) return

    cleanupInterval = setInterval(() => {
      const now = Date.now()
      for (const [toolName, container] of containers) {
        // Skip service containers - they should persist for the session
        if (container.isService) {
          continue
        }

        // Skip containers with active in-flight tool calls (e.g., hashcat cracking)
        if (container.activeCalls > 0) {
          continue
        }

        const timeout = container.idleTimeout ?? IDLE_TIMEOUT_MS // BUG-CM-7 fix: 0 is valid
        if (now - container.lastUsed > timeout) {
          log.info("stopping idle container", { toolName, idleMs: now - container.lastUsed, timeoutMs: timeout })
          stopContainer(toolName).catch((error) => {
            log.error("error stopping idle container", { toolName, error: String(error) })
          })
        }
      }

      // Stop interval if no containers left
      if (containers.size === 0 && cleanupInterval) {
        clearInterval(cleanupInterval)
        cleanupInterval = null
      }
    }, CLEANUP_INTERVAL_MS)
  }

  /**
   * Get status of all running containers
   */
  export function getStatus(): Array<{
    toolName: string
    image: string
    startedAt: number
    lastUsed: number
    idleMs: number
    isService?: boolean
    serviceName?: string
  }> {
    const now = Date.now()
    return Array.from(containers.values()).map((c) => ({
      toolName: c.toolName,
      image: c.image,
      startedAt: c.startedAt,
      lastUsed: c.lastUsed,
      idleMs: now - c.lastUsed,
      isService: c.isService,
      serviceName: c.serviceName,
    }))
  }

  /**
   * Get list of active service names
   */
  export function getActiveServices(): string[] {
    return Array.from(serviceContainers.keys())
  }

  /**
   * Call a tool on a container, spawning it if necessary
   */
  export async function callTool(
    toolName: string,
    image: string,
    method: string,
    args: Record<string, unknown>,
    options?: ContainerOptions
  ): Promise<unknown> {
    // If clock offset changed from what the container was started with, restart it
    // (env vars are set at docker run time — reusing a container would silently ignore the new offset)
    const existing = containers.get(toolName)
    if (existing && options?.clockOffset !== existing.clockOffset) {
      log.info("clock offset changed, restarting container", {
        toolName,
        oldOffset: existing.clockOffset,
        newOffset: options?.clockOffset,
      })
      await stopContainer(toolName)
    }

    const client = await getClient(toolName, image, options)

    // Update last used time
    const container = containers.get(toolName)
    if (container) {
      container.lastUsed = Date.now()
    }

    // Serialize concurrent calls to the same container.
    // The MCP SDK's stdio transport corrupts when multiple callTool()
    // write to the same pipe concurrently (causes segfault in Bun).
    const mutex = container?.callMutex
    if (mutex) {
      await mutex.acquire()
    }
    if (container) {
      container.activeCalls++
    }
    try {
      const result = await client.callTool(
        { name: method, arguments: args },
        undefined,
        {
          timeout: options?.timeout ?? 300_000,
          resetTimeoutOnProgress: true,
          onprogress: (progress: { message?: string }) => {
            log.info("tool progress", {
              toolName,
              method,
              message: progress.message,
            })
          },
        }
      )

      return result
    } finally {
      if (container) {
        container.activeCalls--
        container.lastUsed = Date.now()
      }
      mutex?.release()
    }
  }
}
