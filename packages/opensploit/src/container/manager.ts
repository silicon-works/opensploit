import { spawn, type Subprocess } from "bun"
import { Client } from "@modelcontextprotocol/sdk/client/index.js"
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js"
import { Log } from "../util/log"
import { Installation } from "../installation"

const log = Log.create({ service: "container" })

// Container lifecycle settings
const IDLE_TIMEOUT_MS = 5 * 60 * 1000 // 5 minutes idle timeout
const CLEANUP_INTERVAL_MS = 30 * 1000 // Check every 30 seconds

// Retry settings with exponential backoff
const MAX_RETRIES = 3
const INITIAL_RETRY_DELAY_MS = 1000 // 1 second
const MAX_RETRY_DELAY_MS = 10000 // 10 seconds

/**
 * Sleep for a specified number of milliseconds
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/**
 * Calculate delay for exponential backoff
 */
function calculateRetryDelay(attempt: number): number {
  const delay = INITIAL_RETRY_DELAY_MS * Math.pow(2, attempt - 1)
  return Math.min(delay, MAX_RETRY_DELAY_MS)
}

/**
 * Classify error type for better error messages
 */
function classifyConnectionError(error: unknown): {
  type: "timeout" | "refused" | "network" | "unknown"
  message: string
  suggestion: string
} {
  const errorStr = String(error).toLowerCase()

  if (errorStr.includes("timeout") || errorStr.includes("timed out")) {
    return {
      type: "timeout",
      message: "Connection timed out",
      suggestion: "The target may be slow to respond or firewalled. Try increasing timeout or check network connectivity.",
    }
  }

  if (errorStr.includes("refused") || errorStr.includes("econnrefused")) {
    return {
      type: "refused",
      message: "Connection refused",
      suggestion: "The service may not be running on the target port. Verify the port is open and the service is active.",
    }
  }

  if (errorStr.includes("network") || errorStr.includes("unreachable") || errorStr.includes("no route")) {
    return {
      type: "network",
      message: "Network error",
      suggestion: "Check network connectivity and ensure the target is reachable. Verify VPN connection if targeting internal hosts.",
    }
  }

  return {
    type: "unknown",
    message: "Connection failed",
    suggestion: "Check the error details and verify target accessibility.",
  }
}

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
  }

  // Track running containers
  const containers = new Map<string, ManagedContainer>()
  let cleanupInterval: ReturnType<typeof setInterval> | null = null

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
      const proc = spawn(["docker", "image", "inspect", image], {
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

    // Pull image if not exists
    if (!(await imageExists(image))) {
      await pullImage(image)
    }

    // Start container with stdio
    log.info("starting container", { toolName, image })

    // Create a dummy proc reference for tracking (actual process is managed by transport)
    const dummyProc = spawn(["echo"], { stdout: "ignore", stderr: "ignore" })

    const client = new Client({
      name: "opensploit",
      version: Installation.VERSION,
    })

    // Build docker run args based on options
    const dockerArgs = ["run", "--rm", "-i", "--network=host"]
    if (options?.privileged) {
      dockerArgs.push("--privileged")
      log.info("running container in privileged mode", { toolName, image })
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
      throw new Error(`Failed to connect to MCP server in container: ${error}`)
    }

    // Get container ID for tracking
    const containerId = `${toolName}-${Date.now()}`

    const managed: ManagedContainer = {
      id: containerId,
      image,
      toolName,
      process: dummyProc,
      client,
      transport: stdioTransport,
      lastUsed: Date.now(),
      startedAt: Date.now(),
    }

    containers.set(toolName, managed)

    // Ensure cleanup interval is running
    startCleanupInterval()

    log.info("container started", { toolName, image, containerId })

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

    log.info("stopping container", { toolName, image: container.image })

    try {
      await container.client.close()
    } catch (error) {
      log.debug("error closing client", { toolName, error: String(error) })
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
        if (now - container.lastUsed > IDLE_TIMEOUT_MS) {
          log.info("stopping idle container", { toolName, idleMs: now - container.lastUsed })
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
  }> {
    const now = Date.now()
    return Array.from(containers.values()).map((c) => ({
      toolName: c.toolName,
      image: c.image,
      startedAt: c.startedAt,
      lastUsed: c.lastUsed,
      idleMs: now - c.lastUsed,
    }))
  }

  /**
   * Call a tool on a container, spawning it if necessary
   * Includes retry logic with exponential backoff for transient failures
   */
  export async function callTool(
    toolName: string,
    image: string,
    method: string,
    args: Record<string, unknown>,
    options?: ContainerOptions
  ): Promise<unknown> {
    let lastError: unknown

    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      try {
        const client = await getClient(toolName, image, options)

        // Update last used time
        const container = containers.get(toolName)
        if (container) {
          container.lastUsed = Date.now()
        }

        // Call the tool
        const result = await client.callTool({
          name: method,
          arguments: args,
        })

        return result
      } catch (error) {
        lastError = error
        const errorStr = String(error).toLowerCase()

        // Check if error is retryable
        const isRetryable =
          errorStr.includes("timeout") ||
          errorStr.includes("timed out") ||
          errorStr.includes("connection reset") ||
          errorStr.includes("network") ||
          errorStr.includes("unreachable")

        if (!isRetryable || attempt === MAX_RETRIES) {
          // Not retryable or last attempt - throw with enhanced error
          const classified = classifyConnectionError(error)
          log.error("tool call failed", {
            toolName,
            method,
            attempt,
            errorType: classified.type,
            error: String(error),
          })

          const enhancedError = new Error(
            `${classified.message}: ${String(error)}\n\nSuggestion: ${classified.suggestion}`
          )
          throw enhancedError
        }

        // Calculate delay and retry
        const delay = calculateRetryDelay(attempt)
        log.warn("tool call failed, retrying", {
          toolName,
          method,
          attempt,
          maxRetries: MAX_RETRIES,
          delayMs: delay,
          error: String(error),
        })

        // Stop the container before retry (force fresh connection)
        await stopContainer(toolName)

        await sleep(delay)
      }
    }

    // Should not reach here, but just in case
    throw lastError
  }
}
