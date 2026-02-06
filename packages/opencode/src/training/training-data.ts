/**
 * Training Data Module
 *
 * Captures pentest sessions as training data for ML pipelines.
 * Provides a unified directory structure for easy data collection.
 *
 * Directory Structure:
 * ~/.opensploit/sessions/{sessionID}/
 * ├── session.json            # Session metadata (target, model, outcome, timestamps)
 * ├── trajectory.jsonl        # Chronological TVAR + tool calls (one entry per line)
 * ├── state.yaml              # Engagement state (persisted from /tmp/ at session end)
 * ├── state_history.yaml      # State transitions (persisted from /tmp/ at session end)
 * ├── findings/               # Phase findings (persisted from /tmp/ at session end)
 * └── outputs/                # MCP tool raw outputs (written by output-store.ts)
 *     └── out_*.json
 *
 * Requirements:
 * - REQ-TRN-001: Capture agent trajectories for fine-tuning
 * - REQ-TRN-002: Store trajectories in structured format
 * - REQ-RSN-030: Record complete reasoning trajectories
 */

import path from "path"
import os from "os"
import { mkdirSync, existsSync, writeFileSync, readFileSync, copyFileSync, cpSync, renameSync, rmSync } from "fs"
import { Session } from "@/session"
import { Trajectory } from "@/session/trajectory"
import { MessageV2 } from "@/session/message-v2"
import { Log } from "@/util/log"
import { Lock } from "@/util/lock"
import { Bus } from "@/bus"
import * as SessionDirectory from "@/session/directory"

const log = Log.create({ service: "training-data" })

// Session archive directory (training-ready data)
export const SESSIONS_DIR = path.join(os.homedir(), ".opensploit", "sessions")

/** @deprecated Use SESSIONS_DIR instead */
export const TRAINING_DIR = SESSIONS_DIR

/**
 * Get session archive directory for a session.
 */
export function getSessionTrainingDir(sessionID: string): string {
  return path.join(SESSIONS_DIR, sessionID)
}

/**
 * Get outputs directory for a session (used by output-store.ts).
 */
export function getSessionOutputsDir(sessionID: string): string {
  return path.join(getSessionTrainingDir(sessionID), "outputs")
}

/**
 * Session metadata for training.
 */
export interface SessionMetadata {
  sessionID: string
  title: string
  model: string
  providerID: string
  startTime: string
  endTime?: string
  duration?: number // milliseconds
  target?: string
  outcome?: {
    success: boolean
    accessLevel?: "none" | "user" | "root"
    flagsCaptured?: string[]
  }
  stats: {
    messages: number
    tvarBlocks: number
    toolCalls: number
    successfulTools: number
    failedTools: number
    phases: string[]
    childSessions?: number
  }
  tokens?: {
    input: number
    output: number
    total: number
  }
  cost?: number
}

/**
 * Training trajectory entry (one per line in JSONL).
 * Captures COMPLETE data for fine-tuning - raw storage data.
 */
export interface TrajectoryEntry {
  // === Identity ===
  timestamp: string
  sessionID: string
  messageID: string
  partID: string
  agentName?: string // "master" or sub-agent name (e.g., "recon", "enum")

  // === Message Context ===
  role: "user" | "assistant"
  modelID?: string
  providerID?: string
  parentMessageID?: string // Links conversation flow
  tokens?: {
    input: number
    output: number
    reasoning?: number
    cacheRead?: number
    cacheWrite?: number
  }
  cost?: number

  // === Part Type ===
  type: "text" | "tvar" | "tool"

  // === Text Parts (user prompts, assistant text) ===
  text?: string

  // === TVAR Parts (reasoning) ===
  phase?: string
  thought?: string
  verify?: string
  action?: string
  result?: string
  toolCallID?: string // Links TVAR to tool call

  // === Tool Parts (COMPLETE) ===
  tool?: string
  callID?: string
  toolInput?: Record<string, unknown> // Full input parameters
  toolOutput?: string // Full output text
  toolMetadata?: Record<string, unknown> // Warnings, counts, etc.
  toolSuccess?: boolean
  toolError?: string
  toolDuration?: number
}

/**
 * Ensure training directory exists for a session.
 */
export function ensureTrainingDir(sessionID: string): string {
  const dir = getSessionTrainingDir(sessionID)
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true })
  }
  return dir
}

/**
 * Extract target from session title or first user message.
 */
function extractTarget(title: string, messages: Awaited<ReturnType<typeof Session.messages>>): string | undefined {
  // Try to extract from title (common patterns)
  const ipMatch = title.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)
  if (ipMatch) return ipMatch[1]

  const hostMatch = title.match(/([a-zA-Z0-9-]+\.htb|[a-zA-Z0-9-]+\.local)/)
  if (hostMatch) return hostMatch[1]

  // Try first user message
  for (const msg of messages) {
    if (msg.info.role === "user") {
      for (const part of msg.parts) {
        if (part.type === "text") {
          const textIp = part.text.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)
          if (textIp) return textIp[1]
          const textHost = part.text.match(/([a-zA-Z0-9-]+\.htb|[a-zA-Z0-9-]+\.local)/)
          if (textHost) return textHost[1]
        }
      }
      break // Only check first user message
    }
  }

  return undefined
}

/**
 * Collect stats from messages.
 */
interface MessageStats {
  model: string
  providerID: string
  tvarBlocks: number
  toolCalls: number
  successfulTools: number
  failedTools: number
  phases: Set<string>
  inputTokens: number
  outputTokens: number
  cost: number
  messageCount: number
}

async function collectMessageStats(sessionID: string, stats: MessageStats): Promise<void> {
  const messages = await Session.messages({ sessionID })

  for (const msg of messages) {
    stats.messageCount++
    if (msg.info.role === "assistant") {
      if (stats.model === "unknown") {
        stats.model = msg.info.modelID
        stats.providerID = msg.info.providerID
      }
      stats.inputTokens += msg.info.tokens?.input ?? 0
      stats.outputTokens += msg.info.tokens?.output ?? 0
      stats.cost += msg.info.cost ?? 0
    }

    for (const part of msg.parts) {
      if (part.type === "tvar") {
        stats.tvarBlocks++
        if (part.phase) stats.phases.add(part.phase)
      } else if (part.type === "tool") {
        stats.toolCalls++
        if (part.state.status === "completed") {
          stats.successfulTools++
        } else if (part.state.status === "error") {
          stats.failedTools++
        }
      }
    }
  }
}

/**
 * Save session metadata to session.json.
 * Aggregates stats from root session AND all child sessions (sub-agents).
 *
 * Uses Lock.write() to prevent race conditions when multiple sub-agents
 * trigger concurrent saves via Session.Event.Updated.
 */
export async function saveSessionMetadata(sessionID: string): Promise<SessionMetadata | null> {
  const lock = await Lock.write(`metadata:${sessionID}`)
  try {
    const session = await Session.get(sessionID)
    const rootMessages = await Session.messages({ sessionID })

    if (rootMessages.length === 0) {
      log.info("skip_empty_session", { sessionID: sessionID.slice(-8) })
      return null
    }

    // Collect stats from root session and all children
    const stats: MessageStats = {
      model: "unknown",
      providerID: "unknown",
      tvarBlocks: 0,
      toolCalls: 0,
      successfulTools: 0,
      failedTools: 0,
      phases: new Set<string>(),
      inputTokens: 0,
      outputTokens: 0,
      cost: 0,
      messageCount: 0,
    }

    // Process root session
    await collectMessageStats(sessionID, stats)

    // Process all child sessions
    const children = await getChildSessionsRecursive(sessionID)
    for (const child of children) {
      await collectMessageStats(child.id, stats)
    }

    const startTime = session.time.created
    const endTime = session.time.updated

    const metadata: SessionMetadata = {
      sessionID,
      title: session.title,
      model: stats.model,
      providerID: stats.providerID,
      startTime: new Date(startTime).toISOString(),
      endTime: endTime ? new Date(endTime).toISOString() : undefined,
      duration: endTime ? endTime - startTime : undefined,
      target: extractTarget(session.title, rootMessages),
      stats: {
        messages: stats.messageCount,
        tvarBlocks: stats.tvarBlocks,
        toolCalls: stats.toolCalls,
        successfulTools: stats.successfulTools,
        failedTools: stats.failedTools,
        phases: Array.from(stats.phases),
        childSessions: children.length,
      },
      tokens: {
        input: stats.inputTokens,
        output: stats.outputTokens,
        total: stats.inputTokens + stats.outputTokens,
      },
      cost: stats.cost,
    }

    // Ensure directory exists
    const dir = ensureTrainingDir(sessionID)

    // Write session.json
    const metadataPath = path.join(dir, "session.json")
    writeFileSync(metadataPath, JSON.stringify(metadata, null, 2), "utf-8")

    log.info("saved_metadata", {
      sessionID: sessionID.slice(-8),
      messages: stats.messageCount,
      tvarBlocks: stats.tvarBlocks,
      toolCalls: stats.toolCalls,
      childSessions: children.length,
    })

    return metadata
  } catch (error) {
    log.error("save_metadata_failed", { sessionID: sessionID.slice(-8), error })
    return null
  } finally {
    lock[Symbol.dispose]()
  }
}

/**
 * Get all child sessions recursively.
 */
async function getChildSessionsRecursive(sessionID: string): Promise<Session.Info[]> {
  const children = await Session.children(sessionID)
  const all: Session.Info[] = [...children]
  for (const child of children) {
    const grandchildren = await getChildSessionsRecursive(child.id)
    all.push(...grandchildren)
  }
  return all
}

/**
 * Process messages from a session and add entries to the list.
 * Captures COMPLETE data for fine-tuning.
 */
async function processSessionMessages(
  sessionID: string,
  agentName: string,
  entries: TrajectoryEntry[]
): Promise<void> {
  const messages = await Session.messages({ sessionID })

  for (const msg of messages) {
    // Extract message-level info with proper type narrowing
    let msgTokens: TrajectoryEntry["tokens"]
    let msgCost: number | undefined
    let msgModelID: string | undefined
    let msgProviderID: string | undefined
    let parentMessageID: string | undefined

    if (msg.info.role === "assistant") {
      msgTokens = {
        input: msg.info.tokens?.input ?? 0,
        output: msg.info.tokens?.output ?? 0,
        reasoning: msg.info.tokens?.reasoning,
        cacheRead: msg.info.tokens?.cache?.read,
        cacheWrite: msg.info.tokens?.cache?.write,
      }
      msgCost = msg.info.cost
      msgModelID = msg.info.modelID
      msgProviderID = msg.info.providerID
      parentMessageID = msg.info.parentID
    } else {
      msgTokens = undefined
      msgCost = undefined
      msgModelID = msg.info.model?.modelID
      msgProviderID = msg.info.model?.providerID
      parentMessageID = undefined
    }

    for (const part of msg.parts) {
      let entry: TrajectoryEntry | null = null
      const baseEntry = {
        sessionID,
        messageID: msg.info.id,
        partID: part.id,
        agentName,
        role: msg.info.role,
        modelID: msgModelID,
        providerID: msgProviderID,
        parentMessageID,
        tokens: msgTokens,
        cost: msgCost,
      }

      if (part.type === "text" && part.text) {
        // Capture user prompts and assistant text
        entry = {
          ...baseEntry,
          timestamp: part.time?.start
            ? new Date(part.time.start).toISOString()
            : new Date(msg.info.time.created).toISOString(),
          type: "text",
          text: part.text,
        }
      } else if (part.type === "tvar") {
        // Capture TVAR reasoning blocks
        entry = {
          ...baseEntry,
          timestamp: new Date(part.time.start).toISOString(),
          type: "tvar",
          phase: part.phase,
          thought: part.thought,
          verify: part.verify,
          action: part.action,
          result: part.result,
          toolCallID: part.toolCallID,
        }
      } else if (part.type === "tool") {
        // Capture COMPLETE tool data
        const state = part.state
        let startMs: number | undefined
        let endMs: number | undefined
        let toolOutput: string | undefined
        let toolError: string | undefined
        let toolMetadata: Record<string, unknown> | undefined

        if (state.status === "completed") {
          startMs = state.time?.start
          endMs = state.time?.end
          toolOutput = state.output
          toolMetadata = state.metadata
        } else if (state.status === "error") {
          startMs = state.time?.start
          endMs = state.time?.end
          toolError = state.error
          toolMetadata = state.metadata
        } else if (state.status === "running") {
          startMs = state.time?.start
          toolMetadata = state.metadata
        }

        entry = {
          ...baseEntry,
          timestamp: startMs ? new Date(startMs).toISOString() : new Date().toISOString(),
          type: "tool",
          tool: part.tool,
          callID: part.callID,
          toolInput: state.input,
          toolOutput,
          toolMetadata,
          toolSuccess: state.status === "completed",
          toolError,
          toolDuration: startMs && endMs ? endMs - startMs : undefined,
        }
      }

      if (entry) {
        entries.push(entry)
      }
    }
  }
}

/**
 * Extract agent name from session title.
 */
function extractAgentName(title: string, isRoot: boolean): string {
  if (isRoot) return "master"

  // Match pattern: @agentName subagent
  const match = title.match(/@([^\s]+)\s+subagent/)
  if (match) return match[1]

  // Match pattern: pentest/xxx
  const pentestMatch = title.match(/pentest\/(\w+)/)
  if (pentestMatch) return pentestMatch[1]

  return "subagent"
}

/**
 * Save trajectory to trajectory.jsonl (one entry per line).
 * Aggregates data from root session AND all child sessions (sub-agents).
 *
 * Uses Lock.write() to prevent race conditions when multiple sub-agents
 * trigger concurrent saves via Session.Event.Updated.
 */
export async function saveTrajectory(sessionID: string): Promise<number> {
  const lock = await Lock.write(`trajectory:${sessionID}`)
  try {
    const session = await Session.get(sessionID)
    const entries: TrajectoryEntry[] = []

    // Process root session
    await processSessionMessages(sessionID, "master", entries)

    // Process all child sessions (sub-agents)
    const children = await getChildSessionsRecursive(sessionID)
    for (const child of children) {
      const agentName = extractAgentName(child.title, false)
      await processSessionMessages(child.id, agentName, entries)
    }

    if (entries.length === 0) {
      return 0
    }

    // Sort by timestamp
    entries.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())

    const dir = ensureTrainingDir(sessionID)
    const trajectoryPath = path.join(dir, "trajectory.jsonl")

    // Atomic write: build full content then write once (no clear+append race)
    const content = entries.map((e) => JSON.stringify(e)).join("\n") + "\n"
    writeFileSync(trajectoryPath, content, "utf-8")

    log.info("saved_trajectory", {
      sessionID: sessionID.slice(-8),
      entries: entries.length,
      childSessions: children.length,
    })

    return entries.length
  } catch (error) {
    log.error("save_trajectory_failed", { sessionID: sessionID.slice(-8), error })
    return 0
  } finally {
    lock[Symbol.dispose]()
  }
}

/**
 * Save complete training data for a session.
 */
export async function saveTrainingData(sessionID: string): Promise<{
  success: boolean
  metadata?: SessionMetadata
  trajectoryEntries: number
}> {
  const metadata = await saveSessionMetadata(sessionID)
  const trajectoryEntries = await saveTrajectory(sessionID)

  return {
    success: metadata !== null && trajectoryEntries > 0,
    metadata: metadata ?? undefined,
    trajectoryEntries,
  }
}

/**
 * Persist working directory state to the session archive.
 * Called before /tmp/ cleanup when a root session is deleted.
 * Copies state.yaml, state_history.yaml, findings/, and artifacts/
 * from the ephemeral /tmp/ directory to the persistent archive.
 */
export function persistWorkingDirToArchive(rootSessionID: string): void {
  const tmpDir = SessionDirectory.get(rootSessionID)
  if (!SessionDirectory.exists(rootSessionID)) {
    log.info("persist_skip_no_tmpdir", { sessionID: rootSessionID.slice(-8) })
    return
  }

  const archiveDir = ensureTrainingDir(rootSessionID)

  // Copy state files
  for (const file of ["state.yaml", "state_history.yaml"]) {
    const src = path.join(tmpDir, file)
    if (existsSync(src)) {
      copyFileSync(src, path.join(archiveDir, file))
    }
  }

  // Copy findings directory
  const findingsSrc = path.join(tmpDir, "findings")
  if (existsSync(findingsSrc)) {
    const findingsDest = path.join(archiveDir, "findings")
    mkdirSync(findingsDest, { recursive: true })
    cpSync(findingsSrc, findingsDest, { recursive: true })
  }

  // Copy artifacts (screenshots, loot)
  const artifactsSrc = path.join(tmpDir, "artifacts")
  if (existsSync(artifactsSrc)) {
    const artifactsDest = path.join(archiveDir, "artifacts")
    mkdirSync(artifactsDest, { recursive: true })
    cpSync(artifactsSrc, artifactsDest, { recursive: true })
  }

  log.info("persisted_working_dir", { sessionID: rootSessionID.slice(-8), archiveDir })
}

/**
 * Check if a session is a pentest session (mode === "pentest").
 */
async function isPentestSession(sessionID: string): Promise<boolean> {
  try {
    const messages = await Session.messages({ sessionID })
    for (const msg of messages) {
      if (msg.info.role === "assistant" && "mode" in msg.info) {
        return (msg.info as any).mode === "pentest"
      }
    }
    return false
  } catch {
    return false
  }
}

/**
 * Find the root session ID by walking up the parent chain.
 */
async function findRootSessionID(sessionID: string): Promise<string> {
  try {
    const session = await Session.get(sessionID)
    if (!session.parentID) {
      return sessionID
    }
    return findRootSessionID(session.parentID)
  } catch {
    return sessionID
  }
}

/**
 * Run one-time migrations:
 * - Rename ~/.opensploit/training/ to ~/.opensploit/sessions/
 * - Delete legacy ~/.opensploit/outputs/ and ~/.opensploit/output-index/
 */
function runMigrations(): void {
  const opensploitDir = path.join(os.homedir(), ".opensploit")
  const oldTrainingDir = path.join(opensploitDir, "training")
  const legacyOutputsDir = path.join(opensploitDir, "outputs")
  const legacyOutputIndexDir = path.join(opensploitDir, "output-index")

  // Migrate training/ → sessions/ (one-time rename)
  if (existsSync(oldTrainingDir) && !existsSync(SESSIONS_DIR)) {
    try {
      renameSync(oldTrainingDir, SESSIONS_DIR)
      log.info("migrated training/ to sessions/")
    } catch (error) {
      log.error("migration_failed", { from: "training/", to: "sessions/", error })
    }
  }

  // Delete legacy directories
  for (const dir of [legacyOutputsDir, legacyOutputIndexDir]) {
    if (existsSync(dir)) {
      try {
        rmSync(dir, { recursive: true, force: true })
        log.info("deleted_legacy_dir", { dir })
      } catch (error) {
        log.warn("failed_to_delete_legacy_dir", { dir, error })
      }
    }
  }
}

/**
 * Initialize training data capture.
 * Runs migrations, then subscribes to session events to auto-save pentest session data.
 * Re-captures whenever any session in the tree updates (root or child).
 */
export function init(): void {
  // Run one-time migrations
  runMigrations()

  Bus.subscribe(Session.Event.Updated, async (event) => {
    const { info } = event.properties

    // Find the root session (walk up parent chain if needed)
    const rootSessionID = await findRootSessionID(info.id)

    // Check if the root session is a pentest session
    const isPentest = await isPentestSession(rootSessionID)
    if (!isPentest) {
      return
    }

    // Save training data for root (aggregates all children)
    log.info("auto_save_triggered", {
      sessionID: rootSessionID.slice(-8),
      trigger: info.id === rootSessionID ? "root" : "child"
    })
    await saveTrainingData(rootSessionID)
  })

  log.info("training_data_capture_initialized")
}

/**
 * Load session metadata from disk.
 */
export function loadSessionMetadata(sessionID: string): SessionMetadata | null {
  const metadataPath = path.join(getSessionTrainingDir(sessionID), "session.json")
  if (!existsSync(metadataPath)) {
    return null
  }
  try {
    const content = readFileSync(metadataPath, "utf-8")
    return JSON.parse(content) as SessionMetadata
  } catch {
    return null
  }
}

/**
 * Load trajectory entries from disk.
 */
export function loadTrajectory(sessionID: string): TrajectoryEntry[] {
  const trajectoryPath = path.join(getSessionTrainingDir(sessionID), "trajectory.jsonl")
  if (!existsSync(trajectoryPath)) {
    return []
  }
  try {
    const content = readFileSync(trajectoryPath, "utf-8")
    return content
      .split("\n")
      .filter((line) => line.trim())
      .map((line) => JSON.parse(line) as TrajectoryEntry)
  } catch {
    return []
  }
}
