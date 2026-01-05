/**
 * Background Task Manager
 *
 * Manages sub-agents running in the background during penetration testing.
 * Provides status tracking, permission bubbling, and unified approval queue.
 *
 * Requirements:
 * - REQ-AGT-001: Sub-agents spawn without blocking master
 * - REQ-AGT-002: Background execution with status updates
 * - REQ-AGT-003: Permission requests bubble to root session
 * - REQ-AGT-004: Master can query sub-agent status
 */

import { Bus } from "@/bus"
import { BusEvent } from "@/bus/bus-event"
import { Session } from "."
import { SessionPrompt } from "./prompt"
import { MessageV2 } from "./message-v2"
import { Log } from "@/util/log"
import z from "zod"

const log = Log.create({ service: "session.background-task" })

export namespace BackgroundTask {
  /**
   * Status of a background task
   */
  export type Status = "pending" | "running" | "completed" | "error" | "waiting_approval"

  /**
   * Background task info
   */
  export interface Info {
    id: string
    sessionID: string
    rootSessionID: string
    agentName: string
    description: string
    status: Status
    startTime: number
    endTime?: number
    error?: string
    result?: string
    pendingApprovals: number
  }

  /**
   * Events for background task updates
   */
  export const Event = {
    Started: BusEvent.define(
      "background_task.started",
      z.object({
        task: z.custom<Info>(),
      })
    ),
    Updated: BusEvent.define(
      "background_task.updated",
      z.object({
        task: z.custom<Info>(),
      })
    ),
    Completed: BusEvent.define(
      "background_task.completed",
      z.object({
        task: z.custom<Info>(),
      })
    ),
    ApprovalRequired: BusEvent.define(
      "background_task.approval_required",
      z.object({
        taskID: z.string(),
        rootSessionID: z.string(),
        callID: z.string(),
        type: z.string(),
        title: z.string(),
      })
    ),
  }

  // In-memory store for background tasks (per root session)
  const taskStore = new Map<string, Map<string, Info>>()

  /**
   * Get all tasks for a root session
   */
  export function getTasks(rootSessionID: string): Info[] {
    const sessionTasks = taskStore.get(rootSessionID)
    if (!sessionTasks) return []
    return Array.from(sessionTasks.values())
  }

  /**
   * Get a specific task
   */
  export function getTask(rootSessionID: string, taskID: string): Info | undefined {
    return taskStore.get(rootSessionID)?.get(taskID)
  }

  /**
   * Register a new background task
   */
  export function register(task: Info): void {
    let sessionTasks = taskStore.get(task.rootSessionID)
    if (!sessionTasks) {
      sessionTasks = new Map()
      taskStore.set(task.rootSessionID, sessionTasks)
    }
    sessionTasks.set(task.id, task)
    Bus.publish(Event.Started, { task })
    log.info("registered", { taskID: task.id, agent: task.agentName })
  }

  /**
   * Update task status
   */
  export function update(rootSessionID: string, taskID: string, updates: Partial<Info>): Info | undefined {
    const task = getTask(rootSessionID, taskID)
    if (!task) return undefined

    Object.assign(task, updates)
    Bus.publish(Event.Updated, { task })
    return task
  }

  /**
   * Mark task as completed
   */
  export function complete(rootSessionID: string, taskID: string, result?: string): void {
    const task = update(rootSessionID, taskID, {
      status: "completed",
      endTime: Date.now(),
      result,
    })
    if (task) {
      Bus.publish(Event.Completed, { task })
      log.info("completed", { taskID, agent: task.agentName })
    }
  }

  /**
   * Mark task as errored
   */
  export function fail(rootSessionID: string, taskID: string, error: string): void {
    const task = update(rootSessionID, taskID, {
      status: "error",
      endTime: Date.now(),
      error,
    })
    if (task) {
      Bus.publish(Event.Completed, { task })
      log.error("failed", { taskID, agent: task?.agentName, error })
    }
  }

  /**
   * Notify that an approval is required for a task
   */
  export function requireApproval(
    rootSessionID: string,
    taskID: string,
    approval: { callID: string; type: string; title: string }
  ): void {
    const task = getTask(rootSessionID, taskID)
    if (task) {
      task.pendingApprovals++
      task.status = "waiting_approval"
      Bus.publish(Event.Updated, { task })
      Bus.publish(Event.ApprovalRequired, {
        taskID,
        rootSessionID,
        ...approval,
      })
      log.info("approval_required", { taskID, agent: task.agentName, type: approval.type })
    }
  }

  /**
   * Clear approval (after user responds)
   */
  export function clearApproval(rootSessionID: string, taskID: string): void {
    const task = getTask(rootSessionID, taskID)
    if (task && task.pendingApprovals > 0) {
      task.pendingApprovals--
      if (task.pendingApprovals === 0 && task.status === "waiting_approval") {
        task.status = "running"
      }
      Bus.publish(Event.Updated, { task })
    }
  }

  /**
   * Get summary of active tasks
   */
  export function getSummary(rootSessionID: string): {
    total: number
    running: number
    waitingApproval: number
    completed: number
    failed: number
  } {
    const tasks = getTasks(rootSessionID)
    return {
      total: tasks.length,
      running: tasks.filter((t) => t.status === "running").length,
      waitingApproval: tasks.filter((t) => t.status === "waiting_approval").length,
      completed: tasks.filter((t) => t.status === "completed").length,
      failed: tasks.filter((t) => t.status === "error").length,
    }
  }

  /**
   * Clean up tasks for a session
   */
  export function cleanup(rootSessionID: string): void {
    taskStore.delete(rootSessionID)
  }

  /**
   * Get all pending approvals across all background tasks for a root session
   */
  export function getPendingApprovals(rootSessionID: string): Array<{
    taskID: string
    agentName: string
    sessionID: string
  }> {
    const tasks = getTasks(rootSessionID)
    return tasks
      .filter((t) => t.pendingApprovals > 0)
      .map((t) => ({
        taskID: t.id,
        agentName: t.agentName,
        sessionID: t.sessionID,
      }))
  }
}
