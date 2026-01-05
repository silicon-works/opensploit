import { TextAttributes } from "@opentui/core"
import { useTheme } from "../context/theme"
import { useSync } from "@tui/context/sync"
import { useRoute } from "@tui/context/route"
import { For, Show, createMemo, createResource, createSignal, Switch, Match } from "solid-js"
import { Trajectory } from "@/session/trajectory"
import { BackgroundTask } from "@/session/background-task"
import { EngagementState } from "@/session/engagement-state"
import { useDialog } from "../ui/dialog"

export function DialogEngagementLog() {
  const { theme } = useTheme()
  const route = useRoute()
  const dialog = useDialog()
  const [tab, setTab] = createSignal<"log" | "state" | "tasks">("log")

  // Get the current session ID
  const sessionID = createMemo(() => {
    if (route.data.type === "session") return route.data.sessionID
    return null
  })

  // Fetch engagement log
  const [engagementLog, { refetch }] = createResource(sessionID, async (id) => {
    if (!id) return null
    try {
      return await Trajectory.fromEngagement(id)
    } catch (e) {
      console.error("Failed to fetch engagement log:", e)
      return null
    }
  })

  // Get engagement state
  const state = createMemo(() => {
    const id = sessionID()
    if (!id) return null
    return EngagementState.read(id)
  })

  // Get background tasks
  const tasks = createMemo(() => {
    const id = sessionID()
    if (!id) return []
    return BackgroundTask.getTasks(id)
  })

  const typeIcon = (type: string) => {
    switch (type) {
      case "tool":
        return "\u{1F527}" // wrench emoji
      case "tvar":
        return "\u{1F4AD}" // thought bubble
      default:
        return "\u{1F4DD}" // memo
    }
  }

  const severityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return theme.error
      case "high":
        return "#ff6b6b"
      case "medium":
        return theme.warning
      case "low":
        return theme.success
      default:
        return theme.textMuted
    }
  }

  const statusColor = (status: string) => {
    switch (status) {
      case "running":
        return theme.success
      case "completed":
        return theme.textMuted
      case "error":
        return theme.error
      case "waiting_approval":
        return theme.warning
      default:
        return theme.text
    }
  }

  return (
    <box paddingLeft={2} paddingRight={2} gap={1} paddingBottom={1} minWidth={60}>
      <box flexDirection="row" justifyContent="space-between">
        <text fg={theme.text} attributes={TextAttributes.BOLD}>
          Engagement Dashboard
        </text>
        <text fg={theme.textMuted}>esc</text>
      </box>

      {/* Tab buttons */}
      <box flexDirection="row" gap={2}>
        <text
          fg={tab() === "log" ? theme.text : theme.textMuted}
          attributes={tab() === "log" ? TextAttributes.BOLD : undefined}
        >
          [1] Activity Log
        </text>
        <text
          fg={tab() === "state" ? theme.text : theme.textMuted}
          attributes={tab() === "state" ? TextAttributes.BOLD : undefined}
        >
          [2] State
        </text>
        <text
          fg={tab() === "tasks" ? theme.text : theme.textMuted}
          attributes={tab() === "tasks" ? TextAttributes.BOLD : undefined}
        >
          [3] Tasks
        </text>
      </box>

      <Switch>
        {/* Activity Log Tab */}
        <Match when={tab() === "log"}>
          <Show when={engagementLog.loading}>
            <text fg={theme.textMuted}>Loading engagement log...</text>
          </Show>

          <Show when={engagementLog.error}>
            <text fg={theme.error}>Error loading engagement log</text>
          </Show>

          <Show when={engagementLog() && !engagementLog.loading}>
            <box>
              <text fg={theme.text} attributes={TextAttributes.BOLD}>
                Summary
              </text>
              <text fg={theme.text}>
                Agents: <span style={{ fg: theme.textMuted }}>{engagementLog()!.summary.agentNames.join(", ")}</span>
              </text>
              <text fg={theme.text}>
                Tools:{" "}
                <span style={{ fg: theme.success }}>{engagementLog()!.summary.successfulTools} success</span>
                {" / "}
                <span style={{ fg: theme.error }}>{engagementLog()!.summary.failedTools} failed</span>
              </text>
              <Show when={engagementLog()!.summary.phases.length > 0}>
                <text fg={theme.text}>
                  Phases: <span style={{ fg: theme.textMuted }}>{engagementLog()!.summary.phases.join(" -> ")}</span>
                </text>
              </Show>
            </box>

            <box>
              <text fg={theme.text} attributes={TextAttributes.BOLD}>
                Recent Activity
              </text>
              <For each={engagementLog()!.entries.slice(-20)}>
                {(entry) => {
                  const time = entry.timestamp.split("T")[1]?.substring(0, 8) || ""
                  return (
                    <box flexDirection="row" gap={1}>
                      <text fg={theme.textMuted} flexShrink={0}>
                        {time}
                      </text>
                      <text fg={theme.text} flexShrink={0}>
                        [{entry.agentName.substring(0, 10)}]
                      </text>
                      <text fg={theme.textMuted}>{typeIcon(entry.type)}</text>
                      <text fg={theme.text} wrapMode="char">
                        {entry.summary.substring(0, 50)}
                      </text>
                    </box>
                  )
                }}
              </For>
            </box>
          </Show>

          <Show when={!sessionID()}>
            <text fg={theme.textMuted}>No active session</text>
          </Show>
        </Match>

        {/* State Tab */}
        <Match when={tab() === "state"}>
          <Show
            when={state()}
            fallback={<text fg={theme.textMuted}>No engagement state found</text>}
          >
            {(s) => (
              <box gap={1}>
                <Show when={s().target}>
                  <box>
                    <text fg={theme.text} attributes={TextAttributes.BOLD}>
                      Target
                    </text>
                    <Show when={s().target?.ip}>
                      <text fg={theme.text}>
                        IP: <span style={{ fg: theme.textMuted }}>{s().target!.ip}</span>
                      </text>
                    </Show>
                    <Show when={s().target?.hostname}>
                      <text fg={theme.text}>
                        Hostname: <span style={{ fg: theme.textMuted }}>{s().target!.hostname}</span>
                      </text>
                    </Show>
                    <Show when={s().target?.os}>
                      <text fg={theme.text}>
                        OS: <span style={{ fg: theme.textMuted }}>{s().target!.os}</span>
                      </text>
                    </Show>
                  </box>
                </Show>

                <Show when={s().phase}>
                  <text fg={theme.text}>
                    Phase: <span style={{ fg: theme.warning }}>{s().phase}</span>
                  </text>
                </Show>

                <Show when={s().accessLevel && s().accessLevel !== "none"}>
                  <text fg={theme.text}>
                    Access:{" "}
                    <span style={{ fg: s().accessLevel === "root" ? theme.error : theme.warning }}>
                      {s().accessLevel}
                    </span>
                  </text>
                </Show>

                <Show when={s().ports?.length}>
                  <box>
                    <text fg={theme.text} attributes={TextAttributes.BOLD}>
                      Ports ({s().ports!.length})
                    </text>
                    <For each={s().ports!.slice(0, 10)}>
                      {(port) => (
                        <text fg={theme.text}>
                          <span style={{ fg: theme.success }}>*</span> {port.port}/{port.protocol} - {port.service}
                          <Show when={port.version}>
                            <span style={{ fg: theme.textMuted }}> ({port.version})</span>
                          </Show>
                        </text>
                      )}
                    </For>
                    <Show when={s().ports!.length > 10}>
                      <text fg={theme.textMuted}>...and {s().ports!.length - 10} more</text>
                    </Show>
                  </box>
                </Show>

                <Show when={s().credentials?.length}>
                  <box>
                    <text fg={theme.text} attributes={TextAttributes.BOLD}>
                      Credentials ({s().credentials!.length})
                    </text>
                    <For each={s().credentials!}>
                      {(cred) => (
                        <text fg={theme.text}>
                          <span style={{ fg: cred.validated ? theme.success : theme.warning }}>*</span>{" "}
                          {cred.username}:{cred.password ? "***" : cred.hash?.substring(0, 8) + "..."}
                          <span style={{ fg: theme.textMuted }}> [{cred.source}]</span>
                        </text>
                      )}
                    </For>
                  </box>
                </Show>

                <Show when={s().vulnerabilities?.length}>
                  <box>
                    <text fg={theme.text} attributes={TextAttributes.BOLD}>
                      Vulnerabilities ({s().vulnerabilities!.length})
                    </text>
                    <For each={s().vulnerabilities!}>
                      {(vuln) => (
                        <text fg={theme.text}>
                          <span style={{ fg: severityColor(vuln.severity) }}>*</span> [{vuln.severity.toUpperCase()}]{" "}
                          {vuln.name}
                          <span style={{ fg: theme.textMuted }}> on {vuln.service}</span>
                          <Show when={vuln.exploitAvailable}>
                            <span style={{ fg: theme.success }}> (exploit available)</span>
                          </Show>
                        </text>
                      )}
                    </For>
                  </box>
                </Show>

                <Show when={s().flags?.length}>
                  <box>
                    <text fg={theme.text} attributes={TextAttributes.BOLD}>
                      Flags ({s().flags!.length})
                    </text>
                    <For each={s().flags!}>
                      {(flag) => (
                        <text fg={theme.success}>
                          * {flag}
                        </text>
                      )}
                    </For>
                  </box>
                </Show>
              </box>
            )}
          </Show>
        </Match>

        {/* Tasks Tab */}
        <Match when={tab() === "tasks"}>
          <Show
            when={tasks().length > 0}
            fallback={<text fg={theme.textMuted}>No background tasks</text>}
          >
            <box>
              <text fg={theme.text} attributes={TextAttributes.BOLD}>
                Background Tasks ({tasks().length})
              </text>
              <For each={tasks()}>
                {(task) => (
                  <box flexDirection="row" gap={1}>
                    <text fg={statusColor(task.status)} flexShrink={0}>
                      *
                    </text>
                    <text fg={theme.text} flexShrink={0}>
                      [{task.agentName}]
                    </text>
                    <text fg={theme.text} wrapMode="char">
                      {task.description}
                    </text>
                    <text fg={theme.textMuted} flexShrink={0}>
                      ({task.status})
                    </text>
                    <Show when={task.pendingApprovals > 0}>
                      <text fg={theme.warning} flexShrink={0}>
                        [{task.pendingApprovals} pending]
                      </text>
                    </Show>
                  </box>
                )}
              </For>
            </box>
          </Show>
        </Match>
      </Switch>
    </box>
  )
}
