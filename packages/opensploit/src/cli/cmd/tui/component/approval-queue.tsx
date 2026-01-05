/**
 * Unified Approval Queue Component
 *
 * Shows all pending permissions from background sub-agents in one place,
 * allowing the user to approve/deny without switching sessions.
 *
 * Requirements:
 * - REQ-ARC-020: Permission requests from sub-agents SHALL bubble to root session
 * - REQ-ARC-021: Parent session SHALL show unified approval queue for all sub-agents
 */

import { TextAttributes } from "@opentui/core"
import { useTheme } from "../context/theme"
import { useSync } from "@tui/context/sync"
import { useRoute } from "@tui/context/route"
import { useSDK } from "@tui/context/sdk"
import { For, Show, createMemo } from "solid-js"

export function ApprovalQueue() {
  const { theme } = useTheme()
  const sync = useSync()
  const route = useRoute()
  const sdk = useSDK()

  // Get current session ID
  const sessionID = createMemo(() => {
    if (route.data.type === "session") return route.data.sessionID
    return null
  })

  // Get all pending permissions for this session (including bubbled from sub-agents)
  const pendingApprovals = createMemo(() => {
    const id = sessionID()
    if (!id) return []

    const permissions = sync.data.permission[id] ?? []
    return permissions.sort(
      (a, b) => (a.time?.created ?? 0) - (b.time?.created ?? 0)
    )
  })

  // Handle approve action
  const handleApprove = async (permissionID: string, always: boolean) => {
    const id = sessionID()
    if (!id) return

    await sdk.client.permission.respond({
      sessionID: id,
      permissionID,
      response: always ? "always" : "once",
    })
  }

  // Handle deny action
  const handleDeny = async (permissionID: string) => {
    const id = sessionID()
    if (!id) return

    await sdk.client.permission.respond({
      sessionID: id,
      permissionID,
      response: "reject",
    })
  }

  return (
    <Show when={pendingApprovals().length > 0}>
      <box
        borderStyle="single"
        borderColor={theme.warning}
        paddingLeft={1}
        paddingRight={1}
        marginTop={1}
        marginBottom={1}
        flexDirection="column"
      >
        <box flexDirection="row" justifyContent="space-between">
          <text fg={theme.warning} attributes={TextAttributes.BOLD}>
            Pending Approvals ({pendingApprovals().length})
          </text>
          <text fg={theme.textMuted}>
            [y] approve [Y] always [n] deny
          </text>
        </box>

        <For each={pendingApprovals()}>
          {(approval) => {
            // Check if this is a bubbled permission from a sub-agent
            const isBubbled = (approval as any).sourceSessionID !== undefined
            const agentName = (approval as any).agentName

            return (
              <box
                flexDirection="column"
                paddingTop={1}
                paddingBottom={1}
                borderStyle="single"
                borderColor={theme.backgroundElement}
              >
                <box flexDirection="row" gap={2}>
                  <text fg={theme.text} attributes={TextAttributes.BOLD}>
                    {approval.type}
                  </text>
                  <Show when={isBubbled && agentName}>
                    <text fg={theme.textMuted}>
                      from @{agentName}
                    </text>
                  </Show>
                </box>

                <text fg={theme.text} wrapMode="word">
                  {approval.title}
                </text>

                {/* Show metadata if available */}
                <Show when={approval.metadata}>
                  <box paddingLeft={2}>
                    <For each={Object.entries(approval.metadata).slice(0, 3)}>
                      {([key, value]) => (
                        <text fg={theme.textMuted}>
                          {key}: {String(value).substring(0, 60)}
                        </text>
                      )}
                    </For>
                  </box>
                </Show>

                {/* Action buttons */}
                <box flexDirection="row" gap={2} marginTop={1}>
                  <box
                    paddingLeft={1}
                    paddingRight={1}
                    backgroundColor={theme.success}
                    onMouseUp={() => handleApprove(approval.id, false)}
                  >
                    <text fg={theme.selectedListItemText}>[y] Once</text>
                  </box>
                  <box
                    paddingLeft={1}
                    paddingRight={1}
                    backgroundColor={theme.success}
                    onMouseUp={() => handleApprove(approval.id, true)}
                  >
                    <text fg={theme.selectedListItemText}>[Y] Always</text>
                  </box>
                  <box
                    paddingLeft={1}
                    paddingRight={1}
                    backgroundColor={theme.error}
                    onMouseUp={() => handleDeny(approval.id)}
                  >
                    <text fg={theme.selectedListItemText}>[n] Deny</text>
                  </box>
                </box>
              </box>
            )
          }}
        </For>
      </box>
    </Show>
  )
}
