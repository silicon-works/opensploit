import { createMemo, Match, onCleanup, onMount, Show, Switch } from "solid-js"
import { useTheme } from "../../context/theme"
import { useSync } from "../../context/sync"
import { useDirectory } from "../../context/directory"
import { useConnected } from "../../component/dialog-model"
import { createStore } from "solid-js/store"
import { useRoute } from "../../context/route"
import { BackgroundTask } from "@/session/background-task"

export function Footer() {
  const { theme } = useTheme()
  const sync = useSync()
  const route = useRoute()
  const mcp = createMemo(() => Object.values(sync.data.mcp).filter((x) => x.status === "connected").length)
  const mcpError = createMemo(() => Object.values(sync.data.mcp).some((x) => x.status === "failed"))
  const lsp = createMemo(() => Object.keys(sync.data.lsp))
  const permissions = createMemo(() => {
    if (route.data.type !== "session") return []
    return sync.data.permission[route.data.sessionID] ?? []
  })

  // Count permissions from sub-agents (bubbled permissions)
  // Note: sourceSessionID is added by permission bubbling but not yet in SDK types
  const bubbledPermissions = createMemo(() => {
    return permissions().filter((p) => (p as any).sourceSessionID !== undefined)
  })

  // Get background task summary
  const backgroundTasks = createMemo(() => {
    if (route.data.type !== "session") return null
    const summary = BackgroundTask.getSummary(route.data.sessionID)
    if (summary.total === 0) return null
    return summary
  })
  const directory = useDirectory()
  const connected = useConnected()

  const [store, setStore] = createStore({
    welcome: false,
  })

  onMount(() => {
    function tick() {
      if (connected()) return
      if (!store.welcome) {
        setStore("welcome", true)
        timeout = setTimeout(() => tick(), 5000)
        return
      }

      if (store.welcome) {
        setStore("welcome", false)
        timeout = setTimeout(() => tick(), 10_000)
        return
      }
    }
    let timeout = setTimeout(() => tick(), 10_000)

    onCleanup(() => {
      clearTimeout(timeout)
    })
  })

  return (
    <box flexDirection="row" justifyContent="space-between" gap={1} flexShrink={0}>
      <text fg={theme.textMuted}>{directory()}</text>
      <box gap={2} flexDirection="row" flexShrink={0}>
        <Switch>
          <Match when={store.welcome}>
            <text fg={theme.text}>
              Get started <span style={{ fg: theme.textMuted }}>/connect</span>
            </text>
          </Match>
          <Match when={connected()}>
            <Show when={backgroundTasks()}>
              <text fg={theme.text}>
                <Switch>
                  <Match when={backgroundTasks()!.waitingApproval > 0}>
                    <span style={{ fg: theme.warning }}>◐</span>
                  </Match>
                  <Match when={backgroundTasks()!.running > 0}>
                    <span style={{ fg: theme.success }}>◐</span>
                  </Match>
                  <Match when={true}>
                    <span style={{ fg: theme.textMuted }}>◐</span>
                  </Match>
                </Switch>{" "}
                {backgroundTasks()!.running} task{backgroundTasks()!.running !== 1 ? "s" : ""}
              </text>
            </Show>
            <Show when={permissions().length > 0}>
              <text fg={theme.warning}>
                <span style={{ fg: theme.warning }}>◉</span> {permissions().length} Permission
                {permissions().length > 1 ? "s" : ""}
                <Show when={bubbledPermissions().length > 0}>
                  <span style={{ fg: theme.textMuted }}> ({bubbledPermissions().length} from sub-agents)</span>
                </Show>
              </text>
            </Show>
            <text fg={theme.text}>
              <span style={{ fg: theme.success }}>•</span> {lsp().length} LSP
            </text>
            <Show when={mcp()}>
              <text fg={theme.text}>
                <Switch>
                  <Match when={mcpError()}>
                    <span style={{ fg: theme.error }}>⊙ </span>
                  </Match>
                  <Match when={true}>
                    <span style={{ fg: theme.success }}>⊙ </span>
                  </Match>
                </Switch>
                {mcp()} MCP
              </text>
            </Show>
            <text fg={theme.textMuted}>/status</text>
          </Match>
        </Switch>
      </box>
    </box>
  )
}
