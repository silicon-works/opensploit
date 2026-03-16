import { Log } from "../util/log"
import { getRootSession } from "../session/hierarchy"

const log = Log.create({ service: "permission.ultrasploit" })

const state = new Map<string, boolean>()

export namespace Ultrasploit {
  export function enable(sessionID: string): void {
    const rootSessionID = getRootSession(sessionID)
    state.set(rootSessionID, true)
    log.info("enabled", { sessionID: sessionID.slice(-8), rootSessionID: rootSessionID.slice(-8) })
  }

  export function disable(sessionID: string): void {
    const rootSessionID = getRootSession(sessionID)
    state.delete(rootSessionID)
    log.info("disabled", { sessionID: sessionID.slice(-8), rootSessionID: rootSessionID.slice(-8) })
  }

  export function isEnabled(sessionID: string): boolean {
    const rootSessionID = getRootSession(sessionID)
    return state.get(rootSessionID) === true
  }
}
