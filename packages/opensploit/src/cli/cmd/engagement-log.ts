import type { Argv } from "yargs"
import { Session } from "../../session"
import { Trajectory } from "../../session/trajectory"
import { cmd } from "./cmd"
import { bootstrap } from "../bootstrap"
import { UI } from "../ui"
import * as prompts from "@clack/prompts"
import { EOL } from "os"

export const EngagementLogCommand = cmd({
  command: "engagement-log [sessionID]",
  describe: "view consolidated activity log across all sub-agents",
  builder: (yargs: Argv) => {
    return yargs
      .positional("sessionID", {
        describe: "root session id (engagement)",
        type: "string",
      })
      .option("format", {
        describe: "output format",
        choices: ["text", "json"] as const,
        default: "text" as const,
      })
      .option("filter", {
        describe: "filter by type (tool, tvar, all)",
        choices: ["tool", "tvar", "all"] as const,
        default: "all" as const,
      })
      .option("agent", {
        describe: "filter by agent name",
        type: "string",
      })
  },
  handler: async (args) => {
    await bootstrap(process.cwd(), async () => {
      let sessionID = args.sessionID

      if (!sessionID) {
        UI.empty()
        prompts.intro("Engagement Log", {
          output: process.stderr,
        })

        // Only show root sessions (no parentID)
        const sessions = []
        for await (const session of Session.list()) {
          if (!session.parentID) {
            sessions.push(session)
          }
        }

        if (sessions.length === 0) {
          prompts.log.error("No engagement sessions found", {
            output: process.stderr,
          })
          prompts.outro("Done", {
            output: process.stderr,
          })
          return
        }

        sessions.sort((a, b) => b.time.updated - a.time.updated)

        const selectedSession = await prompts.autocomplete({
          message: "Select engagement to view",
          maxItems: 10,
          options: sessions.map((session) => ({
            label: session.title,
            value: session.id,
            hint: `${new Date(session.time.updated).toLocaleString()} • ${session.id.slice(-8)}`,
          })),
          output: process.stderr,
        })

        if (prompts.isCancel(selectedSession)) {
          throw new UI.CancelledError()
        }

        sessionID = selectedSession as string
      }

      try {
        process.stderr.write(`\nLoading engagement log for ${sessionID}...\n\n`)

        const log = await Trajectory.fromEngagement(sessionID!)

        // Apply filters
        let filteredEntries = log.entries

        if (args.filter !== "all") {
          filteredEntries = filteredEntries.filter((e) => e.type === args.filter)
        }

        if (args.agent) {
          filteredEntries = filteredEntries.filter(
            (e) => e.agentName.toLowerCase() === args.agent!.toLowerCase()
          )
        }

        const filteredLog = { ...log, entries: filteredEntries }

        if (args.format === "json") {
          process.stdout.write(JSON.stringify(filteredLog, null, 2))
          process.stdout.write(EOL)
        } else {
          // Text format
          process.stdout.write(Trajectory.formatEngagementLog(filteredLog))
          process.stdout.write(EOL)

          // Summary to stderr
          process.stderr.write(`\n${filteredLog.entries.length} entries`)
          if (args.filter !== "all" || args.agent) {
            process.stderr.write(` (filtered)`)
          }
          process.stderr.write(`\n`)
        }
      } catch (error) {
        UI.error(`Failed to load engagement: ${sessionID!}`)
        process.exit(1)
      }
    })
  },
})
