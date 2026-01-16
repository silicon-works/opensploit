/**
 * Engagement Log CLI Command
 *
 * View consolidated activity log across all sub-agents in a pentest engagement.
 *
 * Requirements (Feature 06):
 * - REQ-SES-013: CLI command to view engagement timeline
 * - REQ-SES-014: Exportable for post-engagement analysis
 */

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
        describe: "filter by entry type",
        choices: ["tool", "tvar", "all"] as const,
        default: "all" as const,
      })
      .option("agent", {
        describe: "filter by agent name",
        type: "string",
      })
      .option("phase", {
        describe: "filter by phase",
        choices: ["reconnaissance", "enumeration", "exploitation", "post_exploitation", "reporting"] as const,
        type: "string",
      })
  },
  handler: async (args) => {
    await bootstrap(process.cwd(), async () => {
      let sessionID = args.sessionID

      // If no sessionID provided, show interactive selector
      if (!sessionID) {
        UI.empty()
        prompts.intro("Engagement Log")

        // Only show root sessions (no parentID)
        const sessions: Session.Info[] = []
        for await (const session of Session.list()) {
          if (!session.parentID) {
            sessions.push(session)
          }
        }

        if (sessions.length === 0) {
          prompts.log.error("No engagement sessions found")
          prompts.outro("Done")
          return
        }

        // Sort by most recent first
        sessions.sort((a, b) => b.time.updated - a.time.updated)

        const selectedSession = await prompts.select({
          message: "Select engagement to view",
          options: sessions.slice(0, 20).map((session) => ({
            label: session.title,
            value: session.id,
            hint: `${new Date(session.time.updated).toLocaleString()} - ${session.id.slice(-8)}`,
          })),
        })

        if (prompts.isCancel(selectedSession)) {
          throw new UI.CancelledError()
        }

        sessionID = selectedSession as string
      }

      try {
        process.stderr.write(`\nLoading engagement log for ${sessionID}...\n\n`)

        const engagementLog = await Trajectory.fromEngagement(sessionID)

        // Apply filters
        let filteredEntries = engagementLog.entries

        // Filter by type
        if (args.filter !== "all") {
          filteredEntries = filteredEntries.filter((e) => e.type === args.filter)
        }

        // Filter by agent
        if (args.agent) {
          const agentLower = args.agent.toLowerCase()
          filteredEntries = filteredEntries.filter((e) => e.agentName.toLowerCase() === agentLower)
        }

        // Filter by phase
        if (args.phase) {
          filteredEntries = filteredEntries.filter((e) => e.phase === args.phase)
        }

        const filteredLog: Trajectory.EngagementLog = {
          ...engagementLog,
          entries: filteredEntries,
        }

        if (args.format === "json") {
          process.stdout.write(JSON.stringify(filteredLog, null, 2))
          process.stdout.write(EOL)
        } else {
          // Text format
          process.stdout.write(Trajectory.formatEngagementLog(filteredLog))
          process.stdout.write(EOL)

          // Summary to stderr
          process.stderr.write(`\n${filteredLog.entries.length} entries`)
          if (args.filter !== "all" || args.agent || args.phase) {
            process.stderr.write(` (filtered)`)
          }
          process.stderr.write(`\n`)
        }
      } catch (error) {
        if (error instanceof Error) {
          UI.error(`Failed to load engagement: ${error.message}`)
        } else {
          UI.error(`Failed to load engagement: ${sessionID}`)
        }
        process.exit(1)
      }
    })
  },
})
