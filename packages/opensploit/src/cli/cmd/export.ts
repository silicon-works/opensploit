import type { Argv } from "yargs"
import { Session } from "../../session"
import { Trajectory } from "../../session/trajectory"
import { cmd } from "./cmd"
import { bootstrap } from "../bootstrap"
import { UI } from "../ui"
import * as prompts from "@clack/prompts"
import { EOL } from "os"

export const ExportCommand = cmd({
  command: "export [sessionID]",
  describe: "export session data as JSON",
  builder: (yargs: Argv) => {
    return yargs
      .positional("sessionID", {
        describe: "session id to export",
        type: "string",
      })
      .option("format", {
        describe: "export format",
        choices: ["json", "trajectory", "jsonl", "sharegpt"] as const,
        default: "json" as const,
      })
      .option("anonymize", {
        describe: "anonymize IPs, hostnames, and credentials for training data",
        type: "boolean",
        default: false,
      })
      .option("detect-anti-patterns", {
        describe: "detect anti-patterns for negative training data",
        type: "boolean",
        default: false,
      })
  },
  handler: async (args) => {
    await bootstrap(process.cwd(), async () => {
      let sessionID = args.sessionID
      process.stderr.write(`Exporting session: ${sessionID ?? "latest"}`)

      if (!sessionID) {
        UI.empty()
        prompts.intro("Export session", {
          output: process.stderr,
        })

        const sessions = []
        for await (const session of Session.list()) {
          sessions.push(session)
        }

        if (sessions.length === 0) {
          prompts.log.error("No sessions found", {
            output: process.stderr,
          })
          prompts.outro("Done", {
            output: process.stderr,
          })
          return
        }

        sessions.sort((a, b) => b.time.updated - a.time.updated)

        const selectedSession = await prompts.autocomplete({
          message: "Select session to export",
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

        prompts.outro("Exporting session...", {
          output: process.stderr,
        })
      }

      try {
        const format = args.format ?? "json"

        if (format === "json") {
          // Original JSON export
          const sessionInfo = await Session.get(sessionID!)
          const messages = await Session.messages({ sessionID: sessionID! })

          const exportData = {
            info: sessionInfo,
            messages: messages.map((msg) => ({
              info: msg.info,
              parts: msg.parts,
            })),
          }

          process.stdout.write(JSON.stringify(exportData, null, 2))
          process.stdout.write(EOL)
        } else if (format === "trajectory" || format === "jsonl" || format === "sharegpt") {
          // Trajectory-based exports for training data
          let trajectory = await Trajectory.fromSession(sessionID!)

          if (!trajectory || trajectory.trajectory.length === 0) {
            UI.error("No TVAR reasoning found in session. Ensure the pentest agent was used.")
            process.exit(1)
          }

          process.stderr.write(`\nFound ${trajectory.trajectory.length} TVAR steps\n`)

          // Apply anonymization if requested
          if (args.anonymize) {
            trajectory = Trajectory.anonymize(trajectory)
            process.stderr.write("Applied anonymization to trajectory\n")
          }

          // Detect anti-patterns if requested
          if (args["detect-anti-patterns"]) {
            const antiPatterns = Trajectory.detectAntiPatterns(trajectory)
            trajectory.antiPatterns = antiPatterns
            if (antiPatterns.length > 0) {
              process.stderr.write(`Detected ${antiPatterns.length} anti-patterns for negative training\n`)
            }
          }

          if (format === "trajectory") {
            // Full trajectory JSON
            process.stdout.write(JSON.stringify(trajectory, null, 2))
          } else if (format === "jsonl") {
            // JSONL for fine-tuning
            process.stdout.write(Trajectory.toJSONL(trajectory))
          } else if (format === "sharegpt") {
            // ShareGPT format
            process.stdout.write(Trajectory.toShareGPT(trajectory))
          }
          process.stdout.write(EOL)
        }
      } catch (error) {
        UI.error(`Session not found: ${sessionID!}`)
        process.exit(1)
      }
    })
  },
})
