import type { Argv } from "yargs"
import { cmd } from "./cmd"
import { Session } from "../../session"
import { Trajectory } from "../../session/trajectory"
import { bootstrap } from "../bootstrap"
import { UI } from "../ui"
import * as prompts from "@clack/prompts"

export const OutcomeCommand = cmd({
  command: "outcome [sessionID]",
  describe: "record pentest session outcome for training data quality",
  builder: (yargs: Argv) => {
    return yargs
      .positional("sessionID", {
        describe: "session id to annotate",
        type: "string",
      })
      .option("success", {
        describe: "whether the engagement was successful",
        type: "boolean",
      })
      .option("access", {
        describe: "highest access level achieved",
        choices: ["none", "user", "root"] as const,
      })
      .option("flags", {
        describe: "comma-separated list of flags captured",
        type: "string",
      })
      .option("notes", {
        describe: "additional notes about the engagement",
        type: "string",
      })
  },
  handler: async (args) => {
    await bootstrap(process.cwd(), async () => {
      let sessionID = args.sessionID

      // Interactive session selection if not provided
      if (!sessionID) {
        UI.empty()
        prompts.intro("Record engagement outcome", {
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
          message: "Select session to annotate",
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

      // Load existing trajectory or create new one
      let trajectory = await Trajectory.fromSession(sessionID)

      if (!trajectory) {
        UI.error("No TVAR reasoning found in session. Ensure the pentest agent was used.")
        process.exit(1)
      }

      // Interactive prompts if outcome details not provided
      let success = args.success
      let access = args.access
      let flags = args.flags?.split(",").map((f) => f.trim())
      let notes = args.notes

      if (success === undefined) {
        const successResult = await prompts.confirm({
          message: "Was the engagement successful?",
          output: process.stderr,
        })
        if (prompts.isCancel(successResult)) throw new UI.CancelledError()
        success = successResult
      }

      if (!access) {
        const accessResult = await prompts.select({
          message: "Highest access level achieved?",
          options: [
            { label: "None", value: "none" },
            { label: "User shell", value: "user" },
            { label: "Root/Admin", value: "root" },
          ],
          output: process.stderr,
        })
        if (prompts.isCancel(accessResult)) throw new UI.CancelledError()
        access = accessResult as "none" | "user" | "root"
      }

      if (!flags && (access === "user" || access === "root")) {
        const flagsResult = await prompts.text({
          message: "Flags captured? (comma-separated, e.g., user.txt,root.txt)",
          placeholder: "user.txt,root.txt",
          output: process.stderr,
        })
        if (prompts.isCancel(flagsResult)) throw new UI.CancelledError()
        if (flagsResult) {
          flags = flagsResult.split(",").map((f) => f.trim())
        }
      }

      if (!notes) {
        const notesResult = await prompts.text({
          message: "Additional notes? (optional)",
          placeholder: "Key techniques used, challenges encountered",
          output: process.stderr,
        })
        if (prompts.isCancel(notesResult)) throw new UI.CancelledError()
        notes = notesResult || undefined
      }

      // Update trajectory with outcome
      trajectory.outcome = {
        success,
        accessAchieved: access,
        flagsCaptured: flags,
        notes,
      }

      // Save the updated trajectory
      await Trajectory.save(trajectory)

      prompts.outro(`Outcome recorded for session ${sessionID.slice(-8)}`, {
        output: process.stderr,
      })

      // Show summary
      console.log("\nOutcome Summary:")
      console.log(`  Success: ${success ? "Yes" : "No"}`)
      console.log(`  Access: ${access}`)
      if (flags && flags.length > 0) {
        console.log(`  Flags: ${flags.join(", ")}`)
      }
      if (notes) {
        console.log(`  Notes: ${notes}`)
      }
    })
  },
})
