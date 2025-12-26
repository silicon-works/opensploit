import { Config } from "../config/config"
import z from "zod"
import { Provider } from "../provider/provider"
import { generateObject, type ModelMessage } from "ai"
import { SystemPrompt } from "../session/system"
import { Instance } from "../project/instance"
import { mergeDeep } from "remeda"
import { Log } from "../util/log"

const log = Log.create({ service: "agent" })

import PROMPT_GENERATE from "./generate.txt"
import PROMPT_COMPACTION from "./prompt/compaction.txt"
import PROMPT_EXPLORE from "./prompt/explore.txt"
import PROMPT_SUMMARY from "./prompt/summary.txt"
import PROMPT_TITLE from "./prompt/title.txt"

// Pentest agent prompts
import PROMPT_PENTEST from "./prompt/pentest.txt"
import PROMPT_PENTEST_RECON from "./prompt/pentest/recon.txt"
import PROMPT_PENTEST_ENUM from "./prompt/pentest/enum.txt"
import PROMPT_PENTEST_EXPLOIT from "./prompt/pentest/exploit.txt"
import PROMPT_PENTEST_POST_EXPLOIT from "./prompt/pentest/post-exploit.txt"
import PROMPT_PENTEST_REPORT from "./prompt/pentest/report.txt"

export namespace Agent {
  export const Info = z
    .object({
      name: z.string(),
      description: z.string().optional(),
      mode: z.enum(["subagent", "primary", "all"]),
      native: z.boolean().optional(),
      hidden: z.boolean().optional(),
      default: z.boolean().optional(),
      topP: z.number().optional(),
      temperature: z.number().optional(),
      color: z.string().optional(),
      permission: z.object({
        edit: Config.Permission,
        bash: z.record(z.string(), Config.Permission),
        skill: z.record(z.string(), Config.Permission),
        webfetch: Config.Permission.optional(),
        doom_loop: Config.Permission.optional(),
        external_directory: Config.Permission.optional(),
      }),
      model: z
        .object({
          modelID: z.string(),
          providerID: z.string(),
        })
        .optional(),
      prompt: z.string().optional(),
      tools: z.record(z.string(), z.boolean()),
      options: z.record(z.string(), z.any()),
      maxSteps: z.number().int().positive().optional(),
    })
    .meta({
      ref: "Agent",
    })
  export type Info = z.infer<typeof Info>

  const state = Instance.state(async () => {
    const cfg = await Config.get()
    const defaultTools = cfg.tools ?? {}
    const defaultPermission: Info["permission"] = {
      edit: "allow",
      bash: {
        "*": "allow",
      },
      skill: {
        "*": "allow",
      },
      webfetch: "allow",
      doom_loop: "ask",
      external_directory: "ask",
    }
    const agentPermission = mergeAgentPermissions(defaultPermission, cfg.permission ?? {})

    const planPermission = mergeAgentPermissions(
      {
        edit: "deny",
        bash: {
          "cut*": "allow",
          "diff*": "allow",
          "du*": "allow",
          "file *": "allow",
          "find * -delete*": "ask",
          "find * -exec*": "ask",
          "find * -fprint*": "ask",
          "find * -fls*": "ask",
          "find * -fprintf*": "ask",
          "find * -ok*": "ask",
          "find *": "allow",
          "git diff*": "allow",
          "git log*": "allow",
          "git show*": "allow",
          "git status*": "allow",
          "git branch": "allow",
          "git branch -v": "allow",
          "grep*": "allow",
          "head*": "allow",
          "less*": "allow",
          "ls*": "allow",
          "more*": "allow",
          "pwd*": "allow",
          "rg*": "allow",
          "sort --output=*": "ask",
          "sort -o *": "ask",
          "sort*": "allow",
          "stat*": "allow",
          "tail*": "allow",
          "tree -o *": "ask",
          "tree*": "allow",
          "uniq*": "allow",
          "wc*": "allow",
          "whereis*": "allow",
          "which*": "allow",
          "*": "ask",
        },
        webfetch: "allow",
      },
      cfg.permission ?? {},
    )

    // Pentest agents use restricted bash permissions
    // DENY all security tools and code execution - they must use MCP tools instead
    const pentestBashPermissions = {
      // Explicitly DENY security tools (agents must use MCP tools)
      "nmap*": "deny",
      "ssh *": "deny",
      "ssh-*": "deny",
      "scp *": "deny",
      "sqlmap*": "deny",
      "hydra*": "deny",
      "nikto*": "deny",
      "gobuster*": "deny",
      "ffuf*": "deny",
      "dirb*": "deny",
      "wpscan*": "deny",
      "curl *": "deny",
      "wget *": "deny",
      "nc *": "deny",
      "ncat*": "deny",
      "netcat*": "deny",
      "metasploit*": "deny",
      "msfconsole*": "deny",
      "msfvenom*": "deny",
      "john*": "deny",
      "hashcat*": "deny",
      "crackmapexec*": "deny",
      "enum4linux*": "deny",
      "smbclient*": "deny",
      "rpcclient*": "deny",
      "impacket*": "deny",
      "linpeas*": "deny",
      "winpeas*": "deny",
      "sudo *": "deny",
      // DENY compilers and code execution (prevents running custom exploits via bash)
      "gcc*": "deny",
      "g++*": "deny",
      "cc *": "deny",
      "clang*": "deny",
      "make*": "deny",
      "cmake*": "deny",
      "./*": "deny", // block executing local binaries
      "sh *": "deny",
      "sh -c*": "deny",
      "bash *": "deny",
      "bash -c*": "deny",
      "zsh *": "deny",
      "python *": "deny",
      "python2*": "deny",
      "python3*": "deny",
      "perl *": "deny",
      "ruby *": "deny",
      "node *": "deny",
      "php *": "deny",
      "java *": "deny",
      "javac*": "deny",
      "go run*": "deny",
      "go build*": "deny",
      "cargo *": "deny",
      "rustc*": "deny",
      "chmod +x*": "deny",
      "chmod 7*": "deny",
      // Allow basic file system operations (read-only mostly)
      "ls*": "allow",
      "pwd*": "allow",
      "cat *": "allow",
      "head *": "allow",
      "tail *": "allow",
      "less *": "allow",
      "file *": "allow",
      "wc *": "allow",
      "grep *": "allow",
      "find *": "ask",
      "cd *": "allow",
      // Everything else requires explicit approval
      "*": "ask",
    } as const

    const pentestPermission = mergeAgentPermissions(
      {
        edit: "ask",
        bash: pentestBashPermissions,
        skill: {
          "*": "ask",
        },
        webfetch: "ask",
      },
      cfg.permission ?? {},
    )

    // Pentest recon/enum agents are more restricted (no edit)
    const pentestReadOnlyPermission = mergeAgentPermissions(
      {
        edit: "deny",
        bash: pentestBashPermissions,
        skill: {
          "*": "ask",
        },
        webfetch: "ask",
      },
      cfg.permission ?? {},
    )

    // Pentest report agent can write files but not run commands
    const pentestReportPermission = mergeAgentPermissions(
      {
        edit: "allow",
        bash: {
          "*": "deny",
        },
        skill: {
          "*": "deny",
        },
        webfetch: "deny",
      },
      cfg.permission ?? {},
    )

    const result: Record<string, Info> = {
      build: {
        name: "build",
        tools: { ...defaultTools },
        options: {},
        permission: agentPermission,
        mode: "primary",
        native: true,
      },
      plan: {
        name: "plan",
        options: {},
        permission: planPermission,
        tools: {
          ...defaultTools,
        },
        mode: "primary",
        native: true,
      },
      general: {
        name: "general",
        description: `General-purpose agent for researching complex questions and executing multi-step tasks. Use this agent to execute multiple units of work in parallel.`,
        tools: {
          todoread: false,
          todowrite: false,
          ...defaultTools,
        },
        options: {},
        permission: agentPermission,
        mode: "subagent",
        native: true,
        hidden: true,
      },
      explore: {
        name: "explore",
        tools: {
          todoread: false,
          todowrite: false,
          edit: false,
          write: false,
          ...defaultTools,
        },
        description: `Fast agent specialized for exploring codebases. Use this when you need to quickly find files by patterns (eg. "src/components/**/*.tsx"), search code for keywords (eg. "API endpoints"), or answer questions about the codebase (eg. "how do API endpoints work?"). When calling this agent, specify the desired thoroughness level: "quick" for basic searches, "medium" for moderate exploration, or "very thorough" for comprehensive analysis across multiple locations and naming conventions.`,
        prompt: PROMPT_EXPLORE,
        options: {},
        permission: agentPermission,
        mode: "subagent",
        native: true,
      },
      compaction: {
        name: "compaction",
        mode: "primary",
        native: true,
        hidden: true,
        prompt: PROMPT_COMPACTION,
        tools: {
          "*": false,
        },
        options: {},
        permission: agentPermission,
      },
      title: {
        name: "title",
        mode: "primary",
        options: {},
        native: true,
        hidden: true,
        permission: agentPermission,
        prompt: PROMPT_TITLE,
        tools: {},
      },
      summary: {
        name: "summary",
        mode: "primary",
        options: {},
        native: true,
        hidden: true,
        permission: agentPermission,
        prompt: PROMPT_SUMMARY,
        tools: {},
      },

      // ============================================
      // Pentest Agents
      // ============================================

      // Master pentest agent - primary orchestrator
      pentest: {
        name: "pentest",
        description:
          "Master penetration testing agent that orchestrates security assessments. Use this for comprehensive pentests, vulnerability assessments, and security testing.",
        mode: "primary",
        native: true,
        color: "#e74c3c",
        prompt: PROMPT_PENTEST,
        tools: { ...defaultTools },
        options: {},
        permission: pentestPermission,
      },

      // Reconnaissance subagent
      "pentest/recon": {
        name: "pentest/recon",
        description:
          "Reconnaissance phase subagent. Discovers open ports, services, and performs initial target enumeration. Can delegate sub-tasks to general agent.",
        mode: "subagent",
        native: true,
        color: "#3498db",
        prompt: PROMPT_PENTEST_RECON,
        tools: { ...defaultTools },
        options: {},
        permission: pentestReadOnlyPermission,
      },

      // Enumeration subagent
      "pentest/enum": {
        name: "pentest/enum",
        description:
          "Enumeration phase subagent. Performs detailed service enumeration, directory discovery, and vulnerability identification. Can delegate sub-tasks.",
        mode: "subagent",
        native: true,
        color: "#9b59b6",
        prompt: PROMPT_PENTEST_ENUM,
        tools: { ...defaultTools },
        options: {},
        permission: pentestReadOnlyPermission,
      },

      // Exploitation subagent
      "pentest/exploit": {
        name: "pentest/exploit",
        description:
          "Exploitation phase subagent. Tests and validates vulnerabilities through controlled exploitation. Can write custom exploits and delegate research.",
        mode: "subagent",
        native: true,
        color: "#e74c3c",
        prompt: PROMPT_PENTEST_EXPLOIT,
        tools: { ...defaultTools },
        options: {},
        permission: pentestPermission,
      },

      // Post-exploitation subagent
      "pentest/post-exploit": {
        name: "pentest/post-exploit",
        description:
          "Post-exploitation phase subagent. Assesses privilege escalation, lateral movement, and data exposure from compromised systems. Can delegate enumeration tasks.",
        mode: "subagent",
        native: true,
        color: "#f39c12",
        prompt: PROMPT_PENTEST_POST_EXPLOIT,
        tools: { ...defaultTools },
        options: {},
        permission: pentestPermission,
      },

      // Reporting subagent
      "pentest/report": {
        name: "pentest/report",
        description:
          "Reporting phase subagent. Generates comprehensive penetration test reports with findings, evidence, and remediation recommendations.",
        mode: "subagent",
        native: true,
        color: "#27ae60",
        prompt: PROMPT_PENTEST_REPORT,
        tools: {
          ...defaultTools,
          bash: false, // Report agent shouldn't run commands
        },
        options: {},
        permission: pentestReportPermission,
      },
    }
    for (const [key, value] of Object.entries(cfg.agent ?? {})) {
      if (value.disable) {
        delete result[key]
        continue
      }
      let item = result[key]
      if (!item)
        item = result[key] = {
          name: key,
          mode: "all",
          permission: agentPermission,
          options: {},
          tools: {},
          native: false,
        }
      const {
        name,
        model,
        prompt,
        tools,
        description,
        temperature,
        top_p,
        mode,
        permission,
        color,
        maxSteps,
        ...extra
      } = value
      item.options = {
        ...item.options,
        ...extra,
      }
      if (model) item.model = Provider.parseModel(model)
      if (prompt) item.prompt = prompt
      if (tools)
        item.tools = {
          ...item.tools,
          ...tools,
        }
      item.tools = {
        ...defaultTools,
        ...item.tools,
      }
      if (description) item.description = description
      if (temperature != undefined) item.temperature = temperature
      if (top_p != undefined) item.topP = top_p
      if (mode) item.mode = mode
      if (color) item.color = color
      // just here for consistency & to prevent it from being added as an option
      if (name) item.name = name
      if (maxSteps != undefined) item.maxSteps = maxSteps

      if (permission ?? cfg.permission) {
        item.permission = mergeAgentPermissions(cfg.permission ?? {}, permission ?? {})
      }
    }

    // Mark the default agent
    const defaultName = cfg.default_agent ?? "pentest"
    const defaultCandidate = result[defaultName]
    if (defaultCandidate && defaultCandidate.mode !== "subagent") {
      defaultCandidate.default = true
    } else {
      // Fall back to "build" if configured default is invalid
      if (result["build"]) {
        result["build"].default = true
      }
    }

    const hasPrimaryAgents = Object.values(result).filter((a) => a.mode !== "subagent" && !a.hidden).length > 0
    if (!hasPrimaryAgents) {
      throw new Config.InvalidError({
        path: "config",
        message: "No primary agents are available. Please configure at least one agent with mode 'primary' or 'all'.",
      })
    }

    return result
  })

  export async function get(agent: string) {
    return state().then((x) => x[agent])
  }

  export async function list() {
    return state().then((x) => Object.values(x))
  }

  export async function defaultAgent(): Promise<string> {
    const agents = await state()
    const defaultCandidate = Object.values(agents).find((a) => a.default)
    return defaultCandidate?.name ?? "build"
  }

  export async function generate(input: { description: string; model?: { providerID: string; modelID: string } }) {
    const cfg = await Config.get()
    const defaultModel = input.model ?? (await Provider.defaultModel())
    const model = await Provider.getModel(defaultModel.providerID, defaultModel.modelID)
    const language = await Provider.getLanguage(model)
    const system = SystemPrompt.header(defaultModel.providerID)
    system.push(PROMPT_GENERATE)
    const existing = await list()
    const result = await generateObject({
      experimental_telemetry: {
        isEnabled: cfg.experimental?.openTelemetry,
        metadata: {
          userId: cfg.username ?? "unknown",
        },
      },
      temperature: 0.3,
      messages: [
        ...system.map(
          (item): ModelMessage => ({
            role: "system",
            content: item,
          }),
        ),
        {
          role: "user",
          content: `Create an agent configuration based on this request: \"${input.description}\".\n\nIMPORTANT: The following identifiers already exist and must NOT be used: ${existing.map((i) => i.name).join(", ")}\n  Return ONLY the JSON object, no other text, do not wrap in backticks`,
        },
      ],
      model: language,
      schema: z.object({
        identifier: z.string(),
        whenToUse: z.string(),
        systemPrompt: z.string(),
      }),
    })
    return result.object
  }
}

function mergeAgentPermissions(basePermission: any, overridePermission: any): Agent.Info["permission"] {
  if (typeof basePermission.bash === "string") {
    basePermission.bash = {
      "*": basePermission.bash,
    }
  }
  if (typeof overridePermission.bash === "string") {
    overridePermission.bash = {
      "*": overridePermission.bash,
    }
  }

  if (typeof basePermission.skill === "string") {
    basePermission.skill = {
      "*": basePermission.skill,
    }
  }
  if (typeof overridePermission.skill === "string") {
    overridePermission.skill = {
      "*": overridePermission.skill,
    }
  }
  const merged = mergeDeep(basePermission ?? {}, overridePermission ?? {}) as any
  let mergedBash
  if (merged.bash) {
    if (typeof merged.bash === "string") {
      mergedBash = {
        "*": merged.bash,
      }
    } else if (typeof merged.bash === "object") {
      mergedBash = mergeDeep(
        {
          "*": "allow",
        },
        merged.bash,
      )
    }
  }

  let mergedSkill
  if (merged.skill) {
    if (typeof merged.skill === "string") {
      mergedSkill = {
        "*": merged.skill,
      }
    } else if (typeof merged.skill === "object") {
      mergedSkill = mergeDeep(
        {
          "*": "allow",
        },
        merged.skill,
      )
    }
  }

  const result: Agent.Info["permission"] = {
    edit: merged.edit ?? "allow",
    webfetch: merged.webfetch ?? "allow",
    bash: mergedBash ?? { "*": "allow" },
    skill: mergedSkill ?? { "*": "allow" },
    doom_loop: merged.doom_loop,
    external_directory: merged.external_directory,
  }

  return result
}
