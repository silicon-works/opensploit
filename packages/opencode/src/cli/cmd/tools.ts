import type { Argv } from "yargs"
import { cmd } from "./cmd"
import { UI } from "../ui"
import { EOL } from "os"
import * as prompts from "@clack/prompts"
import path from "path"
import os from "os"
import fs from "fs/promises"
import yaml from "js-yaml"
import z from "zod"

// Registry configuration
const REGISTRY_CONFIG = {
  REMOTE_URL: "https://opensploit.ai/registry.yaml",
  CACHE_DIR: path.join(os.homedir(), ".opensploit"),
  CACHE_PATH: path.join(os.homedir(), ".opensploit", "registry.yaml"),
  CACHE_TTL_MS: 24 * 60 * 60 * 1000, // 24 hours
}

const VALID_PHASES = ["reconnaissance", "enumeration", "exploitation", "post-exploitation"] as const

// Registry Zod Schema
const RegistryToolSchema = z.object({
  name: z.string(),
  version: z.string().optional(),
  description: z.string(),
  image: z.string().optional(),
  capabilities: z.array(z.string()).optional().default([]),
  phases: z.array(z.string()).optional().default([]),
  routing: z
    .object({
      use_for: z.array(z.string()).optional(),
      triggers: z.array(z.string()).optional(),
      never_use_for: z.array(z.union([z.string(), z.object({ task: z.string(), use_instead: z.union([z.string(), z.array(z.string())]), reason: z.string().optional() })])).optional(),
      prefer_over: z.array(z.string()).optional(),
    })
    .optional(),
  requirements: z
    .object({
      network: z.boolean().optional(),
      privileged: z.boolean().optional(),
      privileged_reason: z.string().optional(),
    })
    .optional(),
  methods: z.record(z.string(), z.object({
    description: z.string(),
    when_to_use: z.string().optional(),
    params: z.record(z.string(), z.any()).optional(),
    returns: z.record(z.string(), z.any()).optional(),
  })).optional(),
})

const RegistrySchema = z.object({
  version: z.string(),
  updated_at: z.string().optional(),
  tools: z.record(z.string(), RegistryToolSchema),
})

type Registry = z.infer<typeof RegistrySchema>
type RegistryTool = z.infer<typeof RegistryToolSchema>

// Registry fetching functions
async function ensureCacheDir(): Promise<void> {
  try {
    await fs.mkdir(REGISTRY_CONFIG.CACHE_DIR, { recursive: true })
  } catch {
    // Directory may already exist
  }
}

async function getCacheTimestamp(): Promise<number | null> {
  try {
    const stats = await fs.stat(REGISTRY_CONFIG.CACHE_PATH)
    return stats.mtime.getTime()
  } catch {
    return null
  }
}

function isCacheStale(timestamp: number): boolean {
  return Date.now() - timestamp > REGISTRY_CONFIG.CACHE_TTL_MS
}

async function loadCacheFromDisk(): Promise<Registry | null> {
  try {
    const text = await fs.readFile(REGISTRY_CONFIG.CACHE_PATH, "utf-8")
    const parsed = yaml.load(text)
    return RegistrySchema.parse(parsed)
  } catch {
    return null
  }
}

async function fetchRemoteRegistry(): Promise<Registry | null> {
  try {
    const response = await fetch(REGISTRY_CONFIG.REMOTE_URL, {
      headers: { "User-Agent": "opensploit-cli" },
      signal: AbortSignal.timeout(30000),
    })

    if (!response.ok) {
      return null
    }

    const text = await response.text()
    const parsed = yaml.load(text)
    const validated = RegistrySchema.parse(parsed)

    // Save to disk cache
    await ensureCacheDir()
    await fs.writeFile(REGISTRY_CONFIG.CACHE_PATH, text, "utf-8")

    return validated
  } catch {
    return null
  }
}

interface GetRegistryResult {
  registry: Registry
  cacheStatus: "fresh" | "stale" | "new"
}

async function getRegistry(): Promise<GetRegistryResult> {
  const cacheTimestamp = await getCacheTimestamp()
  const diskCache = cacheTimestamp ? await loadCacheFromDisk() : null

  // If disk cache is fresh, use it
  if (diskCache && cacheTimestamp && !isCacheStale(cacheTimestamp)) {
    return { registry: diskCache, cacheStatus: "fresh" }
  }

  // Try to fetch from remote
  const remote = await fetchRemoteRegistry()
  if (remote) {
    return { registry: remote, cacheStatus: "new" }
  }

  // Fall back to stale disk cache
  if (diskCache) {
    return { registry: diskCache, cacheStatus: "stale" }
  }

  throw new Error("Registry unavailable. Check network connection and try again.")
}

// Search functions
function buildSearchText(tool: RegistryTool): string {
  const parts: string[] = [
    tool.name,
    tool.description,
    ...(tool.capabilities || []),
    ...(tool.routing?.use_for || []),
    ...(tool.routing?.triggers || []),
  ]

  if (tool.methods) {
    for (const [methodName, method] of Object.entries(tool.methods)) {
      parts.push(methodName)
      parts.push(method.description)
      if (method.when_to_use) {
        parts.push(method.when_to_use)
      }
    }
  }

  return parts.join(" ").toLowerCase()
}

function countKeywordMatches(query: string, searchText: string): number {
  const queryWords = query.toLowerCase().split(/\s+/).filter((w) => w.length > 1)
  let score = 0

  for (const word of queryWords) {
    const regex = new RegExp(`\\b${word}\\b`, "g")
    const exactMatches = (searchText.match(regex) || []).length
    score += exactMatches * 3

    if (searchText.includes(word)) {
      score += 1
    }
  }

  if (searchText.includes(query.toLowerCase())) {
    score += 5
  }

  return score
}

interface SearchResult {
  toolId: string
  tool: RegistryTool
  score: number
}

function searchTools(registry: Registry, query: string, phase?: string, capability?: string, limit: number = 5): SearchResult[] {
  const results: SearchResult[] = []

  for (const [toolId, tool] of Object.entries(registry.tools)) {
    if (phase && !tool.phases?.includes(phase)) {
      continue
    }
    if (capability && !tool.capabilities?.includes(capability)) {
      continue
    }

    const searchText = buildSearchText(tool)
    const score = countKeywordMatches(query, searchText)

    if (score > 0) {
      results.push({ toolId, tool, score })
    }
  }

  results.sort((a, b) => b.score - a.score)
  return results.slice(0, limit)
}

// Main tools command
export const ToolsCommand = cmd({
  command: "tools",
  describe: "manage security tool registry",
  builder: (yargs: Argv) =>
    yargs
      .command(ToolsListCommand)
      .command(ToolsSearchCommand)
      .command(ToolsInfoCommand)
      .command(ToolsUpdateCommand)
      .option("verbose", {
        describe: "show detailed output",
        type: "boolean",
        alias: "v",
      })
      .demandCommand(0),
  async handler(args) {
    // Default behavior when no subcommand: list tools
    if (!args._.includes("list") && !args._.includes("search") && !args._.includes("info") && !args._.includes("update")) {
      await listTools(args.verbose as boolean | undefined)
    }
  },
})

// List command
const ToolsListCommand = cmd({
  command: "list",
  aliases: ["ls"],
  describe: "list all available security tools",
  builder: (yargs: Argv) =>
    yargs
      .option("verbose", {
        describe: "show detailed output",
        type: "boolean",
        alias: "v",
      })
      .option("phase", {
        describe: "filter by phase",
        type: "string",
        choices: VALID_PHASES,
      }),
  async handler(args) {
    await listTools(args.verbose, args.phase as string | undefined)
  },
})

async function listTools(verbose?: boolean, phase?: string) {
  UI.empty()
  prompts.intro("Security Tool Registry")

  const spinner = prompts.spinner()
  spinner.start("Loading registry...")

  try {
    const { registry, cacheStatus } = await getRegistry()
    spinner.stop(`Registry loaded (${cacheStatus})`)

    const tools = Object.entries(registry.tools)
      .filter(([_, tool]) => !phase || tool.phases?.includes(phase))
      .sort(([a], [b]) => a.localeCompare(b))

    if (tools.length === 0) {
      prompts.log.warn("No tools found")
      prompts.outro("Done")
      return
    }

    for (const [toolId, tool] of tools) {
      const phases = tool.phases?.join(", ") || "any"
      const capabilities = tool.capabilities?.slice(0, 3).join(", ") || "general"

      if (verbose) {
        prompts.log.info(
          `${UI.Style.TEXT_HIGHLIGHT_BOLD}${toolId}${UI.Style.TEXT_NORMAL}` +
          `\n    ${tool.description}` +
          `\n    ${UI.Style.TEXT_DIM}Phases: ${phases}${UI.Style.TEXT_NORMAL}` +
          `\n    ${UI.Style.TEXT_DIM}Capabilities: ${capabilities}${UI.Style.TEXT_NORMAL}`
        )
      } else {
        prompts.log.info(`${toolId} ${UI.Style.TEXT_DIM}- ${tool.description.substring(0, 60)}${tool.description.length > 60 ? "..." : ""}${UI.Style.TEXT_NORMAL}`)
      }
    }

    prompts.outro(`${tools.length} tool(s) available`)
  } catch (error) {
    spinner.stop("Failed to load registry", 1)
    prompts.log.error(error instanceof Error ? error.message : String(error))
    prompts.outro("Done")
  }
}

// Search command
const ToolsSearchCommand = cmd({
  command: "search <query>",
  describe: "search for security tools",
  builder: (yargs: Argv) =>
    yargs
      .positional("query", {
        describe: "search query",
        type: "string",
        demandOption: true,
      })
      .option("phase", {
        describe: "filter by phase",
        type: "string",
        choices: VALID_PHASES,
      })
      .option("capability", {
        describe: "filter by capability",
        type: "string",
      })
      .option("limit", {
        describe: "maximum results",
        type: "number",
        default: 5,
      }),
  async handler(args) {
    UI.empty()
    prompts.intro(`Search: "${args.query}"`)

    const spinner = prompts.spinner()
    spinner.start("Searching...")

    try {
      const { registry, cacheStatus } = await getRegistry()
      const results = searchTools(registry, args.query as string, args.phase as string | undefined, args.capability as string | undefined, args.limit as number)

      if (results.length === 0) {
        spinner.stop("No results")
        prompts.log.warn("No tools found matching your query")
        prompts.log.info(`Valid phases: ${VALID_PHASES.join(", ")}`)
        prompts.outro("Try different keywords")
        return
      }

      spinner.stop(`${results.length} result(s)`)

      for (const { toolId, tool, score } of results) {
        const phases = tool.phases?.join(", ") || "any"

        prompts.log.info(
          `${UI.Style.TEXT_HIGHLIGHT_BOLD}${toolId}${UI.Style.TEXT_NORMAL} ${UI.Style.TEXT_DIM}(score: ${score})${UI.Style.TEXT_NORMAL}` +
          `\n    ${tool.description}` +
          `\n    ${UI.Style.TEXT_DIM}Phases: ${phases}${UI.Style.TEXT_NORMAL}`
        )

        if (tool.routing?.use_for?.length) {
          prompts.log.info(`    ${UI.Style.TEXT_DIM}Use for: ${tool.routing.use_for.slice(0, 3).join(", ")}${UI.Style.TEXT_NORMAL}`)
        }

        if (tool.methods) {
          const methodNames = Object.keys(tool.methods).slice(0, 3)
          prompts.log.info(`    ${UI.Style.TEXT_DIM}Methods: ${methodNames.join(", ")}${UI.Style.TEXT_NORMAL}`)
        }
      }

      prompts.outro(`Registry version: ${registry.version}`)
    } catch (error) {
      spinner.stop("Search failed", 1)
      prompts.log.error(error instanceof Error ? error.message : String(error))
      prompts.outro("Done")
    }
  },
})

// Info command
const ToolsInfoCommand = cmd({
  command: "info <tool>",
  describe: "show detailed information about a tool",
  builder: (yargs: Argv) =>
    yargs.positional("tool", {
      describe: "tool ID",
      type: "string",
      demandOption: true,
    }),
  async handler(args) {
    UI.empty()

    const spinner = prompts.spinner()
    spinner.start("Loading...")

    try {
      const { registry } = await getRegistry()
      const tool = registry.tools[args.tool as string]

      if (!tool) {
        spinner.stop("Not found", 1)
        prompts.log.error(`Tool not found: ${args.tool}`)
        prompts.log.info("Use 'opencode tools list' to see available tools")
        prompts.outro("Done")
        return
      }

      spinner.stop(`${tool.name}`)
      prompts.intro(`Tool: ${args.tool}`)

      prompts.log.info(`${UI.Style.TEXT_NORMAL_BOLD}Description:${UI.Style.TEXT_NORMAL} ${tool.description}`)

      if (tool.version) {
        prompts.log.info(`${UI.Style.TEXT_NORMAL_BOLD}Version:${UI.Style.TEXT_NORMAL} ${tool.version}`)
      }

      if (tool.image) {
        prompts.log.info(`${UI.Style.TEXT_NORMAL_BOLD}Image:${UI.Style.TEXT_NORMAL} ${tool.image}`)
      }

      prompts.log.info(`${UI.Style.TEXT_NORMAL_BOLD}Phases:${UI.Style.TEXT_NORMAL} ${tool.phases?.join(", ") || "any"}`)
      prompts.log.info(`${UI.Style.TEXT_NORMAL_BOLD}Capabilities:${UI.Style.TEXT_NORMAL} ${tool.capabilities?.join(", ") || "general"}`)

      if (tool.requirements) {
        const reqs: string[] = []
        if (tool.requirements.network) reqs.push("network")
        if (tool.requirements.privileged) {
          reqs.push(`privileged${tool.requirements.privileged_reason ? ` (${tool.requirements.privileged_reason})` : ""}`)
        }
        if (reqs.length > 0) {
          prompts.log.info(`${UI.Style.TEXT_NORMAL_BOLD}Requirements:${UI.Style.TEXT_NORMAL} ${reqs.join(", ")}`)
        }
      }

      if (tool.routing?.use_for?.length) {
        prompts.log.info(`${UI.Style.TEXT_NORMAL_BOLD}Use for:${UI.Style.TEXT_NORMAL} ${tool.routing.use_for.join(", ")}`)
      }

      if (tool.routing?.never_use_for?.length) {
        const neverUse = tool.routing.never_use_for.map(n => typeof n === "string" ? n : n.task)
        prompts.log.warn(`${UI.Style.TEXT_NORMAL_BOLD}Never use for:${UI.Style.TEXT_NORMAL} ${neverUse.join(", ")}`)
      }

      if (tool.methods) {
        prompts.log.info(`\n${UI.Style.TEXT_NORMAL_BOLD}Methods:${UI.Style.TEXT_NORMAL}`)
        for (const [methodName, method] of Object.entries(tool.methods)) {
          prompts.log.info(`  ${UI.Style.TEXT_HIGHLIGHT}${methodName}${UI.Style.TEXT_NORMAL}`)
          prompts.log.info(`    ${method.description}`)
          if (method.when_to_use) {
            prompts.log.info(`    ${UI.Style.TEXT_DIM}When: ${method.when_to_use}${UI.Style.TEXT_NORMAL}`)
          }
          if (method.params) {
            const params = Object.entries(method.params)
              .map(([name, info]: [string, any]) => `${name}${info.required ? "*" : ""}`)
              .join(", ")
            prompts.log.info(`    ${UI.Style.TEXT_DIM}Params: ${params}${UI.Style.TEXT_NORMAL}`)
          }
        }
      }

      prompts.outro("Done")
    } catch (error) {
      spinner.stop("Failed", 1)
      prompts.log.error(error instanceof Error ? error.message : String(error))
      prompts.outro("Done")
    }
  },
})

// Update command
const ToolsUpdateCommand = cmd({
  command: "update",
  aliases: ["refresh"],
  describe: "force refresh the tool registry",
  async handler() {
    UI.empty()
    prompts.intro("Update Tool Registry")

    const spinner = prompts.spinner()
    spinner.start("Fetching from opensploit.ai...")

    try {
      // Force fetch from remote
      const registry = await fetchRemoteRegistry()

      if (registry) {
        spinner.stop("Registry updated")
        prompts.log.success(`Updated to version ${registry.version}`)
        prompts.log.info(`${Object.keys(registry.tools).length} tools available`)
      } else {
        spinner.stop("Update failed", 1)
        prompts.log.error("Failed to fetch registry from remote")
        prompts.log.info("Check your network connection")
      }

      prompts.outro("Done")
    } catch (error) {
      spinner.stop("Update failed", 1)
      prompts.log.error(error instanceof Error ? error.message : String(error))
      prompts.outro("Done")
    }
  },
})
