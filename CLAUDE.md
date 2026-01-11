# CLAUDE.md

This file provides context for Claude to work effectively on the OpenSploit codebase.

## Project Overview

**OpenSploit** is an autonomous penetration testing platform that orchestrates security tools via the Model Context Protocol (MCP). It is forked from OpenCode (an AI coding assistant) and repurposed for offensive security.

- **Domain**: opensploit.ai
- **Architecture**: Local-first, provider-agnostic AI agent
- **Requirements**: See `OpenSploit Technical Requirements Document.md` for complete specifications

## Key Concepts (Concise Reference)

### Security Phases
The agent operates in phases: **Reconnaissance** → **Enumeration** → **Exploitation** → **Post-Exploitation** → **Reporting**

### Agent Model (Hybrid)
- **Master agent** understands security phases and methodology
- **Sub-agents** are spawned for specific tasks within each phase (e.g., port scanning, web fuzzing, SQL injection testing)
- Sub-agents are task-specific, not phase-specific
- Master orchestrates which sub-agents to spawn based on current phase and findings

### Tool Orchestration
- Security tools (nmap, sqlmap, ffuf, etc.) run as MCP servers in Docker containers
- MCP servers are maintained in `silicon-works/mcp-tools` (local: `../mcp-tools`, GitHub: https://github.com/silicon-works/mcp-tools)
- This repo contains the agent that consumes those tools via Tool Registry Search (RAG)

### Tool Registry RAG System
Agents discover tools via the **Tool Registry Search** tool (RAG-based):
- Agents query by natural language, phase, or capability
- RAG ranking combines: semantic similarity (40%) + selection level (40%) + phase match (20%)
- **Selection Hierarchy**: Skills (Level 1) → Specialized (Level 2) → General-purpose (Level 3)
- Registry cached locally at `~/.opensploit/registry.yaml`, fetched from opensploit.ai

## Repository Structure

Monorepo using Bun workspaces + Turbo:

```
packages/
├── opensploit/   # Core agent, CLI, server, tools (MAIN PACKAGE)
├── console/      # Web dashboard (may be moved/replaced)
├── desktop/      # Desktop client (SolidJS)
├── tauri/        # Cross-platform desktop app
├── web/          # Documentation site (Astro)
├── sdk/          # TypeScript SDK
├── ui/           # Shared UI components
├── plugin/       # Plugin system interface
├── util/         # Shared utilities
├── enterprise/   # Self-hosted enterprise version
├── function/     # Serverless functions
├── slack/        # Slack integration
├── script/       # Build scripts
└── docs/         # Documentation content
```

**Note**: Package retention is under review. Do not remove packages without explicit approval.

## MCP Tools Repository (`silicon-works/mcp-tools`)

The external mcp-tools repository contains all MCP tool servers:

```
mcp-tools/
├── registry.yaml              # Tool registry (source of truth)
├── packages/
│   └── mcp-common/            # Shared Python package (BaseMCPServer, ToolResult)
└── tools/
    ├── nmap/                  # Network scanner
    ├── ffuf/                  # Web fuzzer
    ├── curl/                  # HTTP client with RCE injection
    ├── ssh/                   # Remote shell and file transfer
    ├── netcat/                # Reverse shell listener
    ├── sqlmap/                # SQL injection
    ├── hydra/                 # Password brute-force
    ├── nuclei/                # Vulnerability scanner
    ├── nikto/                 # Web server scanner
    ├── metasploit/            # Exploitation framework
    ├── mysql/                 # MySQL client
    ├── payload/               # Binary compilation, shells
    ├── privesc/               # Privilege escalation enumeration
    ├── tunnel/                # SSH tunneling and SOCKS proxy
    ├── web-fingerprint/       # Web technology detection
    ├── cve-lookup/            # CVE research via NVD API
    ├── web-session/           # Authenticated session management
    ├── exploit-runner/        # Run exploit scripts
    └── ...                    # 25+ tools total
```

## Core Package Structure (`packages/opensploit/`)

```
src/
├── agent/           # Agent definitions and prompts
│   ├── agent.ts     # Agent registry (build, plan, explore, etc.)
│   └── prompt/      # System prompts for each agent
├── cli/             # CLI with yargs
│   └── cmd/
│       ├── run.ts   # Main execution
│       └── tui/     # Terminal UI (SolidJS + OpenTUI)
├── server/          # Hono HTTP server
│   └── server.ts    # API routes (~80KB)
├── session/         # Session management
│   ├── prompt.ts    # System prompt builder
│   ├── processor.ts # Tool result processing
│   └── message*.ts  # Message schemas
├── tool/            # Built-in tools
│   ├── bash.ts      # Shell execution
│   ├── read.ts      # File reading
│   ├── edit.ts      # File editing
│   ├── task.ts      # Sub-agent spawning
│   └── ...          # glob, grep, lsp, web*, etc.
├── provider/        # LLM provider abstraction
│   └── provider.ts  # 75+ providers supported
├── mcp/             # MCP client integration
├── config/          # Configuration system
├── permission/      # Permission/security model
├── storage/         # Data persistence
├── file/            # File operations
└── lsp/             # Language Server Protocol
```

## Agent System

### Existing Agents (in `agent.ts`)

| Agent | Type | Purpose |
|-------|------|---------|
| `build` | Primary | Full tool access, default agent |
| `plan` | Primary | Read-only, code exploration |
| `general` | Subagent | Multi-step task orchestration |
| `explore` | Subagent | Fast codebase exploration |
| `compaction` | Hidden | Conversation compression |
| `title` | Hidden | Session title generation |
| `summary` | Hidden | Session summarization |

### Creating New Agents

Agents are defined in `packages/opensploit/src/agent/agent.ts`:

```typescript
{
  name: "agent-name",
  type: "subagent",           // or "primary"
  description: "What this agent does",
  model: "claude-sonnet-4-20250514",  // optional override
  tools: {
    toolName: true/false,     // enable/disable tools
  },
  permission: {
    edit: "allow" | "deny" | "ask",
    bash: { "command:*": "allow" | "deny" | "ask" },
  },
  prompt: CUSTOM_PROMPT,      // system prompt
  temperature: 0.7,           // optional
}
```

### Sub-Agent Spawning

The `task.ts` tool spawns sub-agents. Pattern:

```typescript
// From master agent, spawn a sub-agent for specific task
tools/call: task
arguments: {
  agent: "explore",
  message: "Find all authentication endpoints"
}
```

For OpenSploit: Master agent spawns task-specific sub-agents based on phase needs.

## Tech Stack

- **Runtime**: Bun 1.3.5+
- **Language**: TypeScript (ESM)
- **Build**: Turbo monorepo, Vite
- **Server**: Hono
- **UI**: SolidJS, OpenTUI (terminal), Kobalte
- **LLM**: Vercel AI SDK (multi-provider)
- **Protocol**: MCP 1.15.1
- **Storage**: SQLite (sessions), ChromaDB (patterns - planned)

## Development Commands

```bash
bun install              # Install dependencies
bun dev                  # Run CLI in dev mode
bun typecheck            # Type check all packages
bun turbo build          # Build all packages
bun test                 # Run tests (packages/opensploit)
```

From `packages/opensploit/`:
```bash
bun run script/build.ts  # Custom build
bun dev                  # Run locally
```

## Commit Rules

1. **One sentence commit messages** - concise and descriptive
2. **No "Co-Authored-By: Claude"** - do not include this line
3. **Do not commit**:
   - `OpenSploit Technical Requirements Document.md`
   - `CLAUDE.md`
4. **Examples**:
   - `fix: correct MCP client connection timeout handling`
   - `feat: add Tool Registry Search RAG implementation`
   - `refactor: simplify agent spawning logic`

## Naming Transition

The codebase is being renamed from "opencode" to "opensploit":

| Current | Target |
|---------|--------|
| `opencode` | `opensploit` |
| `~/.opencode/` | `~/.opensploit/` |
| `~/.config/opencode/` | `~/.config/opensploit/` |
| `@opencode-ai/*` | `@opensploit/*` (TBD) |

Focus on patterns and architecture; specific paths will be updated.

## Guidelines

### Do
- Reference `OpenSploit Technical Requirements Document.md` for detailed specifications
- Follow the hybrid agent model (master + task-specific sub-agents)
- Extend existing patterns (agents, tools, providers)
- Consider security implications (permission model, target validation)
- Use Tool Registry Search for tool discovery (agents should not have hardcoded tool knowledge)

### Don't
- Remove packages without explicit approval
- Assume package removal - some may be kept or repurposed
- Duplicate requirements doc content here (reference it instead)
- Add security tools directly to this repo (MCP servers go in `silicon-works/mcp-tools`)

## Key Files to Understand

| File | Purpose | Size |
|------|---------|------|
| `src/agent/agent.ts` | Agent definitions | ~400 lines |
| `src/server/server.ts` | API routes | ~80KB |
| `src/session/prompt.ts` | System prompt builder | ~45KB |
| `src/config/config.ts` | Configuration system | ~37KB |
| `src/provider/provider.ts` | LLM providers | ~33KB |
| `src/tool/task.ts` | Sub-agent spawning | Key for OpenSploit |
| `src/mcp/index.ts` | MCP client | ~18KB |

## Security Considerations

OpenSploit requires additional safety measures not present in OpenCode:

- **Target validation**: Warn before scanning external/non-private IPs
- **Forbidden targets**: Block government, military, critical infrastructure
- **Consent flow**: Require explicit user confirmation for external targets
- **Audit logging**: Log all scan authorizations and tool executions
- **Privileged containers**: Prompt user approval before running containers requiring raw sockets

See requirements doc sections 9.1-9.6 for complete security requirements.
