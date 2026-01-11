
**Version:** 1.0    
**Date:** December 2025    
**Status:** Final Draft    
**Domain:** opensploit.ai
  
---  

## Table of Contents

[[#1. Executive Summary]]
[[#2. Project Overview]]
[[#3. System Architecture Requirements]]
- [[#3.2.2 Background Sub-Agent Execution]]
- [[#3.2.3 Context Injection for Sub-Agents]]
- [[#3.4.2 Session Working Directory]]
[[#4. Functional Requirements]]
- [[#4.4.1 Tool Registry RAG Implementation]]
- [[#4.6.1 Engagement Log Aggregation]]
- [[#4.9 Intelligent Tool Selection & Orchestration]]
- [[#4.10 Shell Session Management]]
- [[#4.11 Target State Tracking]]
- [[#4.12 Exploit Template System]]
- [[#4.13 Knowledge Base RAG (Future Enhancement)]]
[[#5. Non-Functional Requirements]]
[[#6. Technical Stack Requirements]]
[[#7. Integration Requirements]]
[[#8. Data Requirements]]
[[#9. Security Requirements]]
[[#10. User Interface Requirements]]
[[#11. Deployment Requirements]]
[[#12. Testing Requirements]]
[[#13. Resource Management Requirements]]
[[#14. Maintenance & Support Requirements]]
[[#15. Acceptance Criteria]]
[[#16. Agent Reasoning Architecture]]
- [[#16.6 TVAR Display in User Interface]]
[[#17. Training Data & Model Fine-Tuning]]
[[#18. Appendices]]

---  

## 1. Executive Summary

### 1.1 Purpose

This Technical Requirements Document (TRD) defines the complete technical specifications, functional requirements, and implementation guidelines for OpenSploit, a local-first autonomous penetration testing platform.

### 1.2 Scope

OpenSploit is an AI-powered security testing assistant that orchestrates penetration testing tools via the Model Context Protocol (MCP). The system runs entirely on the user's local machine, with optional cloud services for enhanced functionality.

### 1.3 Document Conventions

| Term | Meaning |  
|------|---------|  
| **SHALL** | Mandatory requirement that must be implemented |  
| **SHOULD** | Recommended requirement, implement unless justified otherwise |  
| **MAY** | Optional requirement, implement if resources permit |  
| **REQ-XXX-NNN** | Requirement identifier (Category-Subcategory-Number) |  
| **P0** | Critical priority - must have for MVP |  
| **P1** | High priority - should have for MVP |  
| **P2** | Medium priority - post-MVP |  

### 1.4 Key Stakeholders

| Stakeholder | Role | Interest |  
|-------------|------|----------|  
| Founder/Lead Developer | Primary Developer | Technical implementation, architecture |  
| Security Practitioners | Primary Users | Tool functionality, efficiency, accuracy |  
| Developers | Secondary Users | Ease of use, learning curve |  
| Students/Learners | Tertiary Users | Accessibility, educational value, cost |  
| Enterprise Teams | Future Users | Collaboration, compliance, reporting |  
  
---  

## 2. Project Overview

### 2.1 Product Vision

OpenSploit bridges the gap between complex security tools and accessible AI assistance, enabling professional penetration testing for developers, students, and security practitioners through intelligent automation.

### 2.2 Core Value Propositions

1. **Local-First Architecture**: All computation runs on user's machine, ensuring privacy and eliminating cloud costs
2. **AI Orchestration**: Intelligent tool selection and execution without requiring deep security expertise
3. **On-Demand Tools**: Tools download only when needed, minimizing initial footprint
4. **Adaptive Resources**: System adapts strategy based on available hardware
5. **Attack Memory**: Learns from successful approaches to improve over time

### 2.3 Target Platforms

| Platform | Priority | Minimum Version | Notes |  
|----------|----------|-----------------|-------|  
| Linux (Ubuntu/Debian) | P0 | Ubuntu 20.04+ | Primary development platform |  
| macOS | P0 | macOS 12+ | Full support required |  
| Windows | P1 | Windows 10+ | WSL2 required for Docker |  
| Kali Linux | P1 | 2023.x+ | Native security environment |  

### 2.4 Repository Structure

| Repository                    | Purpose                                              | Language   |  
| ----------------------------- | ---------------------------------------------------- | ---------- |  
| `silicon-works/opensploit`    | Core application (TUI + Agents + Tool Registry RAG)  | TypeScript |  
| `silicon-works/mcp-tools`     | MCP tool servers (nmap, sqlmap, etc.) + registry     | Python     |  
| `silicon-works/opensploit.ai` | Website, docs, auth, API, registry hosting           | TypeScript |  

> **Note:** Core application is TypeScript-based, forked from OpenCode. This provides immediate access to 75+ LLM providers, existing TUI infrastructure, and proven agent patterns. MCP tool servers are Python-based per MCP SDK recommendations.

> **See Section 3.7** for detailed MCP Tools Repository architecture including monorepo structure, Dockerfile patterns, and CI/CD flows.
  
---  

## 3. System Architecture Requirements

### 3.1 High-Level Architecture

```  
┌─────────────────────────────────────────────────────────────────┐  
│                         User's Machine                          │  
├─────────────────────────────────────────────────────────────────┤  
│  ┌───────────────────────────────────────────────────────────┐  │  
│  │                    opensploit (TypeScript)                │  │  
│  │                                                           │  │  
│  │  ┌─────────────────────────────────────────────────────┐  │  │  
│  │  │                        TUI                          │  │  │  
│  │  └─────────────────────────┬───────────────────────────┘  │  │  
│  │                            │                              │  │  
│  │                            ▼                              │  │  
│  │  ┌─────────────────────────────────────────────────────┐  │  │  
│  │  │            Master Pentest Agent (Primary)           │  │  │
│  │  │  - Clarifies target/scope before starting           │  │  │
│  │  │  - Plans attack methodology                         │  │  │
│  │  │  - Spawns phase subagents                           │  │  │
│  │  │  - Tracks findings in session                       │  │  │
│  │  │  - Requests approval at each significant action     │  │  │
│  │  │  - Uses MCP tools exclusively (no custom code)      │  │  │
│  │  └─────────────────────────┬───────────────────────────┘  │  │  
│  │                            │                              │  │  
│  │            ┌───────────────┼───────────────┐              │  │  
│  │            ▼               ▼               ▼              │  │  
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐       │  │  
│  │  │    Recon     │ │    Enum      │ │   Exploit    │  ...  │  │  
│  │  │   Subagent   │ │   Subagent   │ │   Subagent   │       │  │  
│  │  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘       │  │  
│  │         │                │                │               │  │  
│  │         └────────────────┼────────────────┘               │  │  
│  │                          ▼                                │  │  
│  │  ┌─────────────────────────────────────────────────────┐  │  │  
│  │  │          Tool Registry Search (RAG Tool)            │  │  │  
│  │  │  - Invoked by ANY agent before using MCP tools      │  │  │  
│  │  │  - Searches registry by query, phase, capability    │  │  │  
│  │  │  - Returns relevant tools + MCP server + methods    │  │  │  
│  │  └─────────────────────────┬───────────────────────────┘  │  │  
│  │                            │                              │  │  
│  │                            ▼                              │  │  
│  │  ┌─────────────────────────────────────────────────────┐  │  │  
│  │  │              Tool Registry (Cached)                 │  │  │  
│  │  │         ~/.opensploit/registry.yaml                 │  │  │  
│  │  │      (fetched from external source)                 │  │  │  
│  │  └─────────────────────────────────────────────────────┘  │  │  
│  │                                                           │  │  
│  │  ┌─────────────────────────────────────────────────────┐  │  │  
│  │  │                  Session Storage                    │  │  │  
│  │  │  ┌─────────────┐  ┌─────────────────────────────┐   │  │  │  
│  │  │  │   SQLite    │  │   Pattern Memory (Future)   │   │  │  │  
│  │  │  │  sessions,  │  │   Cloud-based (S3)          │   │  │  │  
│  │  │  │  findings,  │  │   Deferred to later phase   │   │  │  │  
│  │  │  │  action_log │  │                             │   │  │  │  
│  │  │  └─────────────┘  └─────────────────────────────┘   │  │  │  
│  │  └─────────────────────────────────────────────────────┘  │  │  
│  └───────────────────────────────────────────────────────────┘  │  
│                              │ stdio (MCP)                      │  
│                              ▼                                  │  
│  ┌───────────────────────────────────────────────────────────┐  │  
│  │                     Docker Engine                         │  │  
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐       │  │  
│  │  │  nmap   │  │ sqlmap  │  │gobuster │  │  etc... │       │  │  
│  │  │   MCP   │  │   MCP   │  │   MCP   │  │         │       │  │  
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘       │  │  
│  │              (Future - mcp-tools repo)                    │  │  
│  └───────────────────────────────────────────────────────────┘  │  
│                                                                 │  
│  ┌───────────────────────────────────────────────────────────┐  │  
│  │                     LLM Provider                          │  │  
│  │     Ollama (local) │ Claude API │ OpenAI │ Bedrock        │  │  
│  └───────────────────────────────────────────────────────────┘  │  
└─────────────────────────────────────────────────────────────────┘  
```  

### 3.2 Core Agent Layer

| Req ID      | Requirement                                                           | Priority |  
| ----------- | --------------------------------------------------------------------- | -------- |  
| REQ-ARC-001 | System SHALL implement agent loop based on OpenCode fork              | P0       |  
| REQ-ARC-002 | Agent SHALL support phase-based pentesting methodology                | P0       |  
| REQ-ARC-003 | Agent SHALL maintain conversation context across tool invocations     | P0       |  
| REQ-ARC-004 | Agent SHALL support sub-agent spawning for specialized tasks          | P0       |  
| REQ-ARC-005 | Agent SHALL implement planning capabilities for complex attack chains | P1       |  
| REQ-ARC-006 | System SHALL implement a Master Pentest Agent as the primary orchestrator | P0   |  
| REQ-ARC-007 | Master Agent SHALL spawn phase-specific subagents (recon, enum, exploit, post-exploit, report) | P0 |  
| REQ-ARC-008 | All agents (master and subagents) SHALL have access to Tool Registry Search tool | P0 |  
| REQ-ARC-009 | Agents SHALL query Tool Registry Search before invoking any MCP tool | P0 |  
| REQ-ARC-010-A | Master Agent SHALL clarify target/scope with user before starting pentest | P0 |
| REQ-ARC-011-A | Master Agent SHALL use MCP tools (searchsploit, exploit-runner, metasploit) for exploitation rather than writing custom exploit code | P0 |
| REQ-ARC-012-A | Users SHALL be able to invoke individual phase subagents directly (e.g., "just do recon") | P1 |
| REQ-ARC-013 | Subagents SHALL be able to spawn their own subagents for focused sub-tasks (recursive delegation) | P0 |
| REQ-ARC-014 | Agents SHALL use delegation to prevent context rot during long engagements | P0 |
| REQ-ARC-015-A | Parent agents SHALL summarize subagent results rather than copying full output to their context | P0 |
| REQ-ARC-016-A | The `general` subagent SHALL serve as a flexible workhorse for ad-hoc multi-step tasks | P0 |

#### 3.2.1 Recursive Delegation Model

Long penetration testing engagements generate significant context (tool outputs, findings, conversation history). Without management, this leads to "context rot" where the LLM loses track of earlier information as the context window fills.

**Solution: Hierarchical Delegation**

```
Master Agent (Manager)
├── Maintains high-level strategy and findings summary
├── Spawns phase subagents for major work chunks
│
├── pentest/recon (Middle Manager)
│   ├── Focuses on reconnaissance tasks
│   ├── Spawns general subagents for specific sub-tasks
│   │   ├── "Fingerprint web server at 10.10.10.1:80"
│   │   └── "Enumerate SMB shares on 10.10.10.1"
│   └── Returns summarized findings (not raw tool output)
│
├── pentest/enum (Middle Manager)
│   ├── Spawns subagents for service-specific enumeration
│   └── Returns summarized findings
│
└── ... continues through phases
```

**Key Principles:**

1. **Context Isolation**: Each subagent starts with focused context for its specific task
2. **Summarization**: Parents receive summaries, not raw output, preventing context bloat
3. **Flexible Depth**: Agents decide when to delegate based on task complexity
4. **Reusability**: The `general` agent handles any ad-hoc task that doesn't fit a specialized agent

**When to Delegate:**

- Task will generate significant output (scans, enumerations)
- Task is independent and can run in isolation
- Multiple tasks can run in parallel
- Specialized focus is needed

#### 3.2.2 Background Sub-Agent Execution

Sub-agents SHALL run as background tasks that report to the parent session, rather than as independent interactive sessions that users must manually switch between.

```
┌─────────────────────────────────────────────────────────────────┐
│                      Parent Session (Interactive)               │
│                                                                 │
│  User sees:                                                     │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │ [Pending Approvals]                                        │ │
│  │  • recon: Run nmap full port scan? [y/n]                  │ │
│  │  • enum: Start ffuf directory brute? [y/n]                │ │
│  │                                                            │ │
│  │ [Active Sub-agents]                                        │ │
│  │  ○ pentest/recon - scanning ports... (45s)                │ │
│  │  ○ pentest/enum - waiting for approval                    │ │
│  │  ● pentest/exploit - idle                                 │ │
│  │                                                            │ │
│  │ [Results]                                                  │ │
│  │  ▸ Recon complete: Found 22/tcp, 80/tcp, 443/tcp         │ │
│  └───────────────────────────────────────────────────────────┘ │
│                                                                 │
│  Background (user does NOT switch to these):                    │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐                        │
│  │  recon  │  │  enum   │  │ exploit │                        │
│  │ session │  │ session │  │ session │                        │
│  └─────────┘  └─────────┘  └─────────┘                        │
└─────────────────────────────────────────────────────────────────┘
```

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| REQ-AGT-001 | Sub-agents SHALL run as background tasks, not interactive sessions | P0 |
| REQ-AGT-002 | Sub-agent sessions SHALL be hidden from session list (background flag) | P0 |
| REQ-AGT-003 | Sub-agent results SHALL be displayed inline in parent session | P0 |
| REQ-AGT-004 | Permission requests from sub-agents SHALL bubble to root session | P0 |
| REQ-AGT-005 | Parent session SHALL show unified approval queue for all sub-agents | P0 |
| REQ-AGT-006 | Sub-agent progress SHALL be visible in parent session while running | P1 |

#### 3.2.3 Context Injection for Sub-Agents

Sub-agents SHALL receive engagement state context when spawned, preventing redundant discovery of information already found by other agents.

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| REQ-AGT-010 | Sub-agents SHALL receive current engagement state context at spawn | P0 |
| REQ-AGT-011 | Engagement state SHALL include target info, discovered ports, credentials, vulnerabilities | P0 |
| REQ-AGT-012 | Sub-agents SHALL write discoveries to shared state file | P1 |
| REQ-AGT-013 | Context injection SHALL include session working directory path | P0 |

### 3.3 Tool Management Layer

| Req ID      | Requirement                                                         | Priority |  
| ----------- | ------------------------------------------------------------------- | -------- |  
| REQ-ARC-015 | System SHALL implement MCP client for tool communication            | P0       |  
| REQ-ARC-016 | System SHALL support on-demand Docker image pulling                 | P0       |  
| REQ-ARC-017 | System SHALL maintain tool registry with capability metadata        | P0       |  
| REQ-ARC-018 | System SHALL implement container lifecycle management               | P0       |  
| REQ-ARC-019 | System SHALL support parallel tool execution based on resource tier | P1       |  

### 3.4 Memory Layer

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-ARC-020 | System SHALL implement SQLite for session and finding storage | P0 |
| REQ-ARC-021 | System SHALL implement cloud-based pattern storage (S3) for attack patterns | P2 |
| REQ-ARC-022 | System SHALL support context window management for LLM interactions | P0 |
| REQ-ARC-023 | System SHALL support cloud pattern synchronization for shared learning | P2 |

> **Note:** Pattern memory (attack patterns RAG) is deferred to a later phase. Initial implementation focuses on SQLite for session/findings storage. Pattern storage will be cloud-based (S3 or similar) to enable shared learning across users.

#### 3.4.1 Tool Output Management (Output Store Pattern)

Security tools often produce large outputs (port scans, enumeration results, exploit attempts) that can overflow LLM context windows. This is distinct from agent-to-agent delegation (Section 3.2.1) - the Output Store handles within-agent tool output size.

**Problem:** A single nmap scan can produce 100KB+ of output (~25,000 tokens). Placing this directly in context:
- Consumes significant context budget
- Causes context overflow on smaller models (e.g., 128K context Grok hit 387K tokens after recon)
- Dilutes important findings with raw data

**Solution: External Output Storage with Summarization**

```
┌─────────────────────────────────────────────────────────────┐
│                    Agent Context                            │
│                                                             │
│  1. Agent calls mcp_tool (e.g., nmap.port_scan)            │
│                     │                                       │
│                     ▼                                       │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Output Store                            │   │
│  │  - Check: output > 5000 chars (~1250 tokens)?       │   │
│  │  - If yes: store in ~/.opensploit/outputs/{session} │   │
│  │  - Return: summary + reference ID                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                     │                                       │
│                     ▼                                       │
│  2. Agent receives summary (first 20 lines, last 10 lines) │
│     + reference ID for full retrieval                      │
│                                                             │
│  3. If agent needs details: call read_tool_output          │
│     with reference ID, optional line range, or search      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| REQ-ARC-024 | System SHALL store tool outputs exceeding threshold externally | P0 |
| REQ-ARC-025 | System SHALL return summaries with reference IDs for large outputs | P0 |
| REQ-ARC-026 | System SHALL provide retrieval tool for accessing stored outputs | P0 |
| REQ-ARC-027 | Retrieval tool SHALL support line ranges, search, and size limits | P0 |
| REQ-ARC-028 | Stored outputs SHALL be associated with sessions | P0 |
| REQ-ARC-029 | System SHALL clean up old outputs (default: 24 hours) | P1 |
| REQ-ARC-029a | System SHOULD parse tool outputs into structured records for RAG search | P1 |
| REQ-ARC-029b | Structured indexing SHOULD support tool-specific parsers (ffuf, nmap, nikto, gobuster) | P1 |
| REQ-ARC-029c | Search SHOULD support field-based queries (e.g., `status:200`, `port:22`) | P1 |

**Output Store Thresholds:**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Store threshold | 5000 chars | ~1250 tokens, leaves context for conversation |
| Summary preview | First 20 lines | Enough to understand output structure |
| Summary tail | Last 10 lines | Capture final status/summary |
| Max preview chars | 2000 | Prevent summary itself from being too large |

**File Storage:**

```
~/.opensploit/outputs/
├── {session-id}/
│   ├── {output-id}.txt         # Full raw output
│   ├── {output-id}.meta.json   # Metadata (tool, method, size, timestamp)
│   └── ...
└── ...

~/.opensploit/output-index/
├── {session-id}/
│   ├── {output-id}.ndjson      # Parsed records (newline-delimited JSON)
│   ├── {output-id}.index.json  # Index metadata (record count, types)
│   └── ...
└── ...
```

**Relationship to Recursive Delegation:**

| Mechanism | Purpose | Scope |
|-----------|---------|-------|
| Recursive Delegation | Context isolation between agents | Agent-to-agent |
| Output Store | Prevent single tool from overflowing context | Tool-to-agent |

Both mechanisms work together: a subagent may use Output Store for individual tool calls, then summarize findings when returning to parent.

#### 3.4.2 Session Working Directory

Each engagement SHALL have a dedicated temporary directory for storing documents, findings, and artifacts. This ensures sub-agents write to a centralized location rather than scattered files.

```
/tmp/opensploit-session-{session-id}/
├── state.yaml              # Engagement state (target, ports, creds, vulns)
├── findings/
│   ├── recon.md            # Reconnaissance findings
│   ├── enum.md             # Enumeration findings
│   └── exploit.md          # Exploitation findings
└── artifacts/
    ├── screenshots/        # Screenshot evidence
    └── loot/               # Captured files, credentials
```

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| REQ-SES-001 | System SHALL create session-scoped temp directory at parent session start | P0 |
| REQ-SES-002 | Session temp directory SHALL be in OS temp location for automatic cleanup | P0 |
| REQ-SES-003 | Sub-agents SHALL share the root session's temp directory | P0 |
| REQ-SES-004 | Session temp directory SHALL have standard structure (findings/, artifacts/) | P1 |
| REQ-SES-005 | Session temp directory SHALL be cleaned up when session is deleted | P0 |

### 3.5 LLM Integration Layer

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-ARC-030 | System SHALL inherit OpenCode's LLM provider system (75+ providers) | P0 |  
| REQ-ARC-031 | System SHALL support local LLM via Ollama | P0 |  
| REQ-ARC-032 | System SHALL support Claude, OpenAI, and other major API providers | P0 |  
| REQ-ARC-033 | System SHALL implement auth management via CLI | P0 |  

### 3.6 Component Dependencies

| Component | Depends On | Communication |  
|-----------|------------|---------------|  
| TUI | Agent, Registry | Direct function calls |  
| Agent | MCP Client, Memory, LLM Provider | Direct function calls |  
| MCP Client | Docker Client | stdio (JSON-RPC 2.0) |  
| Docker Client | Docker Engine | Docker SDK |  
| Memory | SQLite, ChromaDB | Library calls |  
| Tool Containers | Docker Engine | Container runtime |  

### 3.7 MCP Tools Repository Architecture

The `mcp-tools` repository is a monorepo containing all MCP tool servers and the tool registry.

#### 3.7.1 Repository Structure

```  
mcp-tools/  
├── registry.yaml                    # Source of truth for tool registry  
├── tools/  
│   ├── nmap/  
│   │   ├── Dockerfile               # kalilinux/kali-rolling based  
│   │   ├── mcp-server.py            # MCP server implementation  
│   │   ├── requirements.txt  
│   │   └── README.md  
│   ├── sqlmap/  
│   │   ├── Dockerfile  
│   │   ├── mcp-server.py  
│   │   └── ...  
│   ├── gobuster/  
│   │   └── ...  
│   └── [additional tools]/  
├── packages/  
│   └── mcp-common/                  # Shared MCP utilities (Python)  
│       ├── __init__.py  
│       ├── base_server.py  
│       └── output_parsers.py  
├── scripts/  
│   └── build-changed.sh             # Build only changed tools  
└── .github/workflows/  
    ├── build-publish.yaml           # CI: Build & push changed images    └── registry-publish.yaml        # CI: Publish registry to opensploit.ai```  
  
#### 3.7.2 Container Architecture  
  
| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-MCP-001 | Each tool SHALL have its own Dockerfile in `tools/<tool>/` | P0 |  
| REQ-MCP-002 | Tool containers SHALL use `kalilinux/kali-rolling` as base image | P0 |  
| REQ-MCP-003 | Each tool container SHALL install only the specific tool needed | P0 |  
| REQ-MCP-004 | Each tool SHALL build to its own image: `ghcr.io/opensploit/tools-<name>:latest` | P0 |  
| REQ-MCP-005 | Tool images SHALL be tagged with both `latest` and git SHA | P0 |  
| REQ-MCP-006 | CI SHALL build only tools that have changed (path-based filtering) | P0 |  
  
#### 3.7.3 Dockerfile Pattern  
  
```dockerfile  
# tools/nmap/Dockerfile  
FROM kalilinux/kali-rolling  
  
# Install only the specific tool  
RUN apt-get update && \  
    apt-get install -y --no-install-recommends \        nmap \        python3 \        python3-pip && \    rm -rf /var/lib/apt/lists/*  
# Install MCP server dependencies  
COPY requirements.txt /app/  
RUN pip3 install --no-cache-dir -r /app/requirements.txt  
  
# Copy MCP server  
COPY mcp-server.py /app/  
WORKDIR /app  
  
# Run MCP server (communicates via stdio)  
CMD ["python3", "mcp-server.py"]  
```  

#### 3.7.4 Registry Flow

```  
┌─────────────────────────────────────────────────────────────────┐  
│                        mcp-tools repo                           │  
│                                                                 │  
│  registry.yaml ─────────────────────────────────────────────┐   │  
│       │                                                     │   │  
│       ▼ (CI: on merge to main)                             │   │  
│  ┌─────────────────────────────────────────────────────┐   │   │  
│  │  GitHub Action: registry-publish.yaml               │   │   │  
│  │  - Validates registry.yaml schema                   │   │   │  
│  │  - Uploads to opensploit.ai/registry.yaml           │   │   │  
│  └─────────────────────────────────────────────────────┘   │   │  
│                                                             │   │  
│  tools/<name>/ ────────────────────────────────────────┐    │   │  
│       │                                                │    │   │  
│       ▼ (CI: on change to tools/<name>/**)            │    │   │  
│  ┌─────────────────────────────────────────────────────┐   │   │  
│  │  GitHub Action: build-publish.yaml                  │   │   │  
│  │  - Detects changed tools via path filter            │   │   │  
│  │  - Builds only changed Dockerfiles                  │   │   │  
│  │  - Pushes to ghcr.io/opensploit/tools-<name>        │   │   │  
│  └─────────────────────────────────────────────────────┘   │   │  
└─────────────────────────────────────────────────────────────────┘  
                              │                              ▼┌─────────────────────────────────────────────────────────────────┐  
│                      opensploit.ai                              │  
│                                                                 │  
│  https://opensploit.ai/registry.yaml  ◄─── Hosted registry      │  
│                                                                 │  
└─────────────────────────────────────────────────────────────────┘  
                              │                              ▼┌─────────────────────────────────────────────────────────────────┐  
│                    User's Machine (opensploit)                  │  
│                                                                 │  
│  1. Fetches https://opensploit.ai/registry.yaml                 │  
│  2. Caches to ~/.opensploit/registry.yaml                       │  
│  3. Tool Registry Search queries local cache                    │  
│  4. When tool needed: docker pull ghcr.io/opensploit/tools-X    │  
│  5. Starts container, connects via MCP stdio                    │  
│                                                                 │  
└─────────────────────────────────────────────────────────────────┘  
```  

#### 3.7.5 On-Demand Tool Loading

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-MCP-010 | OpenSploit SHALL pull tool images only when first used | P0 |  
| REQ-MCP-011 | OpenSploit SHALL display download progress during image pull | P0 |  
| REQ-MCP-012 | OpenSploit SHALL cache pulled images locally | P0 |  
| REQ-MCP-013 | OpenSploit SHALL check for image updates based on registry version | P1 |  
| REQ-MCP-014 | Each tool image SHALL be independently versioned | P0 |  

#### 3.7.6 Benefits of Kali Base Image

| Benefit | Description |  
|---------|-------------|  
| **Pre-packaged tools** | Kali repos maintain security tools with proper dependencies |  
| **Consistent versions** | Tools are tested together in Kali releases |  
| **Simple installation** | `apt install nmap` vs manual compilation |  
| **Security updates** | Kali team maintains security patches |  
| **Community familiarity** | Security practitioners expect Kali tooling |  

> **Note:** While each container uses kali-rolling as base, only the specific tool is installed to minimize image size. Full Kali is ~3GB; individual tool containers target <200MB where possible.

#### 3.7.7 Privileged Container Requirements

Many security tools require elevated privileges (raw sockets, packet manipulation, etc.). Container isolation provides the security boundary, while user approval provides the authorization checkpoint.

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-MCP-020 | Tool containers SHALL run as root inside the container when required | P0 |  
| REQ-MCP-021 | Container isolation (namespaces, seccomp, etc.) SHALL be the security boundary | P0 |  
| REQ-MCP-022 | Registry SHALL specify `requires_privileged` per tool and per method | P0 |  
| REQ-MCP-023 | Registry SHALL include `privileged_reason` explaining why privileges are needed | P0 |  
| REQ-MCP-024 | OpenSploit SHALL prompt user for approval before running privileged containers | P0 |  
| REQ-MCP-025 | Approval dialog SHALL display tool name, target, and privilege reason | P0 |  
| REQ-MCP-026 | User approval SHALL be logged in the audit trail | P0 |  

**Privilege Approval Flow:**

```  
┌─────────────────────────────────────────────────────────────┐  
│  ⚠️  PRIVILEGED CONTAINER REQUIRED                          ││                                                             │  
│  Tool: nmap (port_scan with SYN scan)                       │  
│  Target: 10.10.10.1                                         │  
│                                                             │  
│  This tool requires elevated privileges for:                │  
│    • Raw socket access (SYN scans, OS detection)            │  
│    • Network interface access                               │  
│                                                             │  
│  Container isolation still applies.                         │  
│  This action will be logged.                                │  
│                                                             │  
│  [Deny]                              [Allow]                │  
└─────────────────────────────────────────────────────────────┘  
```  

**Registry Privilege Metadata:**

```yaml  
tools:  
  nmap:    requirements:      privileged: true      privileged_reason: "Raw socket access for SYN scans, OS detection"    methods:      port_scan:        requires_privileged:          tcp_connect: false  # Can run unprivileged          syn: true           # Needs raw sockets          udp: true           # Needs raw sockets      os_detection:        requires_privileged: true  
```  
  
---  

## 4. Functional Requirements

### 4.1 Phase Management

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-FUN-001 | Agent SHALL support Reconnaissance phase (port scanning, service detection) | P0 |  
| REQ-FUN-002 | Agent SHALL support Enumeration phase (directory bruteforcing, version detection) | P0 |  
| REQ-FUN-003 | Agent SHALL support Exploitation phase (vulnerability testing, exploit execution) | P0 |  
| REQ-FUN-004 | Agent SHALL support Post-Exploitation phase (privilege escalation, persistence) | P1 |  
| REQ-FUN-005 | Agent SHALL support Reporting phase (finding aggregation, report generation) | P0 |  
| REQ-FUN-006 | Agent SHALL automatically transition between phases based on findings | P0 |  
| REQ-FUN-007 | Agent SHALL allow manual phase override by user | P0 |  

### 4.2 Tool Orchestration

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-FUN-010 | Agent SHALL select appropriate tools based on current phase and findings | P0 |  
| REQ-FUN-011 | Agent SHALL provide reasoning for tool selection decisions | P0 |  
| REQ-FUN-012 | Agent SHALL handle tool failures gracefully with fallback strategies | P0 |  
| REQ-FUN-013 | Agent SHALL chain tool outputs as inputs to subsequent tools | P0 |  
| REQ-FUN-014 | Agent SHALL respect tool prerequisites and dependencies | P1 |  
| REQ-FUN-015 | Agent SHALL invoke Tool Registry Search (RAG) before using any MCP tool | P0 |  
| REQ-FUN-016 | Tool Registry Search SHALL use semantic search to find relevant tools by query, phase, or capability | P0 |  
| REQ-FUN-017 | Tool Registry Search SHALL return tool metadata including MCP server info and method signatures | P0 |  
| REQ-FUN-018 | Agents SHALL NOT have hardcoded knowledge of available tools; discovery is via RAG only | P0 |  

### 4.3 User Interaction

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-FUN-020 | System SHALL provide natural language interface for target specification | P0 |  
| REQ-FUN-021 | System SHALL display real-time progress of tool execution | P0 |  
| REQ-FUN-022 | System SHALL present findings in categorized, prioritized format | P0 |  
| REQ-FUN-023 | System SHALL request explicit user approval before each significant action (scans, exploits, file writes) | P0 |  
| REQ-FUN-024 | System SHALL support session pause and resume | P1 |  
| REQ-FUN-025 | System SHALL provide help and guidance for new users | P1 |  
| REQ-FUN-026 | Approval flow SHALL follow existing OpenCode permission patterns (dialogs, confirmations) | P0 |  
| REQ-FUN-027 | Agent SHALL clarify any ambiguity about target/scope before beginning pentest | P0 |  

### 4.4 Registry System

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-FUN-030 | System SHALL maintain registry of available tools with metadata | P0 |  
| REQ-FUN-031 | Registry SHALL include tool capabilities, phases, and requirements | P0 |  
| REQ-FUN-032 | Registry SHALL include method signatures with parameters and returns | P0 |  
| REQ-FUN-033 | System SHALL fetch registry at installation and check updates at startup | P0 |  
| REQ-FUN-034 | System SHALL cache registry locally for offline operation | P0 |  
| REQ-FUN-035 | Registry SHALL support version constraints for tool compatibility | P1 |  
| REQ-FUN-036 | System SHALL implement Tool Registry Search as a RAG-based tool callable by any agent | P0 |  
| REQ-FUN-037 | Tool Registry Search SHALL support queries by natural language, phase, and capability | P0 |  
| REQ-FUN-038 | Tool Registry Search SHALL be the ONLY mechanism for agents to discover available tools | P0 |  
| REQ-FUN-039 | Registry SHALL be hosted externally (opensploit.ai or mcp-tools repo) and fetched by client | P0 |  

#### 4.4.1 Tool Registry RAG Implementation

> **Note:** RAG alone does not prevent tool over-reliance. General-purpose tools (curl, netcat) often have higher semantic similarity to queries because they're described broadly. The RAG system must incorporate routing metadata and selection hierarchy to guide agents toward specialized tools.

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-FUN-036-A | RAG index SHALL include tool routing metadata (use_for, never_use_for, prefer_over) as searchable fields | P0 |  
| REQ-FUN-036-B | RAG index SHALL include selection_level (1=Skill, 2=Specialized, 3=General) for ranking | P0 |  
| REQ-FUN-036-C | RAG index SHALL include phase appropriateness (required, recommended, discouraged per phase) | P0 |  
| REQ-FUN-036-D | RAG ranking SHALL combine semantic similarity with selection_level weighting | P0 |  
| REQ-FUN-036-E | RAG results SHALL prioritize Level 1/2 tools over Level 3 even if Level 3 has higher semantic match | P0 |  
| REQ-FUN-036-F | RAG SHALL perform "negative retrieval" - surfacing never_use_for warnings when query matches anti-patterns | P1 |  
| REQ-FUN-036-G | RAG result format SHALL include: tool metadata, routing guidance, anti-pattern warnings, suggested alternatives | P0 |  

**RAG Ranking Formula:**

```  
final_score = (semantic_similarity * 0.4) + (selection_level_score * 0.4) + (phase_match * 0.2)  
  
where:  
  selection_level_score = {1: 1.0, 2: 0.7, 3: 0.3}  # Skills highest, general lowest  phase_match = 1.0 if tool in phase.required/recommended, 0.5 if optional, 0.0 if discouraged```  
  
**Example RAG Result Structure:**  
  
```json  
{  
  "query": "test login form for SQL injection",  "phase": "enumeration",  "results": [    {      "tool": "sqlmap",      "score": 0.91,      "selection_level": 2,      "routing": {        "use_for": ["Any SQL injection testing", "Database enumeration via SQLi"],        "triggers": ["Login form detected", "Database error in response"]      },      "recommended_for_phase": true    },    {      "tool": "curl",      "score": 0.72,      "selection_level": 3,      "routing": {        "never_use_for": {          "task": "SQL injection testing",          "use_instead": "sqlmap",          "reason": "sqlmap provides comprehensive automated SQLi detection"        }      },      "discouraged_for_phase": true,      "warning": "curl is discouraged for this task. Use sqlmap instead."    }  ],  "anti_pattern_warnings": [    "SQL injection testing detected. Do NOT use curl for this - use sqlmap for comprehensive detection."  ]}  
```  

### 4.5 Container Management

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-FUN-040 | System SHALL pull Docker images on-demand when tool is first used | P0 |  
| REQ-FUN-041 | System SHALL display download progress to user | P0 |  
| REQ-FUN-042 | System SHALL start containers with appropriate resource limits | P0 |  
| REQ-FUN-043 | System SHALL implement idle timeout for container cleanup | P0 |  
| REQ-FUN-044 | System SHALL stop and remove containers when resources are low | P0 |  
| REQ-FUN-045 | System SHALL support maximum concurrent container limits per resource tier | P0 |  

### 4.6 Session Management

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-FUN-050 | System SHALL persist session state across restarts | P0 |
| REQ-FUN-051 | System SHALL store all findings with provenance (tool, method, timestamp) | P0 |
| REQ-FUN-052 | System SHALL maintain action log for audit purposes | P0 |
| REQ-FUN-053 | System SHALL support multiple concurrent sessions | P1 |
| REQ-FUN-054 | System SHALL support session export and import | P2 |

#### 4.6.1 Engagement Log Aggregation

Users need a consolidated view of "what happened" across all sub-agents during a penetration test engagement.

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| REQ-SES-010 | System SHALL support engagement log aggregation across parent and child sessions | P0 |
| REQ-SES-011 | Engagement log SHALL show all TVAR reasoning steps from all agents in timeline order | P0 |
| REQ-SES-012 | Engagement log SHALL include agent name for each step | P0 |
| REQ-SES-013 | System SHALL provide CLI command to view engagement timeline | P1 |
| REQ-SES-014 | Engagement log SHALL be exportable for post-engagement analysis | P1 |

### 4.7 Pattern Learning

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-FUN-060 | System SHALL store successful attack patterns with embeddings | P0 |  
| REQ-FUN-061 | System SHALL support similarity search for relevant patterns | P0 |  
| REQ-FUN-062 | System SHALL anonymize patterns before storage | P0 |  
| REQ-FUN-063 | System SHALL allow user to opt-in to cloud pattern sharing | P2 |  
| REQ-FUN-064 | System SHALL fetch community patterns for subscribed users | P2 |  

### 4.8 Reporting

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-FUN-070 | System SHALL generate summary reports of assessment findings | P0 |  
| REQ-FUN-071 | System SHALL categorize findings by severity (Critical, High, Medium, Low, Info) | P0 |  
| REQ-FUN-072 | System SHALL include evidence and reproduction steps in findings | P0 |  
| REQ-FUN-073 | System SHALL support multiple report formats (Markdown, HTML, PDF) | P1 |  
| REQ-FUN-074 | System SHALL support professional report templates | P1 |  
| REQ-FUN-075 | System SHALL support compliance-specific templates (PCI-DSS, HIPAA, SOC2) | P2 |  

### 4.9 Intelligent Tool Selection & Orchestration

> **Note:** This section extends Section 4.2 (Tool Orchestration) with enforcement mechanisms to prevent tool misuse patterns discovered during testing. The core problem: when given flexible general-purpose tools (e.g., curl) alongside specialized tools (e.g., sqlmap), agents tend to over-rely on the flexible tool even when specialized tools would be more effective.

#### 4.9.1 Tool Routing Rules

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-FUN-080 | Registry SHALL define `use_for` conditions specifying when each tool is appropriate | P0 |  
| REQ-FUN-081 | Registry SHALL define `never_use_for` conditions specifying anti-patterns for each tool | P0 |  
| REQ-FUN-082 | Registry SHALL define `prefer_over` relationships between tools for specific tasks | P0 |  
| REQ-FUN-083 | Tool Registry Search SHALL return routing guidance alongside tool metadata | P0 |
| REQ-FUN-084 | Agent SHALL consider tool routing guidance in TVAR verification step when selecting tools | P0 |

> **Note:** Routing rules (`use_for`, `never_use_for`, `prefer_over`) are **guidance for reasoning**, not hard blocks. The agent considers this guidance in the TVAR verification step (Section 16.1) and makes reasoned decisions. This allows the agent to deviate when justified (e.g., when specialized tools aren't available) while still benefiting from accumulated knowledge about tool effectiveness.  

**Example Registry Routing Metadata:**

```yaml  
tools:  
  curl:    routing:      use_for:        - "One-off HTTP debugging"        - "Custom protocol interactions"        - "Downloading files"      never_use_for:        - task: "SQL injection testing"          use_instead: sqlmap          reason: "sqlmap provides comprehensive automated SQLi detection"        - task: "Session/cookie management"          use_instead: web-session          reason: "web-session maintains state across requests"        - task: "Brute force attacks"          use_instead: hydra          reason: "hydra is optimized for credential attacks"        - task: "Vulnerability scanning"          use_instead: [nuclei, nikto]          reason: "Dedicated scanners have vulnerability databases"  
  sqlmap:    routing:      use_for:        - "Any SQL injection testing"        - "Database enumeration via SQLi"        - "Data extraction via SQLi"      triggers:  # Conditions that should prompt sqlmap usage        - "Login form detected"        - "Database error in response"        - "User input reflected in query context"      prefer_over:        - curl  # For any SQLi-related task  
```  

#### 4.9.2 Composite Workflow Tools (Skills)

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-FUN-085 | System SHALL support composite "skill" tools that orchestrate multiple specialized tools | P1 |  
| REQ-FUN-086 | Skills SHALL encapsulate best-practice tool sequences for common tasks | P1 |  
| REQ-FUN-087 | Skills SHALL handle inter-tool data flow automatically | P1 |  
| REQ-FUN-088 | Registry SHALL define skill compositions with tool sequences | P1 |  
| REQ-FUN-089 | Agent SHOULD prefer invoking skills over individual tools for covered tasks | P1 |  

**Example Skill Definitions:**

```yaml  
skills:  
  web-vuln-scan:    description: "Comprehensive web vulnerability assessment"    use_for: "Initial web application security testing"    orchestrates:      - tool: web-fingerprint        purpose: "Identify technology stack"      - tool: nuclei        purpose: "Scan for known CVEs"        depends_on: web-fingerprint  # Uses detected tech to select templates      - tool: ffuf        purpose: "Directory enumeration"      - tool: sqlmap        purpose: "Test discovered forms for SQLi"        condition: "forms_detected"  
  credential-attack:    description: "Brute force credentials for a service"    use_for: "Attempting to discover valid credentials"    params:      target: { type: string, required: true }      service: { type: enum, values: [ssh, ftp, http-post-form, mysql] }      userlist: { type: string, description: "Newline-separated usernames" }    orchestrates:      - tool: hydra        purpose: "Execute brute force attack"        auto_config:          - "Creates temporary wordlist files from input"          - "Selects appropriate hydra module based on service"          - "Configures rate limiting based on target"  
  authenticated-web-test:    description: "Test authenticated web application functionality"    use_for: "Security testing after obtaining credentials"    orchestrates:      - tool: web-session        purpose: "Establish and maintain authenticated session"      - tool: ffuf        purpose: "Authenticated directory enumeration"        uses_session: true      - tool: sqlmap        purpose: "Test authenticated endpoints"        uses_session: true  
```  

#### 4.9.3 Phase-Based Tool Gating

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-FUN-090 | Registry SHALL define which tools are appropriate for each pentest phase | P0 |  
| REQ-FUN-091 | Registry SHALL define `required`, `recommended`, `optional`, and `discouraged` tool lists per phase | P1 |  
| REQ-FUN-092 | Agent SHALL warn when using a tool discouraged for the current phase | P1 |  
| REQ-FUN-093 | System SHALL display phase-appropriate tool recommendations before each phase begins | P1 |  

**Example Phase-Tool Mapping:**

```yaml  
phases:  
  reconnaissance:    required: [nmap]    recommended: [web-fingerprint]    optional: [nuclei]    discouraged:      - tool: curl        reason: "Use web-fingerprint for HTTP reconnaissance"      - tool: sqlmap        reason: "Exploitation tools are premature in recon phase"  
  enumeration:    required: [ffuf]    recommended: [nikto, nuclei, sqlmap]    optional: [wpscan, web-session]    discouraged:      - tool: curl        reason: "Use specialized enumeration tools"  
  exploitation:    unlocks_after: [reconnaissance, enumeration]    required: []    recommended: [sqlmap, hydra, exploit-runner, ssh]    optional: [metasploit, payload, netcat]    discouraged: []  
  post_exploitation:    unlocks_after: [exploitation]    required: []    recommended: [privesc, tunnel, mysql]    optional: [john, payload]    discouraged:      - tool: nmap        reason: "Reconnaissance should be complete"  
```  

#### 4.9.4 Tool Usage Monitoring

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-FUN-094 | System SHALL track tool usage frequency within a session | P1 |  
| REQ-FUN-095 | System SHALL detect anti-patterns in tool usage | P1 |  
| REQ-FUN-096 | System SHALL provide nudges when anti-patterns are detected | P1 |  
| REQ-FUN-097 | Nudges SHALL suggest appropriate specialized tools | P1 |
| REQ-FUN-098 | Usage patterns SHALL be logged for analysis and improvement | P2 |

> **Note:** Nudges are **suggestions injected into TVAR reasoning context**, not automatic corrections. When anti-patterns are detected, the system surfaces a nudge that the agent considers in its next verification step. The agent may choose to follow the nudge or continue with its current approach if justified. This aligns with Section 16.4's reasoning-based approach.

**Anti-Pattern Detection Examples:**

| Anti-Pattern | Detection Condition | Nudge |  
|--------------|---------------------|-------|  
| curl over-reliance | curl called 5+ times for HTTP requests in enumeration phase | "Consider using web-session for session management, nuclei for vuln scanning" |  
| Manual SQLi | curl with SQL-like payloads in POST data | "sqlmap detected SQL injection patterns - use sqlmap for comprehensive testing" |  
| Manual brute force | Repeated ssh/ftp calls with different credentials | "Use hydra for credential brute forcing - it's faster and handles rate limiting" |  
| Skipping recon tools | Exploitation tools used without prior nmap/fingerprint calls | "Reconnaissance appears incomplete - consider running nmap and web-fingerprint first" |  

#### 4.9.5 Tool Selection Hierarchy

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-FUN-099 | System SHALL implement a tool selection hierarchy: Skills → Specialized → General-purpose | P1 |
| REQ-FUN-100 | Agent SHOULD prefer skill-based solutions before individual tools | P1 |
| REQ-FUN-101 | Agent SHOULD prefer specialized tools before general-purpose fallbacks | P1 |
| REQ-FUN-102 | Agent SHALL document reasoning when deviating from the selection hierarchy | P1 |

> **Note:** The selection hierarchy is a **heuristic for TVAR reasoning**, not a strict enforcement mechanism. The agent considers hierarchy position in the verification step but may deviate with documented justification (e.g., specialized tool unavailable, edge case not covered by specialized tools).  

**Tool Selection Hierarchy:**

```  
Level 1: Skills (Highest Priority)  
├── web-vuln-scan  
├── credential-attack  
├── authenticated-web-test  
└── ...  
  
Level 2: Specialized Tools  
├── sqlmap (for SQLi)  
├── hydra (for brute force)  
├── nuclei (for vuln scanning)  
├── web-session (for session management)  
└── ...  
  
Level 3: General-Purpose Tools (Last Resort)  
├── curl (HTTP requests)  
├── netcat (raw connections)  
└── ssh exec (command execution)  
  
Rules:
- Try Level 1 first if a skill covers the task
- Fall to Level 2 if no skill applies
- Fall to Level 3 only with justification
```

### 4.10 Shell Session Management

> **Context:** A critical capability gap identified through research is the inability to interact with shells on compromised targets. The agent can attack targets via MCP tools, but once access is obtained (credentials, reverse shell), there's no way to execute commands on the compromised system. This section defines requirements for persistent shell session management.

#### 4.10.1 Shell Session MCP Tool

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| REQ-FUN-110 | System SHALL provide a `shell-session` MCP tool for managing remote shell sessions | P0 |
| REQ-FUN-111 | Tool SHALL support SSH-based sessions as the primary transport | P0 |
| REQ-FUN-112 | Tool SHALL support reverse shell sessions as fallback transport | P0 |
| REQ-FUN-113 | Tool SHALL maintain multiple concurrent sessions identified by unique session IDs | P0 |
| REQ-FUN-114 | Tool SHALL support command execution with configurable timeouts | P0 |
| REQ-FUN-115 | Tool SHALL support file upload to target via SFTP or inline transfer | P0 |
| REQ-FUN-116 | Tool SHALL support file download from target | P0 |
| REQ-FUN-117 | Tool SHALL implement output stability detection for command completion | P1 |
| REQ-FUN-118 | Tool SHALL support shell upgrade (dumb shell to PTY) | P1 |

**Shell Session Methods:**

```yaml
shell-session:
  methods:
    # SSH-based sessions (preferred)
    ssh_connect:
      description: "Establish SSH session to target"
      params:
        host: { type: string, required: true }
        port: { type: integer, default: 22 }
        username: { type: string, required: true }
        password: { type: string }
        private_key: { type: string, description: "Base64-encoded key" }
        timeout: { type: integer, default: 30 }
      returns:
        session_id: string
        banner: string

    exec:
      description: "Execute command on established session"
      params:
        session_id: { type: string, required: true }
        command: { type: string, required: true }
        timeout: { type: integer, default: 120 }
        get_pty: { type: boolean, default: false }
      returns:
        stdout: string
        stderr: string
        exit_code: integer
        timed_out: boolean

    upload:
      description: "Upload file to target"
      params:
        session_id: { type: string, required: true }
        content: { type: string, description: "Base64-encoded content" }
        remote_path: { type: string, required: true }
        mode: { type: string, default: "0755" }
      returns:
        success: boolean
        bytes_written: integer

    download:
      description: "Download file from target"
      params:
        session_id: { type: string, required: true }
        remote_path: { type: string, required: true }
      returns:
        content: string  # Base64-encoded
        size: integer

    # Reverse shell sessions (fallback)
    listen:
      description: "Start listener for reverse shell connection"
      params:
        port: { type: integer, required: true }
        timeout: { type: integer, default: 300 }
      returns:
        session_id: string
        remote_ip: string

    shell_exec:
      description: "Execute command on reverse shell with output stability detection"
      params:
        session_id: { type: string, required: true }
        command: { type: string, required: true }
        timeout: { type: integer, default: 60 }
      returns:
        output: string

    # Session management
    list_sessions:
      description: "List all active sessions"
      returns:
        sessions: array

    close:
      description: "Close session gracefully"
      params:
        session_id: { type: string, required: true }
      returns:
        success: boolean

    upgrade_shell:
      description: "Upgrade dumb shell to interactive PTY"
      params:
        session_id: { type: string, required: true }
      returns:
        success: boolean
```

**Output Stability Detection Algorithm:**

```
1. Execute command on channel
2. Start timer
3. Loop:
   a. If output received:
      - Append to buffer
      - Reset stability timer
   b. If no output for STABILITY_WINDOW (default 0.5s):
      - Check for shell prompt ($ # > or custom)
      - If prompt found or stability timeout: return buffer
   c. If total timeout exceeded: return buffer + "[TIMEOUT]"
4. Return collected output
```

### 4.11 Target State Tracking

> **Context:** The agent needs structured memory of what it has discovered and achieved on each target. Relying solely on conversation context leads to lost information and repeated work.

#### 4.11.1 Target Tracker Tool

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| REQ-FUN-120 | System SHALL provide a `target-tracker` built-in tool for tracking target state | P0 |
| REQ-FUN-121 | Tool SHALL track discovered ports and services per target | P0 |
| REQ-FUN-122 | Tool SHALL track discovered and validated credentials | P0 |
| REQ-FUN-123 | Tool SHALL track active shell sessions and access levels | P0 |
| REQ-FUN-124 | Tool SHALL track identified vulnerabilities and exploitation status | P0 |
| REQ-FUN-125 | Tool SHALL track captured flags and evidence | P1 |
| REQ-FUN-126 | Tool SHALL persist state across session restarts | P1 |
| REQ-FUN-127 | Tool SHALL provide query methods for agent reasoning | P0 |

**Target State Schema:**

```typescript
interface TargetState {
  ip: string
  hostname?: string

  // Discovery phase
  ports: {
    port: number
    state: "open" | "filtered" | "closed"
    protocol: "tcp" | "udp"
    service: string
    version?: string
    banner?: string
  }[]

  // Credentials
  credentials: {
    username: string
    password?: string
    hash?: string
    key?: string
    service: string  // ssh, ftp, mysql, http, smb
    validated: boolean
    privileged: boolean  // is this a root/admin account?
  }[]

  // Active access
  sessions: {
    id: string
    type: "ssh" | "reverse" | "webshell" | "meterpreter"
    user: string
    privileged: boolean
    established: timestamp
  }[]

  // Vulnerabilities
  vulnerabilities: {
    id?: string  // CVE if known
    description: string
    service: string
    port?: number
    severity: "critical" | "high" | "medium" | "low"
    exploited: boolean
    accessGained?: "none" | "user" | "root"
  }[]

  // Files of interest
  files: {
    path: string
    type: "config" | "credential" | "flag" | "suid" | "writable" | "interesting"
    content?: string
    notes?: string
  }[]

  // Overall state
  accessLevel: "none" | "user" | "root"
  flags: string[]  // Captured flags (e.g., user.txt content)

  // Failed attempts (anti-pattern tracking)
  failedAttempts: {
    action: string
    tool: string
    reason: string
    timestamp: timestamp
  }[]
}
```

**Target Tracker Methods:**

```yaml
target-tracker:
  methods:
    register:
      description: "Register a new target"
      params:
        ip: { type: string, required: true }
        hostname: { type: string }

    add_port:
      description: "Record discovered port/service"
      params:
        ip: { type: string, required: true }
        port: { type: integer, required: true }
        service: { type: string }
        version: { type: string }

    add_credential:
      description: "Record discovered credential"
      params:
        ip: { type: string, required: true }
        username: { type: string, required: true }
        password: { type: string }
        service: { type: string, required: true }
        validated: { type: boolean, default: false }

    add_vulnerability:
      description: "Record identified vulnerability"
      params:
        ip: { type: string, required: true }
        description: { type: string, required: true }
        cve: { type: string }
        severity: { type: string }

    update_access:
      description: "Update access level achieved"
      params:
        ip: { type: string, required: true }
        level: { type: string, enum: ["none", "user", "root"] }
        session_id: { type: string }

    record_failure:
      description: "Record failed attempt to avoid repetition"
      params:
        ip: { type: string, required: true }
        action: { type: string, required: true }
        tool: { type: string }
        reason: { type: string }

    get_state:
      description: "Get complete state for target"
      params:
        ip: { type: string, required: true }
      returns:
        state: TargetState

    get_summary:
      description: "Get summary of all targets"
      returns:
        targets: array
        total_access: object
```

### 4.12 Exploit Template System

> **Context:** The MCP-first policy correctly prevents arbitrary code execution, but many vulnerabilities require customization. The exploit template system provides parameterized exploits that maintain the safety of MCP tools while enabling flexible exploitation.

#### 4.12.1 Exploit Templates

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| REQ-FUN-130 | System SHALL provide parameterized exploit templates for common vulnerabilities | P1 |
| REQ-FUN-131 | Templates SHALL NOT allow arbitrary code execution | P0 |
| REQ-FUN-132 | Templates SHALL define required and optional parameters with validation | P0 |
| REQ-FUN-133 | Templates SHALL include success indicators for result verification | P1 |
| REQ-FUN-134 | System SHALL provide 50+ templates covering common CVEs and techniques | P2 |

**Exploit Template Schema:**

```yaml
# Example: exploit-templates/cve-2024-4040-crushftp.yaml
metadata:
  id: cve-2024-4040-crushftp
  name: "CrushFTP Authentication Bypass RCE"
  cve: CVE-2024-4040
  cvss: 9.8
  categories: [web, rce, auth-bypass]
  references:
    - https://nvd.nist.gov/vuln/detail/CVE-2024-4040

parameters:
  target_url:
    type: string
    required: true
    description: "Base URL of CrushFTP instance"
    example: "http://10.10.10.1:8080"
    validation: "^https?://.+"
  command:
    type: string
    required: true
    description: "Command to execute"
    example: "id"

execution:
  type: http
  method: POST
  url: "{{target_url}}/WebInterface/function/"
  params:
    command: getServerInfo
  headers:
    Content-Type: application/x-www-form-urlencoded
  body: |
    serverGroup=a]};java.lang.Runtime.getRuntime().exec("{{command}}");c=c.class.forName("[

success_indicators:
  stdout_contains:
    - "uid="
  status_code: 200

follow_up:
  description: "Establish persistent access"
  suggested_action: "Use shell-session to establish reverse shell"
```

**Enhanced exploit-runner Methods:**

```yaml
exploit-runner:
  methods:
    # Existing methods...

    list_templates:
      description: "List available exploit templates"
      params:
        category: { type: string, description: "Filter by category" }
        cve: { type: string, description: "Search by CVE" }
      returns:
        templates: array

    run_template:
      description: "Execute parameterized exploit template"
      params:
        template: { type: string, required: true, description: "Template ID" }
        parameters: { type: object, required: true }
        timeout: { type: integer, default: 60 }
      returns:
        success: boolean
        output: string
        indicators_matched: array

    get_template_info:
      description: "Get template details and required parameters"
      params:
        template: { type: string, required: true }
      returns:
        metadata: object
        parameters: array
        example: object
```

### 4.13 Knowledge Base RAG (Future Enhancement)

> **Context:** Agent success rate can be significantly improved by providing access to technique knowledge bases like HackTricks, GTFOBins, and PayloadsAllTheThings.

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| REQ-FUN-140 | System SHOULD integrate HackTricks knowledge base for technique lookup | P2 |
| REQ-FUN-141 | System SHOULD integrate GTFOBins for privilege escalation techniques | P2 |
| REQ-FUN-142 | System SHOULD integrate PayloadsAllTheThings for payload generation | P2 |
| REQ-FUN-143 | Knowledge base queries SHALL return relevant techniques for current context | P2 |
| REQ-FUN-144 | Agent SHALL query knowledge base when stuck or exploring options | P2 |

**Example Usage:**

```
Agent: "Found SUID on /usr/bin/find"
Query: knowledge_search("SUID find privilege escalation")
Result: "find . -exec /bin/sh \; -quit" (from GTFOBins)
```

---

## 5. Non-Functional Requirements

### 5.1 Performance

| Req ID      | Requirement                                                            | Metric  | Priority |  
|-------------|------------------------------------------------------------------------|---------|----------|  
| REQ-NFR-001 | Installation SHALL complete within 60 seconds (excluding dependencies) | < 60s   | P0       |  
| REQ-NFR-002 | Agent startup SHALL complete within 5 seconds                          | < 5s    | P0       |  
| REQ-NFR-003 | Tool image pull SHALL show progress within 2 seconds                   | < 2s    | P0       |  
| REQ-NFR-004 | LLM response latency SHOULD be under 3 seconds for simple queries      | < 3s    | P1       |  
| REQ-NFR-005 | Memory system queries SHALL complete within 100ms                      | < 100ms | P0       |  
| REQ-NFR-006 | TUI SHALL maintain 60fps refresh rate during normal operation          | 60fps   | P1       |  

### 5.2 Scalability

| Req ID      | Requirement                                              | Priority |  
|-------------|----------------------------------------------------------|----------|  
| REQ-NFR-010 | System SHALL support sessions with 1000+ findings        | P0       |  
| REQ-NFR-011 | Pattern database SHALL support 100,000+ patterns locally | P1       |  
| REQ-NFR-012 | System SHALL support 50+ installed tools                 | P0       |  
| REQ-NFR-013 | Registry SHALL support 200+ tool definitions             | P1       |  

### 5.3 Reliability

| Req ID      | Requirement                                                | Priority |  
|-------------|------------------------------------------------------------|----------|  
| REQ-NFR-020 | System SHALL handle tool crashes without agent termination | P0       |  
| REQ-NFR-021 | System SHALL recover from container failures automatically | P0       |  
| REQ-NFR-022 | Session data SHALL survive unexpected termination          | P0       |  
| REQ-NFR-023 | System SHALL operate offline after initial setup           | P0       |  
| REQ-NFR-024 | System SHALL validate all external inputs                  | P0       |  

### 5.4 Usability

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-NFR-030 | New user SHALL complete first scan within 5 minutes of installation | P0 |  
| REQ-NFR-031 | System SHALL provide clear error messages with remediation steps | P0 |  
| REQ-NFR-032 | System SHALL provide contextual help for all commands | P1 |  
| REQ-NFR-033 | Documentation SHALL cover all features with examples | P0 |  
| REQ-NFR-034 | System SHALL support keyboard navigation in TUI | P0 |  

### 5.5 Maintainability

| Req ID      | Requirement                                               | Priority |  
|-------------|-----------------------------------------------------------|----------|  
| REQ-NFR-040 | Code SHALL maintain 80%+ test coverage for critical paths | P0       |  
| REQ-NFR-041 | All public APIs SHALL be documented                       | P0       |  
| REQ-NFR-042 | System SHALL support plugin architecture for new tools    | P1       |  
| REQ-NFR-043 | Logs SHALL include sufficient context for debugging       | P0       |  
| REQ-NFR-044 | Configuration SHALL be externalized and documented        | P0       |  
  
---  

## 6. Technical Stack Requirements

### 6.1 Core Application (TypeScript)

| Component       | Technology            | Version | Purpose                     |  
|-----------------|-----------------------|---------|-----------------------------|  
| Language        | TypeScript            | 5.0+    | Core agent implementation   |  
| Runtime         | Bun                   | Latest  | Fast JS runtime             |  
| TUI Framework   | Solid.js + Ink        | Latest  | Terminal user interface     |  
| Base Framework  | OpenCode Fork         | Latest  | Agent loop, providers, auth |  
| SQLite          | better-sqlite3        | Latest  | Session/findings storage    |  
| LLM Providers   | AI SDK                | Latest  | 75+ provider support        |  
| MCP Client      | @modelcontextprotocol | Latest  | Tool server communication   |  

> **Note:** Originally spec'd as Go/Bubble Tea, but TypeScript/OpenCode fork provides faster time-to-market with proven infrastructure.

### 6.2 MCP Tool Servers (Python)

| Component | Technology | Version | Purpose |  
|-----------|------------|---------|---------|  
| Language | Python | 3.10+ | MCP server implementation |  
| MCP SDK | modelcontextprotocol/python-sdk | Latest | Protocol implementation |  
| Nmap Integration | python-nmap | Latest | Port scanning |  
| Network Protocols | impacket | Latest | SMB/Windows protocols |  
| Packet Manipulation | scapy | Latest | Low-level networking |  
| Exploit Dev | pwntools | Latest | Binary exploitation |  

### 6.3 Web Services (TypeScript)

| Component | Technology | Version | Purpose |  
|-----------|------------|---------|---------|  
| Language | TypeScript | 5.0+ | Web services |  
| API Framework | Hono | Latest | Edge-compatible API |  
| Static Site | Astro | Latest | Marketing site |  
| Documentation | Starlight | Latest | Documentation site |  
| Hosting | Cloudflare Workers | N/A | Edge deployment |  
| Database | Supabase | N/A | User data, patterns |  

### 6.4 Infrastructure

| Component          | Technology                          | Purpose                    |  
|--------------------|-------------------------------------|----------------------------|  
| Container Runtime  | Docker Engine                       | Tool containerization      |  
| Container Registry | GitHub Container Registry (ghcr.io) | Image distribution         |  
| CDN                | Cloudflare                          | Registry file distribution |  
| Domain             | opensploit.ai                       | Primary domain             |  
| Version Control    | GitHub                              | Source code, CI/CD         |  
| CI/CD              | GitHub Actions                      | Build, test, deploy        |  
  
---  

## 7. Integration Requirements

### 7.1 MCP Protocol Integration

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-INT-001 | System SHALL implement MCP client per official specification | P0 |  
| REQ-INT-002 | System SHALL support JSON-RPC 2.0 over stdio transport | P0 |  
| REQ-INT-003 | System SHALL implement tools/list for capability discovery | P0 |  
| REQ-INT-004 | System SHALL implement tools/call for tool invocation | P0 |  
| REQ-INT-005 | System SHALL handle MCP error responses gracefully | P0 |  
| REQ-INT-006 | System SHALL support streaming responses where applicable | P1 |  

### 7.2 Docker Integration

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-INT-010 | System SHALL detect Docker availability at startup | P0 |  
| REQ-INT-011 | System SHALL provide clear instructions if Docker is missing | P0 |  
| REQ-INT-012 | System SHALL support Docker socket at standard locations | P0 |  
| REQ-INT-013 | System SHALL configure container networking for target access | P0 |  
| REQ-INT-014 | System SHALL mount necessary volumes for tool data sharing | P1 |  
| REQ-INT-015 | System SHALL support both rootful and rootless Docker | P1 |  

### 7.3 LLM Provider Integration

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-INT-020 | System SHALL inherit OpenCode's provider abstraction layer | P0 |  
| REQ-INT-021 | System SHALL support Ollama for local LLM inference | P0 |  
| REQ-INT-022 | System SHALL support Anthropic Claude API | P0 |  
| REQ-INT-023 | System SHALL support OpenAI API | P0 |  
| REQ-INT-024 | System SHALL support AWS Bedrock | P1 |  
| REQ-INT-025 | System SHALL store API keys securely in system keychain | P0 |  

### 7.4 Security Tool Integration (MVP)

| Tool | Purpose | Phase | Priority |  
|------|---------|-------|----------|  
| nmap | Port scanning, service detection, OS fingerprinting | Reconnaissance | P0 |  
| web-fingerprint | Web technology detection (CMS, frameworks, servers) | Reconnaissance | P0 |  
| cve-lookup | CVE research and exploit discovery via NVD API | Enumeration | P0 |  
| gobuster | Directory and DNS bruteforcing | Enumeration | P0 |  
| ffuf | Web fuzzing | Enumeration | P0 |  
| nikto | Web server vulnerability scanning | Enumeration | P0 |  
| whatweb | Web technology fingerprinting | Reconnaissance | P0 |  
| curl | HTTP requests, RCE injection, file download | Multiple | P0 |  
| sqlmap | SQL injection testing | Exploitation | P0 |  
| hydra | Password brute-forcing | Exploitation | P1 |  
| wpscan | WordPress vulnerability scanning | Enumeration | P1 |  
| metasploit | Exploitation framework | Exploitation | P1 |  
| ssh | Remote command execution and file transfer | Exploitation | P0 |  
| netcat | Reverse shell listener and port checking | Exploitation | P0 |  
| payload | Binary compilation, SUID shells, reverse shells | Exploitation | P0 |  
| mysql | MySQL database enumeration and queries | Post-Exploitation | P1 |
| privesc | Privilege escalation enumeration and suggestions | Post-Exploitation | P0 |
| tunnel | SSH port forwarding and SOCKS proxy | Post-Exploitation | P0 |
| john | Password cracking | Post-Exploitation | P2 |
| nosqlmap | NoSQL injection testing (MongoDB, CouchDB) | Exploitation | P0 |
| mongodb | MongoDB client for direct database interaction | Post-Exploitation | P1 |

### 7.5 External Tool Integration (Local MCP Servers)

Some professional tools run on the host system rather than in Docker containers. OpenSploit SHALL support connecting to local MCP servers for these integrations.

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| REQ-INT-030 | System SHALL support connecting to local MCP servers (non-Docker) | P1 |
| REQ-INT-031 | Registry SHALL support `type: local-mcp` for host-based tools | P1 |
| REQ-INT-032 | System SHALL auto-detect running local MCP servers | P2 |
| REQ-INT-033 | System SHALL gracefully handle unavailable local MCP servers | P1 |

**Supported Local MCP Integrations:**

| Tool | MCP Server | Endpoint | License | Features |
|------|------------|----------|---------|----------|
| Burp Suite | PortSwigger/mcp-server | localhost:9876 | Community/Pro | HTTP requests, encoding, proxy history, scanner (Pro only) |

**Burp Suite Integration:**

The official Burp Suite MCP server (https://github.com/PortSwigger/mcp-server) provides:
- `SendHttp1Request`, `SendHttp2Request` - HTTP request execution
- `UrlEncode`, `UrlDecode`, `Base64Encode`, `Base64Decode` - Payload encoding
- `GetProxyHttpHistory` - Access proxy history
- `CreateRepeaterTab`, `SendToIntruder` - Burp tool integration
- `GetScannerIssues` - Vulnerability scan results (Professional only)

Works with Burp Suite Community Edition for most features. Active scanner requires Professional license.

### 7.6 Host System Integration

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| REQ-INT-040 | System SHALL manage `/etc/hosts` entries for target hostnames | P0 |
| REQ-INT-041 | System SHALL prompt user with sudo requirement before modifying hosts | P0 |
| REQ-INT-042 | System SHALL track all hosts entries it adds (with marker comments) | P0 |
| REQ-INT-043 | System SHALL clean up hosts entries on session end or explicit cleanup | P0 |
| REQ-INT-044 | System SHALL support manual cleanup command for orphaned entries | P1 |

**Hosts Management Flow:**

```
User: pentest soulmate.htb at 10.129.25.244

System:
┌─────────────────────────────────────────────────────────────┐
│  Target requires hostname resolution                         │
│                                                             │
│  Add to /etc/hosts:                                         │
│    10.129.25.244  soulmate.htb                              │
│                                                             │
│  This requires sudo access.                                 │
│  Entry will be removed when session ends.                   │
│                                                             │
│  [Cancel]                              [Add with sudo]      │
└─────────────────────────────────────────────────────────────┘
```

**Implementation:**

```bash
# Marker comment for tracking
echo "10.129.25.244 soulmate.htb  # opensploit:session-abc123" | sudo tee -a /etc/hosts

# Cleanup removes only marked entries
sudo sed -i '/ # opensploit:session-abc123$/d' /etc/hosts
```

---

## 8. Data Requirements

### 8.1 Session Data Schema

```sql  
-- Sessions table  
CREATE TABLE sessions (  
    id TEXT PRIMARY KEY,    target TEXT NOT NULL,    status TEXT NOT NULL DEFAULT 'active',  -- active, completed, paused, failed    phase TEXT NOT NULL DEFAULT 'reconnaissance',    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,    completed_at DATETIME,    ports_found INTEGER DEFAULT 0,    services_found INTEGER DEFAULT 0,    vulns_found INTEGER DEFAULT 0,    access_achieved TEXT,  -- none, user, root    config JSON);  
  
-- Findings table  
CREATE TABLE findings (  
    id TEXT PRIMARY KEY,    session_id TEXT NOT NULL REFERENCES sessions(id),    type TEXT NOT NULL,  -- port, service, vulnerability, credential, file    severity TEXT,  -- critical, high, medium, low, info    title TEXT NOT NULL,    description TEXT,    evidence JSON,    cve TEXT,    cvss REAL,    exploitable BOOLEAN,    tool_used TEXT,    method_used TEXT,    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,    metadata JSON);  
  
-- Action log table  
CREATE TABLE action_log (  
    id INTEGER PRIMARY KEY AUTOINCREMENT,    session_id TEXT NOT NULL REFERENCES sessions(id),    action_type TEXT NOT NULL,  -- tool_call, phase_change, user_input, llm_decision    tool_name TEXT,    method_name TEXT,    params JSON,    result JSON,    success BOOLEAN,    error_message TEXT,    duration_ms INTEGER,    tokens_used INTEGER,    created_at DATETIME DEFAULT CURRENT_TIMESTAMP);  
```  

### 8.2 Pattern Data Schema

```  
Collection: "attack_patterns"  
  
Document structure:  
{  
    "id": "uuid",    "embedding": [float] * 384,  // all-MiniLM-L6-v2    "document": "JSON serialized attack details",    "metadata": {        "target_os": "linux|windows|unknown",        "services": ["ssh", "http"],        "ports": [22, 80, 443],        "vulnerability_type": "sqli|rce|lfi|etc",        "exploit_method": "sqlmap",        "tools_sequence": ["nmap", "gobuster", "sqlmap"],        "success": true,        "access_achieved": "none|user|root",        "time_to_access_minutes": 45,        "session_id": "uuid",        "created_at": "2025-12-01T00:00:00Z"    }}  
```  

### 8.3 File Locations

| Data Type | Location | Purpose |
|-----------|----------|---------|
| Sessions database | `~/.opensploit/sessions.db` | SQLite session storage |
| Pattern vectors | `~/.opensploit/vectors/` | ChromaDB pattern storage |
| Registry cache | `~/.opensploit/registry.yaml` | Tool registry cache |
| Tool outputs | `~/.opensploit/outputs/{session}/` | Large tool output storage (see 3.4.1) |
| Audit log | `~/.opensploit/audit.log` | Security audit trail |
| User config | `~/.config/opensploit/config.json` | User configuration |
| Project config | `./opensploit.yaml` | Project-local overrides |

### 8.4 Data Retention

| Data Type | Default Retention | User Configurable |
|-----------|-------------------|-------------------|
| Session data | Indefinite | Yes - manual deletion |
| Action logs | 90 days | Yes |
| Patterns | Indefinite | Yes - manual deletion |
| Downloaded images | Indefinite | Yes - cleanup command |
| Registry cache | 24 hours (auto-refresh) | No |
| Tool outputs | 24 hours (auto-cleanup) | Yes |  
  
---  

## 9. Security Requirements

### 9.1 Authorization Safeguards

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-SEC-001 | System SHALL warn before scanning non-localhost/non-private IP targets | P0 |  
| REQ-SEC-002 | System SHALL require explicit user confirmation for external targets | P0 |  
| REQ-SEC-003 | System SHALL maintain list of forbidden targets (gov, mil, critical infra) | P0 |  
| REQ-SEC-004 | System SHALL log all scan authorizations for audit purposes | P0 |  
| REQ-SEC-005 | System SHALL display terms of service on first run | P0 |  

### 9.2 Credential Security

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-SEC-010 | API keys SHALL be stored in system keychain where available | P0 |  
| REQ-SEC-011 | API keys SHALL NOT be logged or displayed in plaintext | P0 |  
| REQ-SEC-012 | Discovered credentials SHALL be marked sensitive in findings | P0 |  
| REQ-SEC-013 | Session data SHALL be readable only by owner (600 permissions) | P0 |  

### 9.3 Container Security

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-SEC-020 | Tool containers SHALL run as non-root where possible | P0 |  
| REQ-SEC-021 | Tool containers SHALL have minimal capabilities | P0 |  
| REQ-SEC-022 | Tool containers SHALL NOT have access to Docker socket | P0 |  
| REQ-SEC-023 | Tool containers SHALL use read-only filesystem where possible | P1 |  
| REQ-SEC-024 | Tool images SHALL be signed and verified | P2 |  

### 9.4 Network Security

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-SEC-030 | System SHALL use HTTPS for all external API calls | P0 |  
| REQ-SEC-031 | Cloud pattern sync SHALL use authenticated, encrypted channel | P0 |  
| REQ-SEC-032 | Registry updates SHALL be verified against known checksum | P1 |  
| REQ-SEC-033 | System SHALL NOT send target information to cloud without consent | P0 |  

### 9.5 Audit Logging

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-SEC-040 | System SHALL maintain audit log at ~/.opensploit/audit.log | P0 |  
| REQ-SEC-041 | Audit log SHALL include timestamp, session, action, target, result | P0 |  
| REQ-SEC-042 | Audit log SHALL be append-only | P0 |  
| REQ-SEC-043 | Audit log format SHALL be machine-parseable (JSON lines) | P1 |  

### 9.6 Pre-Scan Safety Check Flow

```  
User: scan example.com  
  
System:  
┌─────────────────────────────────────────────────────────────┐  
│  ⚠️  EXTERNAL TARGET WARNING                                ││                                                             │  
│  You are about to scan: example.com                         │  
│  This is NOT a localhost or private IP address.             │  
│                                                             │  
│  Before proceeding, confirm:                                │  
│  ☐ I have written authorization to test this target         ││  ☐ I understand unauthorized testing is illegal             ││  ☐ I accept full responsibility for this action             ││                                                             │  
│  [Cancel]                              [Proceed with Scan]  │  
└─────────────────────────────────────────────────────────────┘  
```  
  
---  

## 10. User Interface Requirements

### 10.1 Terminal User Interface

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-UI-001 | TUI SHALL be implemented using Solid.js + Ink framework (inherited from OpenCode) | P0 |  
| REQ-UI-002 | TUI SHALL support minimum terminal size of 80x24 | P0 |  
| REQ-UI-003 | TUI SHALL adapt layout to larger terminal sizes | P1 |  
| REQ-UI-004 | TUI SHALL support both light and dark terminal themes | P1 |  
| REQ-UI-005 | TUI SHALL be fully navigable via keyboard | P0 |  

### 10.2 Views

| View | Purpose | Priority |  
|------|---------|----------|  
| Chat View | Main conversation interface with agent | P0 |  
| Progress View | Real-time tool execution status | P0 |  
| Findings View | Categorized vulnerability findings | P0 |  
| Report View | Report generation and preview | P1 |  
| Settings View | Configuration management | P1 |  
| Help View | Command reference and documentation | P1 |  

### 10.3 Command Line Interface

| Command | Purpose | Priority |  
|---------|---------|----------|  
| `opensploit` | Start interactive TUI | P0 |  
| `opensploit scan <target>` | Quick scan with default settings | P0 |  
| `opensploit auth login` | Configure LLM provider credentials | P0 |  
| `opensploit sessions` | List previous sessions | P0 |  
| `opensploit resume <id>` | Resume previous session | P1 |  
| `opensploit report <id>` | Generate report for session | P1 |  
| `opensploit tools` | List available tools | P0 |  
| `opensploit cleanup` | Remove unused Docker images | P0 |  
| `opensploit update` | Update registry and check for updates | P1 |  
| `opensploit version` | Display version information | P0 |  
  
---  

## 11. Deployment Requirements

### 11.1 Installation Methods

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-DEP-001 | System SHALL support one-line installation script | P0 |  
| REQ-DEP-002 | System SHALL support Homebrew installation (macOS/Linux) | P1 |  
| REQ-DEP-003 | System SHALL support `npm install -g` or `bun install -g` for developers | P1 |  
| REQ-DEP-004 | System SHALL provide pre-built binaries for major platforms | P0 |  
| REQ-DEP-005 | Installation SHALL verify Docker availability | P0 |  
| REQ-DEP-006 | Installation SHALL download initial registry | P0 |  

### 11.2 One-Line Installation

```bash  
curl -fsSL https://opensploit.ai/install.sh | sh  
```  

### 11.3 System Requirements

| Tier | RAM | CPU | Disk | Docker |  
|------|-----|-----|------|--------|  
| Minimum (Low) | 4 GB | 2 cores | 10 GB free | Required |  
| Recommended (Medium) | 8 GB | 4 cores | 20 GB free | Required |  
| Optimal (High) | 16+ GB | 6+ cores | 50+ GB free | Required |  

### 11.4 External Dependencies

| Dependency | Required | Purpose | Installation |  
|------------|----------|---------|--------------|  
| Docker Engine | Yes | Tool containerization | User installs separately |  
| Git | No | Source installation | Optional |  
| Go 1.21+ | No | Building from source | Optional |  
| Ollama | No | Local LLM | Optional |  

### 11.5 Update Mechanism

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-DEP-010 | System SHALL check for updates on startup (with user consent) | P1 |  
| REQ-DEP-011 | System SHALL support in-place binary updates | P1 |  
| REQ-DEP-012 | Tool images SHALL update independently of core | P0 |  
| REQ-DEP-013 | Registry SHALL auto-update if stale (>24 hours) | P0 |  
  
---  

## 12. Testing Requirements

### 12.1 Unit Testing

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-TST-001 | Core agent logic SHALL have 80%+ code coverage | P0 |  
| REQ-TST-002 | MCP client SHALL have comprehensive protocol tests | P0 |  
| REQ-TST-003 | Memory system SHALL have CRUD operation tests | P0 |  
| REQ-TST-004 | Each MCP server SHALL have method-level tests | P0 |  
| REQ-TST-005 | Tool parsers SHALL have tests with fixture data | P0 |  

### 12.2 Integration Testing

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-TST-010 | Agent-to-tool communication SHALL be tested end-to-end | P0 |  
| REQ-TST-011 | Docker container lifecycle SHALL be tested | P0 |  
| REQ-TST-012 | Registry fetch and cache SHALL be tested | P0 |  
| REQ-TST-013 | LLM provider switching SHALL be tested | P1 |  

### 12.3 End-to-End Testing

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-TST-020 | System SHALL be tested against DVWA | P0 |  
| REQ-TST-021 | System SHALL be tested against Metasploitable | P1 |  
| REQ-TST-022 | System SHALL be tested against HackTheBox Starting Point | P1 |  
| REQ-TST-023 | Full assessment workflow SHALL complete without errors | P0 |  

### 12.4 Performance Testing

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-TST-030 | System SHALL be tested on minimum hardware (4GB RAM) | P0 |  
| REQ-TST-031 | Memory usage SHALL be profiled under load | P1 |  
| REQ-TST-032 | Container startup time SHALL be benchmarked | P1 |  
| REQ-TST-033 | Large session handling (1000+ findings) SHALL be tested | P1 |

### 12.5 Trajectory & Reasoning Evaluation

> **Note:** Traditional testing evaluates final outputs (did the scan complete?). Trajectory evaluation tests the agent's *reasoning process* - the chain of thoughts, decisions, and tool selections that led to the output. This is essential for improving agent reliability.

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| REQ-TST-040 | System SHALL record agent reasoning trajectories during execution | P0 |
| REQ-TST-041 | Trajectories SHALL include: thought, verification, action, observation for each step | P0 |
| REQ-TST-042 | System SHALL maintain a Golden Test Set of expected reasoning patterns | P0 |
| REQ-TST-043 | Golden Test Set SHALL cover common pentest scenarios (web app, network, priv-esc) | P0 |
| REQ-TST-044 | Trajectory tests SHALL evaluate tool selection decisions against expected choices | P0 |
| REQ-TST-045 | Trajectory tests SHALL flag anti-patterns (curl over-reliance, custom code attempts) | P1 |
| REQ-TST-046 | System SHALL generate trajectory evaluation reports comparing actual vs expected | P1 |
| REQ-TST-047 | Trajectories SHALL be exportable for training data collection | P0 |

**Golden Test Set Structure:**

```yaml
golden_tests:
  - id: "web-app-sqli-001"
    scenario: "Login form SQL injection"
    context:
      phase: enumeration
      discovered:
        - "HTTP service on port 80"
        - "Login form at /login"
        - "POST to /api/auth with username and password"

    expected_trajectory:
      - thought: "Login form detected with POST endpoint - should test for SQL injection"
        verify: "Using sqlmap is appropriate for automated SQLi testing"
        action: "tool_registry_search for SQL injection tools"
        expected_tool: "sqlmap"

      - thought: "Found sqlmap - will test the login form POST endpoint"
        action: "mcp_tool sqlmap.test_url"
        expected_params:
          url: "/api/auth"
          data: "username=test&password=test"

    anti_patterns:
      - pattern: "curl with SQL payloads in POST data"
        reason: "Should use sqlmap for comprehensive SQLi testing"
      - pattern: "Writing custom Python exploit"
        reason: "Should use existing MCP tools"

  - id: "priv-esc-suid-001"
    scenario: "SUID binary privilege escalation"
    context:
      phase: post_exploitation
      discovered:
        - "User shell on target"
        - "SUID binary /usr/bin/custom_app"

    expected_trajectory:
      - thought: "Need to enumerate privilege escalation vectors"
        action: "mcp_tool privesc.enumerate"

      - thought: "SUID binary found - should research known exploits"
        action: "mcp_tool cve-lookup.search or searchsploit"
```

**Trajectory Evaluation Metrics:**

| Metric | Description | Target |
|--------|-------------|--------|
| Tool Selection Accuracy | % of correct tool choices vs golden test | ≥85% |
| Anti-Pattern Rate | % of decisions flagged as anti-patterns | ≤10% |
| Phase Appropriateness | % of tools appropriate for current phase | ≥90% |
| Reasoning Coherence | Thought → Action logical consistency score | ≥0.8 |

---

## 13. Resource Management Requirements

### 13.1 Resource Tier Definitions

| Tier | RAM | Cores | Max Containers | Container Memory | Idle Timeout |  
|------|-----|-------|----------------|------------------|--------------|  
| LOW | ≤8 GB | ≤4 | 1 | 1 GB | 30 seconds |  
| MEDIUM | 8-16 GB | 4-6 | 3 | 2 GB | 120 seconds |  
| HIGH | ≥16 GB | ≥6 | 6 | 4 GB | 300 seconds |  

### 13.2 Adaptive Execution

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-RES-001 | System SHALL detect hardware resources at startup | P0 |  
| REQ-RES-002 | System SHALL assign resource tier based on detection | P0 |  
| REQ-RES-003 | System SHALL allow user to override resource tier | P1 |  
| REQ-RES-004 | System SHALL adapt scan strategy to resource tier | P0 |  
| REQ-RES-005 | LOW tier SHALL use sequential execution only | P0 |  
| REQ-RES-006 | MEDIUM/HIGH tiers SHALL support parallel execution | P0 |  
| REQ-RES-007 | System SHALL monitor memory pressure during execution | P0 |  
| REQ-RES-008 | System SHALL cleanup containers when memory pressure is high | P0 |  

### 13.3 Storage Management

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-RES-010 | System SHALL check available disk before image pull | P0 |  
| REQ-RES-011 | System SHALL warn when disk space is below 1 GB | P0 |  
| REQ-RES-012 | System SHALL provide cleanup command for unused images | P0 |  
| REQ-RES-013 | System SHALL track per-tool disk usage | P1 |  

### 13.4 Tool Image Sizes (Estimates)

| Tool | Estimated Size | Notes |  
|------|----------------|-------|  
| nmap | ~95 MB | Base scanner |  
| gobuster | ~50 MB | Go binary |  
| ffuf | ~50 MB | Go binary |  
| nikto | ~100 MB | Perl + databases |  
| whatweb | ~80 MB | Ruby + plugins |  
| sqlmap | ~120 MB | Python + tampers |  
| hydra | ~80 MB | C binary + libs |  
| wpscan | ~150 MB | Ruby + DB |  
| metasploit | ~2 GB | Full framework |  
| john | ~100 MB | With wordlists |  
  
---  

## 14. Maintenance & Support Requirements

### 14.1 Documentation

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-MNT-001 | Project SHALL maintain comprehensive README | P0 |  
| REQ-MNT-002 | Project SHALL maintain CONTRIBUTING guide | P0 |  
| REQ-MNT-003 | Project SHALL maintain architecture documentation | P0 |  
| REQ-MNT-004 | Each tool SHALL have usage documentation | P0 |  
| REQ-MNT-005 | API interfaces SHALL be documented | P0 |  
| REQ-MNT-006 | Documentation site SHALL be maintained at docs.opensploit.ai | P1 |  

### 14.2 Community Support

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-MNT-010 | Project SHALL maintain Discord server for community support | P0 |  
| REQ-MNT-011 | Project SHALL use GitHub Issues for bug tracking | P0 |  
| REQ-MNT-012 | Project SHALL use GitHub Discussions for feature requests | P0 |  
| REQ-MNT-013 | Project SHALL respond to critical bugs within 48 hours | P1 |  

### 14.3 Release Management

| Req ID | Requirement | Priority |  
|--------|-------------|----------|  
| REQ-MNT-020 | Project SHALL follow semantic versioning | P0 |  
| REQ-MNT-021 | Project SHALL maintain CHANGELOG | P0 |  
| REQ-MNT-022 | Releases SHALL include release notes | P0 |  
| REQ-MNT-023 | Breaking changes SHALL be documented in major versions | P0 |  
  
---  

## 15. Acceptance Criteria

### 15.1 MVP Acceptance Criteria

The Minimum Viable Product SHALL be considered complete when:

1. ✅ One-command installation works on Ubuntu 22.04 and macOS 12+
2. ✅ Agent can conduct autonomous reconnaissance of a target
3. ✅ At least 6 core tools are integrated (nmap, gobuster, ffuf, nikto, whatweb, sqlmap)
4. ✅ Agent transitions between phases automatically
5. ✅ Findings are stored and categorized by severity
6. ✅ Basic Markdown reports can be generated
7. ✅ Session data persists across restarts
8. ✅ Works with Ollama (local) and at least one cloud LLM provider
9. ✅ Resource tier detection and adaptation works
10. ✅ Documentation covers installation and basic usage

### 15.2 Beta Release Criteria

1. ✅ All MVP criteria met
2. ✅ 10+ tools integrated
3. ✅ Pattern storage and retrieval working
4. ✅ Professional report templates available
5. ✅ Tested against DVWA, Metasploitable
6. ✅ 500+ GitHub stars
7. ✅ Active Discord community (100+ members)

### 15.3 Production Release Criteria

1. ✅ All Beta criteria met
2. ✅ 20+ tools integrated
3. ✅ Cloud pattern sync available (paid tier)
4. ✅ 80%+ test coverage on critical paths
5. ✅ Security audit completed
6. ✅ 1000+ GitHub stars
7. ✅ First paying customers

---

## 16. Agent Reasoning Architecture

> **Context:** Penetration testing requires more than tool execution - it requires strategic reasoning about attack paths, adaptation to findings, and methodical exploration. This section defines the reasoning framework agents must follow.

### 16.1 Structured Reasoning Framework (ReAct-Style)

Agents SHALL follow a structured reasoning process inspired by the ReAct (Reasoning + Acting) pattern, enhanced with verification steps.

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| REQ-RSN-001 | Agents SHALL use explicit structured reasoning for each decision | P0 |
| REQ-RSN-002 | Reasoning SHALL follow the TVAR pattern: Thought → Verify → Action → Result | P0 |
| REQ-RSN-003 | Agents SHALL NOT invoke tools without preceding reasoning step | P0 |
| REQ-RSN-004 | Verification step SHALL check tool appropriateness before invocation | P0 |
| REQ-RSN-005 | Result step SHALL analyze tool output before next reasoning cycle | P0 |

**TVAR Reasoning Pattern:**

```
<thought>
What am I trying to accomplish? What have I learned so far?
- Current objective: [specific goal]
- Relevant findings: [from previous steps]
- Possible approaches: [options considered]
</thought>

<verify>
Is this the right approach?
- Tool selection: [why this tool over alternatives]
- Phase appropriateness: [is this tool suitable for current phase]
- Anti-pattern check: [am I falling into known bad patterns]
</verify>

<action>
tool_registry_search or mcp_tool invocation
</action>

<result>
What did I learn?
- Key findings: [extracted information]
- Next steps: [what this enables]
- Adjustments: [if approach needs changing]
</result>
```

### 16.2 Strategic Planning

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| REQ-RSN-010 | Agent SHALL create initial attack plan at session start | P0 |
| REQ-RSN-011 | Plan SHALL be updated as new findings emerge | P0 |
| REQ-RSN-012 | Agent SHALL maintain prioritized list of attack vectors to explore | P1 |
| REQ-RSN-013 | Plan changes SHALL be explained with reasoning | P1 |

### 16.3 Failure Recovery & Adaptation

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| REQ-RSN-020 | Agent SHALL analyze tool failures and adapt strategy | P0 |
| REQ-RSN-021 | Agent SHALL NOT repeat identical failed approaches | P0 |
| REQ-RSN-022 | Agent SHALL search for alternative tools/methods after failure | P0 |
| REQ-RSN-023 | Repeated failures SHALL trigger escalation to user for guidance | P1 |

### 16.4 Anti-Pattern Prevention Through Reasoning

Rather than hardcoded guardrails, the reasoning framework naturally prevents anti-patterns through the verification step:

| Anti-Pattern | Verification Check |
|--------------|-------------------|
| curl over-reliance | "Is curl the best tool for this? What specialized tools exist?" |
| Custom exploit code | "Can existing MCP tools accomplish this? Check registry first." |
| Skipping phases | "Have I completed reconnaissance before exploitation?" |
| Tool fixation | "Am I repeatedly using the same tool? Should I try alternatives?" |

### 16.5 Trajectory Recording

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| REQ-RSN-030 | System SHALL record complete reasoning trajectories | P0 |
| REQ-RSN-031 | Trajectories SHALL be stored with session data | P0 |
| REQ-RSN-032 | Trajectories SHALL be exportable in training-compatible format | P0 |
| REQ-RSN-033 | Trajectory format SHALL include timing information | P1 |

**Trajectory Export Schema:**

```json
{
  "session_id": "abc123",
  "target": "10.10.10.1",
  "model": "claude-3-opus",
  "trajectory": [
    {
      "step": 1,
      "timestamp": "2025-12-01T10:00:00Z",
      "phase": "reconnaissance",
      "thought": "Starting pentest. Need to discover open ports first.",
      "verify": "nmap is appropriate for initial port discovery.",
      "action": {
        "type": "mcp_tool",
        "tool": "nmap",
        "method": "port_scan",
        "params": {"target": "10.10.10.1", "ports": "1-1000"}
      },
      "result": {
        "summary": "Found ports 22 (SSH), 80 (HTTP), 443 (HTTPS)",
        "findings": ["port:22:ssh", "port:80:http", "port:443:https"]
      },
      "tokens_used": 1500,
      "duration_ms": 15000
    }
  ],
  "outcome": {
    "success": true,
    "access_achieved": "user",
    "flags_captured": ["user.txt"]
  }
}
```

### 16.6 TVAR Display in User Interface

TVAR reasoning blocks SHALL be visually distinct from regular output, similar to how Claude's extended thinking is displayed as greyed/collapsed content.

**Current Problem:**
- TVAR tags (`<thought>`, `<verify>`, etc.) appear as raw text in output
- Clutters the user interface with verbose reasoning
- Makes it hard to see actual results and findings

**Solution:**
1. Processor parses TVAR blocks and stores as structured `TVARPart`
2. TVAR blocks are stripped from `TextPart` after parsing (avoid duplication)
3. TUI renders `TVARPart` with muted/collapsed styling

```
┌─────────────────────────────────────────────────────────────────┐
│ [+] Reasoning (reconnaissance)                          ← muted │
│                                                                 │
│ Found 3 open ports: 22 (SSH), 80 (HTTP), 443 (HTTPS)           │
│                                                                 │
│ The web server is running Apache 2.4.41 on Ubuntu.             │
│ Next steps: enumerate web directories and check for vulns.     │
└─────────────────────────────────────────────────────────────────┘

Expanded:
┌─────────────────────────────────────────────────────────────────┐
│ [-] Reasoning (reconnaissance)                          ← muted │
│   Thought: I need to discover open ports on the target...      │
│   Verify: nmap is appropriate for port scanning...             │
│   Action: mcp_tool(nmap, port_scan, {...})                     │
│   Result: Discovered 3 open ports...                           │
│                                                                 │
│ Found 3 open ports: 22 (SSH), 80 (HTTP), 443 (HTTPS)           │
└─────────────────────────────────────────────────────────────────┘
```

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| REQ-RSN-034 | TVAR blocks SHALL be parsed from text and stored as structured TVARPart | P0 |
| REQ-RSN-035 | TVAR blocks SHALL be stripped from TextPart after parsing (no duplication) | P0 |
| REQ-RSN-036 | TVARPart SHALL be rendered with muted/collapsed styling in TUI | P0 |
| REQ-RSN-037 | TVARPart SHALL be expandable to show full reasoning details | P1 |
| REQ-RSN-038 | TVAR display SHALL be togglable (show/hide reasoning) | P1 |

---

## 17. Training Data & Model Fine-Tuning

> **Context:** The long-term goal is a pentesting-specialized LLM. This requires collecting high-quality training data from successful engagements. This section defines requirements for training data collection and the path to fine-tuning.

### 17.1 Training Data Collection

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| REQ-TRN-001 | System SHALL collect reasoning trajectories from successful pentests | P0 |
| REQ-TRN-002 | Training data SHALL be opt-in only (explicit user consent required) | P0 |
| REQ-TRN-003 | Collected data SHALL be anonymized (no real target IPs, hostnames, credentials) | P0 |
| REQ-TRN-004 | System SHALL track engagement outcomes for quality filtering | P0 |
| REQ-TRN-005 | Only successful engagements SHALL be used for training | P0 |

### 17.2 Data Quality Requirements

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| REQ-TRN-010 | Training examples SHALL include complete TVAR reasoning chains | P0 |
| REQ-TRN-011 | Examples SHALL demonstrate correct tool selection patterns | P0 |
| REQ-TRN-012 | Examples SHALL NOT include anti-patterns (these go in negative training) | P0 |
| REQ-TRN-013 | Examples SHALL cover diverse scenario types (web, network, priv-esc) | P1 |
| REQ-TRN-014 | Examples SHALL demonstrate proper phase transitions | P1 |

### 17.3 Training Data Sources

| Source | Priority | Volume Estimate | Notes |
|--------|----------|-----------------|-------|
| HackTheBox machine solves | P0 | 50-100 machines | Primary source, diverse scenarios |
| HTB write-up adaptation | P1 | 300+ writeups | Convert to TVAR format |
| PortSwigger labs | P1 | 200+ labs | Web-focused, good for SQLi/XSS |
| VulnHub VMs | P2 | 100+ VMs | Supplementary variety |
| Real engagements (opt-in) | P2 | Variable | Must be anonymized |

### 17.4 Training Data Schema

```yaml
training_example:
  id: "htb-soulmate-001"
  source: "hackthebox"
  difficulty: "medium"
  categories: ["web", "ftp", "cve-exploitation"]

  # Context provided to model
  context:
    target: "soulmate.htb"
    initial_info: "HackTheBox machine at 10.10.10.X"

  # Expected reasoning trajectory (ground truth)
  trajectory:
    - phase: "reconnaissance"
      thought: "Starting with port scan to discover services"
      action: "nmap.port_scan"
      observation: "Found ports 22 (SSH), 80 (HTTP), 2121 (FTP)"

    - phase: "enumeration"
      thought: "Multiple web services detected. Should enumerate each."
      action: "tool_registry_search 'web enumeration'"
      observation: "Found ffuf for directory bruteforce"

    - phase: "enumeration"
      thought: "Will bruteforce directories and check for subdomains"
      action: "ffuf.vhost_fuzz"
      observation: "Found ftp.soulmate.htb subdomain"

    # ... continues through exploitation

  # Outcome for quality filtering
  outcome:
    flags: ["user.txt", "root.txt"]
    time_to_user_shell: "45 minutes"
    key_techniques: ["CVE-2024-4040", "sudo misconfiguration"]
```

### 17.5 Fine-Tuning Strategy

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| REQ-TRN-020 | System SHALL support export to common fine-tuning formats (JSONL, ShareGPT) | P0 |
| REQ-TRN-021 | System SHALL track training data volume by category/phase | P1 |
| REQ-TRN-022 | System SHALL identify gaps in training data coverage | P1 |
| REQ-TRN-023 | Fine-tuning SHALL target open-weight models (Qwen, Llama) | P1 |

**Target Model Candidates:**

| Model | Parameters | License | Tool Use Support | Notes |
|-------|------------|---------|------------------|-------|
| Qwen 2.5-Coder-32B | 32B | Apache 2.0 | Excellent | Primary candidate |
| Llama 3.1-70B | 70B | Llama 3 | Good | Backup option |
| DeepSeek-Coder-V2 | 21B/236B | MIT | Good | Alternative |

### 17.6 Training Volume Estimates

| Phase | Examples Needed | Rationale |
|-------|----------------|-----------|
| Initial Fine-Tune | 5,000-10,000 | Establish base pentesting behavior |
| Phase 2 | 25,000+ | Cover edge cases, diverse scenarios |
| Production | 100,000+ | Robust generalization |

**Conversion Estimate:** 1 HTB writeup ≈ 50-100 training examples (one per reasoning step)

### 17.7 Negative Training Data

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| REQ-TRN-030 | System SHALL collect anti-pattern examples for negative training | P1 |
| REQ-TRN-031 | Negative examples SHALL be labeled with what went wrong | P1 |
| REQ-TRN-032 | Negative examples SHALL include the correct alternative | P1 |

**Negative Example Format:**

```yaml
negative_example:
  context: "Found login form, testing for SQL injection"

  # What the model did (wrong)
  bad_trajectory:
    thought: "Will test SQL injection manually with curl"
    action: "curl.request with SQL payload"

  # Why it's wrong
  issue: "Used general-purpose tool instead of specialized SQLi tool"

  # Correct approach
  correct_trajectory:
    thought: "Login form detected - should use sqlmap for comprehensive SQLi testing"
    action: "sqlmap.test_form"
```

---

## 18. Appendices

### Appendix A: Tool Registry Schema

```yaml  
version: "1.0"  
updated_at: "2025-12-01T00:00:00Z"  
  
# Phase-based tool gating (Section 4.9.3)  
phases:  
  reconnaissance:    required: [nmap]    recommended: [web-fingerprint]    optional: [nuclei]    discouraged:      - tool: curl        reason: "Use web-fingerprint for HTTP reconnaissance"      - tool: sqlmap        reason: "Exploitation tools are premature in recon phase"  enumeration:    required: [ffuf]    recommended: [nikto, nuclei, sqlmap]    optional: [wpscan, web-session]    discouraged:      - tool: curl        reason: "Use specialized enumeration tools"  exploitation:    unlocks_after: [reconnaissance, enumeration]    recommended: [sqlmap, hydra, exploit-runner, ssh]    optional: [metasploit, payload, netcat]  post_exploitation:    unlocks_after: [exploitation]    recommended: [privesc, tunnel, mysql]    optional: [john, payload]  
# Composite workflow tools (Section 4.9.2)  
skills:  
  web-vuln-scan:    description: "Comprehensive web vulnerability assessment"    use_for: "Initial web application security testing"    orchestrates:      - tool: web-fingerprint        purpose: "Identify technology stack"      - tool: nuclei        purpose: "Scan for known CVEs"      - tool: ffuf        purpose: "Directory enumeration"      - tool: sqlmap        purpose: "Test discovered forms for SQLi"        condition: "forms_detected"  
  credential-attack:    description: "Brute force credentials for a service"    use_for: "Attempting to discover valid credentials"    params:      target: { type: string, required: true }      service: { type: enum, values: [ssh, ftp, http-post-form, mysql] }      userlist: { type: string }    orchestrates:      - tool: hydra        purpose: "Execute brute force attack"  
  authenticated-web-test:    description: "Test authenticated web application functionality"    use_for: "Security testing after obtaining credentials"    orchestrates:      - tool: web-session        purpose: "Establish authenticated session"      - tool: ffuf        purpose: "Authenticated directory enumeration"      - tool: sqlmap        purpose: "Test authenticated endpoints"  
tools:  
  nmap:    name: nmap    version: "7.94"    description: "Network scanner for port discovery and service detection"    image: "ghcr.io/opensploit/tools-nmap:latest"    image_size_mb: 95  
    # Tool selection hierarchy (Section 4.9.5)    selection_level: 2  # Specialized tool  
    capabilities:      - port_scanning      - service_detection      - os_fingerprinting      - vulnerability_scanning  
    phases:      - reconnaissance      - enumeration  
    # Tool routing rules (Section 4.9.1)    routing:      use_for:        - "Port scanning and service discovery"        - "OS fingerprinting"        - "Network reconnaissance"      triggers:        - "New target specified"        - "Need to discover open ports"      prefer_over: []  # nmap is the primary recon tool  
    requirements:      network: true      privileged: false  
    resources:      memory_mb: 256      cpu: 0.5  
    methods:      port_scan:        description: "Scan for open ports on a target"        when_to_use: "When discovering services on a target"        params:          target:            type: string            required: true            description: "IP address or hostname"          ports:            type: string            default: "1-1000"            description: "Port range"          scan_type:            type: enum            values: [tcp, syn, udp]            default: tcp        returns:          open_ports:            type: array            items: integer          services:            type: array            items:              type: object              properties:                port: integer                protocol: string                service: string                version: string            service_scan:  
        description: "Identify service versions"        when_to_use: "After port scan to get version info"        params:          target:            type: string            required: true          ports:            type: string            required: true        returns:          services:            type: array  
  # Example: General-purpose tool with routing constraints  curl:    name: curl    version: "8.0"    description: "HTTP client for requests and file transfer"    image: "ghcr.io/opensploit/tools-curl:latest"    image_size_mb: 50  
    # Level 3 = General-purpose (last resort)    selection_level: 3  
    capabilities:      - http_requests      - file_download      - file_upload  
    phases:      - enumeration      - exploitation  
    # Routing constraints to prevent over-reliance    routing:      use_for:        - "One-off HTTP debugging"        - "Custom protocol interactions"        - "File downloads from known URLs"        - "Testing specific endpoints with custom headers"      never_use_for:        - task: "SQL injection testing"          use_instead: sqlmap          reason: "sqlmap provides comprehensive automated SQLi detection and exploitation"        - task: "Session/cookie management"          use_instead: web-session          reason: "web-session maintains state across requests automatically"        - task: "Brute force attacks"          use_instead: hydra          reason: "hydra is optimized for credential attacks with rate limiting"        - task: "Vulnerability scanning"          use_instead: [nuclei, nikto]          reason: "Dedicated scanners have vulnerability signature databases"        - task: "Directory enumeration"          use_instead: ffuf          reason: "ffuf is faster and handles wordlists efficiently"      triggers: []  # No automatic triggers - use specialized tools first      prefer_over: []  # curl should not be preferred over anything  
    methods:      request:        description: "Make HTTP request"        when_to_use: "Only for one-off requests when specialized tools don't apply"        # ... method details```  
  
### Appendix B: MCP Protocol Examples  
  
**Request: Call tool method**  
```json  
{  
    "jsonrpc": "2.0",    "id": 1,    "method": "tools/call",    "params": {        "name": "port_scan",        "arguments": {            "target": "10.10.10.1",            "ports": "1-1000",            "scan_type": "tcp"        }    }}  
```  

**Response: Success**
```json  
{  
    "jsonrpc": "2.0",    "id": 1,    "result": {        "content": [            {                "type": "text",                "text": "{\"open_ports\": [22, 80, 443], \"services\": [{\"port\": 22, \"service\": \"ssh\", \"version\": \"OpenSSH 8.2p1\"}]}"            }        ]    }}  
```  

**Response: Error**
```json  
{  
    "jsonrpc": "2.0",    "id": 1,    "error": {        "code": -32000,        "message": "Scan failed: host unreachable"    }}  
```  

### Appendix C: Configuration File Examples

**User configuration (~/.config/opensploit/config.json)**
```json  
{  
  "$schema": "https://opensploit.ai/config.json",  "provider": {    "ollama": {      "npm": "@ai-sdk/openai-compatible",      "options": {        "baseURL": "http://localhost:11434/v1"      },      "models": {        "llama3:8b": {          "tools": true,          "options": {            "num_ctx": 16384          }        }      }    }  },  "resources": {    "tier": "auto",    "max_containers": 3,    "idle_timeout": 120  },  "reporting": {    "default_format": "markdown",    "include_evidence": true  }}  
```  

**Project configuration (./opensploit.yaml)**
```yaml  
target: 10.10.10.1  
scope:  
  - 10.10.10.0/24exclude:  
  - 10.10.10.254tools:  
  enabled:    - nmap    - gobuster    - sqlmap  disabled:    - metasploitphases:  
  start: reconnaissance  stop_after: enumeration```  
  
### Appendix D: Audit Log Format  
  
```json  
{"timestamp":"2024-12-01T10:00:00Z","session":"abc123","action":"scan_authorized","target":"10.10.10.1","user_confirmed":true}  
{"timestamp":"2024-12-01T10:00:05Z","session":"abc123","action":"tool_call","tool":"nmap","method":"port_scan","params":{"target":"10.10.10.1","ports":"1-1000"},"success":true,"duration_ms":15000}  
{"timestamp":"2024-12-01T10:00:20Z","session":"abc123","action":"finding","type":"port","data":{"port":22,"service":"ssh"}}  
{"timestamp":"2024-12-01T10:00:21Z","session":"abc123","action":"finding","type":"port","data":{"port":80,"service":"http"}}  
{"timestamp":"2024-12-01T10:00:30Z","session":"abc123","action":"phase_change","from":"reconnaissance","to":"enumeration"}  
```  

### Appendix E: Glossary

| Term | Definition |  
|------|------------|  
| MCP | Model Context Protocol - standard for AI tool communication |  
| TUI | Terminal User Interface |  
| Agent | The AI decision-making component |  
| Tool | A containerized security tool (nmap, sqlmap, etc.) |  
| Registry | Metadata about all available tools |  
| Pattern | A successful attack approach stored for reference |  
| Phase | Stage in pentesting (recon, enum, exploit, post) |  
| Finding | Something discovered during testing (port, vuln, etc.) |  
| Session | A complete penetration testing engagement |  
| Resource Tier | Hardware capability classification (LOW, MEDIUM, HIGH) |  
| Skill | A composite workflow tool that orchestrates multiple specialized tools for a common task |  
| Tool Routing | Rules defining when to use specific tools and what alternatives to prefer |  
| Selection Level | Tool hierarchy position (1=Skill, 2=Specialized, 3=General-purpose) |  
| Anti-Pattern | Detected misuse of tools, such as over-relying on general-purpose tools |  
| Nudge | System suggestion to use a more appropriate tool when anti-patterns are detected |  
| Phase Gating | Restricting tool availability based on current pentest phase |  
| Negative Retrieval | RAG technique that surfaces "don't use X" warnings when query matches anti-patterns |
| Selection Level Score | RAG ranking factor that weights specialized tools (Level 1-2) higher than general-purpose (Level 3) |
| Output Store | System for storing large tool outputs externally to prevent context overflow |
| Context Rot | Degradation of agent effectiveness as context fills with raw tool output |
| Output Reference | Unique ID for retrieving externally stored tool output |
| ReAct | Reasoning + Acting - a framework where agents explicitly reason before taking actions |
| TVAR | Thought-Verify-Action-Result - structured reasoning pattern for agent decisions |
| Trajectory | Complete sequence of reasoning steps and actions during an engagement |
| Golden Test Set | Curated set of expected reasoning patterns for evaluating agent behavior |
| Trajectory Evaluation | Testing methodology that evaluates the reasoning process, not just final outputs |
| Fine-Tuning | Training a base LLM on domain-specific data to specialize its behavior |
| Training Example | A single reasoning step with context, thought, action, and observation |
| Negative Training | Training examples that demonstrate what NOT to do, with correct alternatives |
| FARR Flow | Find-Analyze-Research-Remediate methodology used in CIPHER pentesting agent |

---

**Document Control**

| Version | Date | Author | Changes |  
|---------|------|--------|---------|  
| 1.0 | December 2025 | OpenSploit Team | Initial release |  
  
---  

*OpenSploit Technical Requirements Document v1.0*  *opensploit.ai*
