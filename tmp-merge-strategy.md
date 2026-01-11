# OpenSploit ← OpenCode Merge Strategy

## Current State

- **Branding commit**: `0a5a8eb4e` - "changed the branding to opensploit"
- **Commits since branding**: 37 (OpenSploit-specific features)
- **Commits behind upstream**: 895
- **Upstream remote**: `upstream` → `https://github.com/sst/opencode.git`

## Change Analysis

### New Files (OpenSploit additions) - NO CONFLICTS EXPECTED
```
packages/opensploit/src/agent/prompt/pentest/*.txt   # Pentest agent prompts
packages/opensploit/src/session/engagement-state.ts  # Engagement tracking
packages/opensploit/src/session/hierarchy.ts         # Sub-agent hierarchy
packages/opensploit/src/session/trajectory.ts        # TVAR training data
packages/opensploit/src/session/tvar-parser.ts       # TVAR parser
packages/opensploit/src/tool/hosts.ts                # /etc/hosts management
packages/opensploit/src/tool/output-store.ts         # Scan output storage
packages/opensploit/src/tool/output-indexer.ts       # RAG indexing
packages/opensploit/src/tool/phase-gating.ts         # Phase enforcement
packages/opensploit/src/tool/anti-pattern.ts         # Anti-pattern detection
packages/opensploit/src/tool/mcp-tool.ts             # MCP tool wrapper
packages/opensploit/src/container/manager.ts         # Docker container mgmt
packages/opensploit/src/cli/cmd/outcome.ts           # Outcome tracking CLI
packages/opensploit/src/cli/cmd/engagement-log.ts    # Engagement log CLI
~30 new files total
```

### Modified Existing Files - POTENTIAL CONFLICTS
```
packages/opensploit/src/agent/agent.ts               # Added pentest agents
packages/opensploit/src/permission/index.ts          # Permission bubbling
packages/opensploit/src/tool/registry.ts             # Tool registry mods
packages/opensploit/src/tool/task.ts                 # Sub-agent spawning
packages/opensploit/src/tool/bash.ts                 # Bash restrictions
packages/opensploit/src/tool/webfetch.ts             # Readability extraction
packages/opensploit/src/session/prompt.ts            # Prompt modifications
packages/opensploit/src/session/processor.ts         # Processor changes
packages/opensploit/src/cli/cmd/tui/routes/session/index.tsx  # TUI changes
~15 modified files total
```

## Merge Strategy

### Step 1: Create a working branch
```bash
git checkout -b merge-upstream
```

### Step 2: Reverse the branding (opensploit → opencode)
Option A - Revert the commit:
```bash
git revert 0a5a8eb4e --no-commit
```

Option B - Script the reverse rename:
```bash
# Rename directory
git mv packages/opensploit packages/opencode
git mv .opensploit .opencode

# Reverse string replacements (sed)
find . -type f \( -name "*.ts" -o -name "*.tsx" -o -name "*.json" -o -name "*.md" \) \
  -exec sed -i 's/opensploit/opencode/g' {} \;

git commit -m "tmp: reverse branding for upstream merge"
```

### Step 3: Merge upstream
```bash
git fetch upstream
git merge upstream/dev --no-commit
# Resolve conflicts (should be minimal - only ~15 files)
git commit -m "merge: upstream opencode changes"
```

### Step 4: Re-apply branding (opencode → opensploit)
Option A - Cherry-pick the original branding commit:
```bash
git cherry-pick 0a5a8eb4e
```

Option B - Script the forward rename:
```bash
git mv packages/opencode packages/opensploit
git mv .opencode .opensploit

find . -type f \( -name "*.ts" -o -name "*.tsx" -o -name "*.json" -o -name "*.md" \) \
  -exec sed -i 's/opencode/opensploit/g' {} \;

git commit -m "rebrand: opencode → opensploit"
```

### Step 5: Verify and squash (optional)
```bash
# Test build
bun install && bun typecheck

# Optionally squash the merge commits
git rebase -i dev  # squash tmp commits
```

## Expected Conflict Resolution

After Step 3, conflicts will be in ~15 files. Resolution approach:

| File | Strategy |
|------|----------|
| `agent/agent.ts` | Keep OpenSploit agent additions, merge upstream agent changes |
| `permission/index.ts` | Keep permission bubbling, merge upstream permission features |
| `tool/task.ts` | Keep sub-agent hierarchy, merge upstream task changes |
| `tool/bash.ts` | Keep security restrictions, merge upstream bash improvements |
| `session/prompt.ts` | Keep pentest prompts, merge upstream prompt changes |
| TUI files | Merge carefully - both have UI changes |

## Notes

- The branding commit `0a5a8eb4e` is clean - proper git renames tracked
- Most OpenSploit work is in NEW files → no conflict
- Modified files are few (~15) → manageable conflict resolution
- 895 upstream commits is large but mechanical rename handling makes it feasible
