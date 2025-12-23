<p align="center">
  <a href="https://opensploit.ai">
    <picture>
      <source srcset="packages/console/app/src/asset/logo.svg" media="(prefers-color-scheme: dark)">
      <source srcset="packages/console/app/src/asset/logo.svg" media="(prefers-color-scheme: light)">
      <img src="packages/console/app/src/asset/logo.svg" alt="OpenSploit logo">
    </picture>
  </a>
</p>
<p align="center">The open source offensive cyber security agent.</p>
<p align="center">
  <a href="https://opensploit.ai/discord"><img alt="Discord" src="https://img.shields.io/discord/1391832426048651334?style=flat-square&label=discord" /></a>
  <a href="https://www.npmjs.com/package/opencode-ai"><img alt="npm" src="https://img.shields.io/npm/v/opencode-ai?style=flat-square" /></a>
  <a href="https://github.com/silicon-works/opensploit/actions/workflows/publish.yml"><img alt="Build status" src="https://img.shields.io/github/actions/workflow/status/silicon-works/opensploit/publish.yml?style=flat-square&branch=dev" /></a>
</p>

[![OpenSploit Terminal UI](packages/web/src/assets/lander/screenshot.png)](https://opensploit.ai)

---

### Installation

```bash
# YOLO
curl -fsSL https://opensploit.ai/install | bash

# Package managers
npm i -g opensploit-ai@latest        # or bun/pnpm/yarn
```

> [!TIP]
> Remove versions older than 0.1.x before installing.

### Desktop App (BETA)

OpenSploit is also available as a desktop application. Download directly from the [releases page](https://github.com/silicon-works/opensploit/releases) or [opensploit.ai/download](https://opensploit.ai/download).

| Platform              | Download                                |
| --------------------- | --------------------------------------- |
| macOS (Apple Silicon) | `opensploit-desktop-darwin-aarch64.dmg` |
| macOS (Intel)         | `opensploit-desktop-darwin-x64.dmg`     |
| Windows               | `opensploit-desktop-windows-x64.exe`    |
| Linux                 | `.deb`, `.rpm`, or AppImage             |

#### Installation Directory

The install script respects the following priority order for the installation path:

1. `$OPENSPLOIT_INSTALL_DIR` - Custom installation directory
2. `$XDG_BIN_DIR` - XDG Base Directory Specification compliant path
3. `$HOME/bin` - Standard user binary directory (if exists or can be created)
4. `$HOME/.opensploit/bin` - Default fallback

```bash
# Examples
OPENSPLOIT_INSTALL_DIR=/usr/local/bin curl -fsSL https://opensploit.ai/install | bash
XDG_BIN_DIR=$HOME/.local/bin curl -fsSL https://opensploit.ai/install | bash
```

### Agents

OpenSploit includes two built-in agents you can switch between,
you can switch between these using the `Tab` key.

- **build** - Default, full access agent for development work
- **plan** - Read-only agent for analysis and code exploration
  - Denies file edits by default
  - Asks permission before running bash commands
  - Ideal for exploring unfamiliar codebases or planning changes

Also, included is a **general** subagent for complex searches and multi-step tasks.
This is used internally and can be invoked using `@general` in messages.

Learn more about [agents](https://opensploit.ai/docs/agents).

### Documentation

For more info on how to configure OpenSploit [**head over to our docs**](https://opensploit.ai/docs).

### Contributing

If you're interested in contributing to OpenSploit, please read our [contributing docs](./CONTRIBUTING.md) before submitting a pull request.

### Building on OpenSploit

If you are working on a project that's related to OpenSploit and is using "opensploit" as a part of its name; for example, "opensploit-dashboard" or "opensploit-mobile", please add a note to your README to clarify that it is not built by the OpenSploit team and is not affiliated with us in any way.

### FAQ

#### How is this different than Claude Code?

It's very similar to Claude Code in terms of capability. Here are the key differences:

- 100% open source
- Not coupled to any provider. Although we recommend the models we provide through [OpenSploit Zen](https://opensploit.ai/zen); OpenSploit can be used with Claude, OpenAI, Google or even local models. As models evolve the gaps between them will close and pricing will drop so being provider-agnostic is important.
- Out of the box LSP support
- A focus on TUI. OpenSploit is built by neovim users and the creators of [terminal.shop](https://terminal.shop); we are going to push the limits of what's possible in the terminal.
- A client/server architecture. This for example can allow OpenSploit to run on your computer, while you can drive it remotely from a mobile app. Meaning that the TUI frontend is just one of the possible clients.

---

**Join our community** [Discord](https://discord.gg/opensploit) | [X.com](https://x.com/opensploit)
