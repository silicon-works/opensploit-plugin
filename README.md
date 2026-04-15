# OpenSploit

The autonomous penetration testing plugin for [OpenCode](https://opencode.ai).

OpenSploit turns OpenCode into a penetration testing platform. It provides pentest-specific agents, MCP security tool orchestration, engagement state tracking, and attack methodology — all as a plugin that runs on stock OpenCode.

## What it provides

**10 pentest agents** — Master orchestrator + 8 specialized sub-agents (recon, enum, exploit, post-exploitation, reporting, research, build, captcha). Each follows the TVAR reasoning framework and delegates work through a hierarchical agent system.

**9 custom tools** — MCP tool invocation (Docker containers), tool registry search (RAG), engagement state management, output store, hosts management, browser VNC mode, pattern search/save.

**6 hooks** — Live engagement state injection, session path rewriting, ultrasploit auto-approve, compaction context preservation, trajectory recording, chat message filtering.

**TUI features** — OpenSploit logo, rainbow "ultrasploit" text, sidebar indicator, terminal title override, slash commands.

## Install

Add the plugin to your OpenCode configuration:

```json
// .opencode/opencode.jsonc
{
  "plugin": ["@opensploit/core"]
}
```

```json
// .opencode/tui.json
{
  "plugin": ["@opensploit/core"]
}
```

Or use the full [OpenSploit desktop app](https://github.com/silicon-works/opensploit-app) which comes preconfigured.

## How it works

1. OpenSploit registers pentest agents via the config hook — the default agent becomes `pentest`
2. The master agent orchestrates the engagement, spawning sub-agents for each phase
3. Sub-agents discover and invoke security tools via the MCP tool registry
4. Tools run in Docker containers (nmap, sqlmap, ffuf, hydra, etc.) managed by the container manager
5. Engagement state (ports, credentials, vulnerabilities) is shared across all agents
6. The system.transform hook injects live state into every agent's system prompt

## MCP Security Tools

The security tools run as MCP servers in Docker containers, maintained in a separate repository:

**[silicon-works/mcp-tools](https://github.com/silicon-works/mcp-tools)** — 70+ tools including nmap, sqlmap, ffuf, hydra, metasploit, impacket, netexec, nuclei, nikto, and more.

## Contributing

**Add an agent** — Write a markdown file with YAML frontmatter describing the agent's role, permissions, and prompt. Submit a PR.

**Add a tool** — Write a TypeScript file using the `tool()` API from `@opencode-ai/plugin`. The tool receives a `ToolContext` with session info and returns a string result.

**Add an MCP server** — Fork [mcp-tools](https://github.com/silicon-works/mcp-tools), create a Python MCP server extending `BaseMCPServer`, wrap it in Docker.

**Improve a prompt** — Agent prompts are in `src/agents/prompts/`. Better methodology, more techniques, clearer instructions — all welcome.

## Development

```bash
git clone https://github.com/silicon-works/opensploit-plugin
cd opensploit-plugin
bun install
bun test
```

To test with OpenCode:

```bash
# In your opencode project
echo '{ "plugin": ["file:///path/to/opensploit-plugin/src/index.ts"] }' > .opencode/opencode.jsonc
bun dev
```

## Architecture

```
src/
  index.ts          — Server plugin entry (agents, tools, hooks)
  tui.tsx           — TUI plugin entry (logo, ultrasploit, rainbow)
  agents/           — Agent definitions + prompt files
  tools/            — Custom tools (mcp_tool, registry search, etc.)
  hooks/            — Hook implementations (state injection, path rewriting, etc.)
  memory/           — LanceDB vector search for tool/pattern learning
  pattern/          — Attack pattern capture and search
  container/        — Docker container lifecycle management
  session/          — Session hierarchy and directory management
  training/         — Trajectory recording
  util/             — Target validation, phase gating, output normalizers
```

## License

MIT

Built on [OpenCode](https://opencode.ai) by [Silicon Works Ltd](https://opensploit.ai).
