# Integration & Manual Test Scenarios

These tests require a running OpenCode instance with the plugin loaded,
Docker daemon, and (for some) network access. They cannot run in CI.

## Prerequisites

```bash
# 1. Stock OpenCode at ../opencode with plugin configured
# 2. Docker daemon running
# 3. MCP tool images available (at least nmap)
docker pull ghcr.io/silicon-works/mcp-tools-nmap:latest
```

## Scenario 1: Plugin Loading

**Goal:** Verify plugin loads in stock OpenCode and registers agents + tools.

```bash
cd ../opencode
bun run --cwd packages/opencode --conditions=browser src/index.ts serve &
sleep 5

# Check agents registered
curl -s http://127.0.0.1:4096/config | python3 -c "
import sys,json; d=json.load(sys.stdin)
print('default_agent:', d.get('default_agent'))
print('plugin:', d.get('plugin'))
"

# Expected:
# default_agent: pentest
# plugin: ['file:///...opensploit-plugin/src/index.ts']

# Check agents via agent list
curl -s http://127.0.0.1:4096/agent | python3 -c "
import sys,json
for a in json.load(sys.stdin):
    if 'pentest' in a['name']:
        print(a['name'], f'({a[\"mode\"]})')
"

# Expected: pentest (primary) + 8 sub-agents (subagent)
```

**Pass criteria:**
- [ ] Plugin loads without errors
- [ ] 9 pentest agents appear (pentest + 8 sub-agents)
- [ ] Default agent is "pentest"
- [ ] No "opencode" or "opensploit" errors in logs

## Scenario 2: MCP Tool Invocation (nmap)

**Goal:** Verify mcp_tool can spawn Docker container and call nmap.

```bash
# Start OpenCode server, then via API:
curl -s http://127.0.0.1:4096/session -X POST -d '{"agent":"pentest"}' | python3 -c "
import sys,json; print(json.load(sys.stdin)['id'])
"

# Send a message that triggers mcp_tool
# (This requires interactive session — use TUI instead)
cd ../opencode && bun dev
# In TUI: type "scan 127.0.0.1 ports 22,80 using nmap"
```

**Pass criteria:**
- [ ] Docker container starts for nmap
- [ ] MCP call returns scan results
- [ ] Container stops after idle timeout
- [ ] No permission errors (mcp_tool should ask)

## Scenario 3: Target Validation

**Goal:** Verify external target warnings appear.

In TUI session:
```
> scan 8.8.8.8 using nmap port_scan
```

**Pass criteria:**
- [ ] Warning about external target displayed
- [ ] Tool still executes (advisory, not blocking)

## Scenario 4: Session Directory

**Goal:** Verify /session/ path translation works.

In TUI session:
```
> write a test file to /session/test.txt
> read /session/test.txt
```

**Pass criteria:**
- [ ] File created at /tmp/opensploit-session-{id}/test.txt
- [ ] Read returns correct content
- [ ] Path rewriting is transparent to the agent

## Scenario 5: Output Store

**Goal:** Verify large outputs are stored externally.

In TUI session:
```
> scan 10.10.10.1 with nmap port_scan ports="1-65535"
```
(Use a target with many open ports to generate large output)

**Pass criteria:**
- [ ] Output exceeding 5000 chars is stored externally
- [ ] Summary with reference ID returned instead
- [ ] `read_tool_output` can retrieve the stored output

## Scenario 6: Engagement State Across Sub-Agents

**Goal:** Verify state.yaml is shared between master and sub-agents.

In TUI session:
```
> pentest 10.10.10.1 target.htb
```
Wait for recon sub-agent to find ports, then check:
```
> read /session/state.yaml
```

**Pass criteria:**
- [ ] state.yaml contains discovered ports
- [ ] Sub-agent received engagement state in its system prompt
- [ ] Subsequent sub-agents see previous discoveries

## Scenario 7: TUI Plugin Features

**Goal:** Verify TUI plugin loads and /ultrasploit command works.

In TUI:
1. Press Ctrl+P to open command palette
2. Search for "ultrasploit"
3. Select "Toggle Ultrasploit mode"

**Pass criteria:**
- [ ] Command appears in palette
- [ ] Toast notification shows toggle state
- [ ] /ultrasploit slash command works

## Scenario 8: Full HTB Box (End-to-End)

**Goal:** Complete penetration test from recon to root.

```bash
cd ../opencode && bun dev
# Select pentest agent
# Type: "pentest 10.10.10.X target.htb"
```

**Pass criteria:**
- [ ] Master agent delegates to recon sub-agent
- [ ] Recon finds open ports via mcp_tool (nmap)
- [ ] Master delegates to enum sub-agent
- [ ] Enum discovers services/directories
- [ ] Master delegates to exploit or research
- [ ] Engagement state accumulates across phases
- [ ] No duplicate scanning (state prevents it)
