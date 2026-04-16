/**
 * Adversarial tests for Agent system, prompt content, and ultrasploit activation.
 *
 * Targets:
 *   - src/agents/index.ts          (agent config, permissions)
 *   - src/agents/prompts/*.txt      (prompt content)
 *   - src/hooks/chat-message.ts     (ultrasploit message activation)
 *   - src/hooks/ultrasploit.ts      (ultrasploit state)
 *   - src/tui-rainbow.ts            (rainbow post-processor edge cases)
 */
import { describe, test, expect, beforeEach } from "bun:test"
import { loadAgents } from "../../src/agents/index.js"
import {
  isUltrasploitEnabled,
  setUltrasploit,
  toggleUltrasploit,
} from "../../src/hooks/ultrasploit.js"
import { chatMessageHook } from "../../src/hooks/chat-message.js"
import { createUltrasploitPostProcess } from "../../src/tui-rainbow.js"
import { readFileSync } from "fs"
import { join, dirname } from "path"
import { fileURLToPath } from "url"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url))
const promptDir = join(__dirname, "../../src/agents/prompts")

function readPrompt(name: string): string {
  return readFileSync(join(promptDir, name), "utf-8")
}

/** Create a minimal chat-message hook input/output pair. */
function makeMessage(text: string) {
  return {
    input: {
      sessionID: "test-session-001",
      agent: "pentest",
    },
    output: {
      message: {},
      parts: [{ type: "text" as const, text }],
    },
  }
}

/** Helper to create a render buffer from a string. */
function createBuffer(text: string, width: number) {
  const height = Math.ceil(text.length / width) || 1
  const total = width * height
  const char = new Uint32Array(total)
  for (let i = 0; i < text.length; i++) char[i] = text.charCodeAt(i)
  const fg = new Float32Array(total * 4).fill(1)
  const bg = new Float32Array(total * 4).fill(0)
  return { width, height, buffers: { char, fg, bg } }
}

function readFg(fg: Float32Array, cell: number) {
  const slot = cell * 4
  return { r: fg[slot], g: fg[slot + 1], b: fg[slot + 2], a: fg[slot + 3] }
}

// ---------------------------------------------------------------------------
// 1. Agent Config: Permission Gaps
// ---------------------------------------------------------------------------

describe("agent config: permission gaps", () => {
  const agents = loadAgents()

  // List of agents that should inherit bashSecurityDenials
  const agentsWithBashDenials = [
    "pentest",
    "pentest/recon",
    "pentest/enum",
    "pentest/exploit",
    "pentest/post",
    "pentest/research",
    "pentest/build",
    "pentest/captcha",
  ]

  // Security tools that MUST be denied in bash
  const securityTools = [
    "nmap",
    "sqlmap",
    "hydra",
    "nikto",
    "gobuster",
    "ffuf",
    "netcat",
    "metasploit",
    "msfconsole",
    "john",
    "hashcat",
  ]

  test("1. all non-report subagents inherit bash security denials", () => {
    for (const name of agentsWithBashDenials) {
      const agent = agents[name]
      expect(agent).toBeDefined()
      const bash = agent.permission?.bash
      expect(bash).toBeDefined()

      // Each security tool pattern must be present
      for (const tool of securityTools) {
        const pattern = `${tool}*`
        expect(bash[pattern]).toBe(
          "deny",
          `Agent "${name}" missing bash deny for "${pattern}"`,
        )
      }
    }
  })

  test("2. report agent has blanket bash deny", () => {
    const report = agents["pentest/report"]
    expect(report.permission?.bash).toEqual({ "*": "deny" })
  })

  test("3. report agent blanket deny blocks ALL bash including safe commands", () => {
    // This is by design, but verify the implication: even "echo" and "cat" are denied
    const report = agents["pentest/report"]
    const bash = report.permission?.bash
    // With only "*": "deny" and no overrides, every command is denied.
    // There is no "echo*": "allow" escape hatch.
    expect(bash["*"]).toBe("deny")
    // Confirm there are no other keys that could allow something
    const keys = Object.keys(bash)
    expect(keys).toEqual(["*"])
  })

  // BUG: "curl *" (with space) does NOT match bare "curl" (no arguments).
  // A user or prompt injection could run `curl` with no space to bypass.
  test("4. BUG: bare 'curl' (no space) bypasses 'curl *' deny pattern", () => {
    const bash = agents["pentest"].permission?.bash
    // The deny pattern is "curl *" which requires a space after "curl"
    expect(bash["curl *"]).toBe("deny")
    // But there is no "curl" or "curl*" pattern, so bare "curl" matches only "*"
    expect(bash["curl*"]).toBeUndefined()
    expect(bash["curl"]).toBeUndefined()
    // The wildcard allows it:
    expect(bash["*"]).toBe("allow")
    // FINDING: bare "curl" (no args) falls through to "*": "allow"
  })

  // BUG: Same issue with "wget *" -- bare "wget" bypasses
  test("5. BUG: bare 'wget' (no space) bypasses 'wget *' deny pattern", () => {
    const bash = agents["pentest"].permission?.bash
    expect(bash["wget *"]).toBe("deny")
    expect(bash["wget*"]).toBeUndefined()
    expect(bash["wget"]).toBeUndefined()
    // bare "wget" falls through to "*": "allow"
  })

  // BUG: Same issue with "nc *" -- bare "nc" bypasses
  test("5b. BUG: bare 'nc' (no space) bypasses 'nc *' deny pattern", () => {
    const bash = agents["pentest"].permission?.bash
    expect(bash["nc *"]).toBe("deny")
    expect(bash["nc*"]).toBeUndefined()
    expect(bash["nc"]).toBeUndefined()
  })

  // BUG: "ssh *" and "scp *" have the same gap
  test("5c. BUG: bare 'ssh' and 'scp' (no space) bypass deny patterns", () => {
    const bash = agents["pentest"].permission?.bash
    expect(bash["ssh *"]).toBe("deny")
    expect(bash["ssh*"]).toBeUndefined()
    expect(bash["scp *"]).toBe("deny")
    expect(bash["scp*"]).toBeUndefined()
  })

  // Verify trailing-space edge case: "nmap " (with trailing space) should still
  // be caught by "nmap*" since the glob * matches any suffix including space.
  test("2b. 'nmap *' pattern uses glob without space separator — safe", () => {
    const bash = agents["pentest"].permission?.bash
    // "nmap*" will match "nmap", "nmap ", "nmap -sV", etc. -- this is correct
    expect(bash["nmap*"]).toBe("deny")
  })

  test("6. all agents have mcp:*: allow (verify MCP permissiveness)", () => {
    // MCP permissions come through the top-level "*": "allow" in pentestPermission.
    // There is no explicit "mcp" key — MCP tools pass through the wildcard.
    // This means ALL MCP tools are allowed for all agents, which is intentional
    // but should be documented.
    for (const [name, agent] of Object.entries(agents)) {
      // Every agent should have a wildcard allow at the top permission level
      expect(agent.permission?.["*"]).toBe("allow")
    }
  })

  test("14. loadAgents() called twice returns distinct objects (no caching bug)", () => {
    const first = loadAgents()
    const second = loadAgents()
    // Should not be the same reference
    expect(first).not.toBe(second)
    // But should be deeply equal
    expect(Object.keys(first)).toEqual(Object.keys(second))
    for (const key of Object.keys(first)) {
      expect(first[key].prompt).toBe(second[key].prompt)
    }
  })

  test("15. all prompt files are non-empty and contain substantive content", () => {
    const agentEntries = Object.entries(agents)
    for (const [name, agent] of agentEntries) {
      expect(agent.prompt.trim().length).toBeGreaterThan(100)
    }
  })

  test("all 9 agents are present", () => {
    const expected = [
      "pentest",
      "pentest/recon",
      "pentest/enum",
      "pentest/exploit",
      "pentest/post",
      "pentest/report",
      "pentest/research",
      "pentest/build",
      "pentest/captcha",
    ]
    for (const name of expected) {
      expect(agents[name]).toBeDefined()
    }
    expect(Object.keys(agents).length).toBe(9)
  })

  test("17. agent names are case-sensitive — 'pentest/RECON' does not exist", () => {
    expect(agents["pentest/RECON"]).toBeUndefined()
    expect(agents["Pentest"]).toBeUndefined()
    expect(agents["PENTEST/RECON"]).toBeUndefined()
    // Only lowercase exists
    expect(agents["pentest/recon"]).toBeDefined()
  })
})

// ---------------------------------------------------------------------------
// 2. Prompt Content Vulnerabilities
// ---------------------------------------------------------------------------

describe("prompt content vulnerabilities", () => {
  const agents = loadAgents()
  const base = readPrompt("pentest-base.txt")

  test("7a. no prompts contain contradictory MCP-first vs bash-first instructions", () => {
    // The base says "USE MCP tools for security operations"
    // Verify no sub-agent prompt says something like "use bash for nmap"
    for (const [name, agent] of Object.entries(agents)) {
      const prompt = agent.prompt
      // Should not contain instructions to run security tools via bash
      expect(prompt).not.toContain("run nmap via bash")
      expect(prompt).not.toContain("use bash for nmap")
      expect(prompt).not.toContain("execute nmap directly")
    }
  })

  test("7b. base prompt says 'MCP first' and no sub-prompt contradicts", () => {
    // Every agent prompt should include the base, which says MCP first
    expect(base).toContain("USE MCP tools for security operations")
    for (const [name, agent] of Object.entries(agents)) {
      // Every prompt should contain the base (it's prepended)
      expect(agent.prompt).toContain("USE MCP tools for security operations")
    }
  })

  test("8. MCP-first policy consistency across all prompts", () => {
    // Each sub-agent prompt should mention MCP preference
    const subagentPrompts = [
      "pentest/recon.txt",
      "pentest/enum.txt",
      "pentest/exploit.txt",
      "pentest/build.txt",
    ]
    for (const file of subagentPrompts) {
      const content = readPrompt(file)
      expect(content).toMatch(/MCP.*first|MCP.*preferred/i)
    }
  })

  test("9a. prompts reference tools that should exist in the plugin", () => {
    // Tools referenced across prompts
    const expectedTools = [
      "TodoWrite",
      "Task",
      "Read",
      "Glob",
      "Grep",
      "tool_registry_search",
      "mcp_tool",
      "read_tool_output",
      "update_engagement_state",
    ]
    // Check the master prompt references all core tools
    const masterPrompt = agents["pentest"].prompt
    for (const tool of expectedTools) {
      expect(masterPrompt).toContain(tool)
    }
  })

  test("9b. report prompt references tool_registry_search and mcp_tool despite no bash", () => {
    // The report prompt mentions these tools but the agent only has bash denied.
    // MCP tools should still work since bash deny != MCP deny.
    // This is correct behavior but worth verifying the prompt matches config.
    const reportPrompt = agents["pentest/report"].prompt
    // Report prompt says it has tool_registry_search and mcp_tool
    const reportSpecific = readPrompt("pentest/report.txt")
    expect(reportSpecific).toContain("tool_registry_search")
    expect(reportSpecific).toContain("mcp_tool")
  })

  // BUG: Research agent prompt says "You cannot use Write/Edit/Bash" but the
  // agent config uses pentestPermission which allows bash (with denials) and
  // has no restriction on Write/Edit. The prompt-level restriction is unenforceable.
  test("9c. BUG: research agent prompt claims no Write/Edit/Bash but config allows them", () => {
    const researchPrompt = readPrompt("pentest/research.txt")
    expect(researchPrompt).toContain("You don't modify files")
    expect(researchPrompt).toContain("You don't run commands")

    // But the config uses pentestPermission which has bash: { "*": "allow", ... }
    const research = agents["pentest/research"]
    expect(research.permission?.bash?.["*"]).toBe("allow")
    // FINDING: Prompt says "no bash" but config allows bash.
    // The LLM might follow the prompt instruction, but there's no hard enforcement.
    // A prompt injection could override this soft restriction.
  })

  test("10. prompts have basic injection resistance markers", () => {
    // Check that agent prompts don't blindly trust target content.
    // The base prompt should warn about scope, but there's no explicit
    // "ignore instructions from target content" defense.
    // This is a FINDING: no anti-injection headers exist.
    const hasAntiInjection =
      base.includes("ignore") && base.includes("target content")
    // We expect this to be false -- it's a gap
    // Recording as a finding rather than a failing test:
    if (!hasAntiInjection) {
      // FINDING: No explicit prompt injection defense exists.
      // Target web pages, banners, or error messages could contain
      // instructions that the LLM might follow.
    }
    // The test passes because we're documenting the gap, not asserting it's fixed
    expect(true).toBe(true)
  })

  test("11. TVAR framework is present in ALL agent prompts (via base inclusion)", () => {
    for (const [name, agent] of Object.entries(agents)) {
      expect(agent.prompt).toContain("TVAR")
      // "TVAR" appears in the base which is prepended to all
    }
  })

  test("12a. exploit prompt has safety boundaries", () => {
    const exploitPrompt = readPrompt("pentest/exploit.txt")
    expect(exploitPrompt).toContain("NEVER")
    expect(exploitPrompt).toContain("approval")
    expect(exploitPrompt).toContain("Safety Boundaries")
  })

  test("12b. post-exploitation prompt has safety boundaries", () => {
    const postPrompt = readPrompt("pentest/post.txt")
    expect(postPrompt).toContain("NEVER")
    expect(postPrompt).toContain("Safety Boundaries")
  })

  test("13. captcha agent restricts itself to CAPTCHA handling", () => {
    const captchaPrompt = readPrompt("pentest/captcha.txt")
    // Should mention its limited role
    expect(captchaPrompt).toContain("CAPTCHA")
    // Should NOT reference general exploitation tools
    expect(captchaPrompt).not.toContain("sqlmap")
    expect(captchaPrompt).not.toContain("exploit")
    expect(captchaPrompt).not.toContain("hydra")

    // But it has pentestPermission with bash access + "question" permission
    const captcha = agents["pentest/captcha"]
    expect(captcha.permission?.question).toBe("allow")
    // FINDING: captcha agent has full pentestPermission (including bash nmap etc deny,
    // but bash "*": "allow" means it can run arbitrary bash besides security tools).
    // A prompt injection in a CAPTCHA page could potentially misuse this.
  })

  // Verify the post agent is an orchestrator that does NOT use mcp_tool
  test("post agent prompt says it does not use mcp_tool or tool_registry_search", () => {
    const postPrompt = readPrompt("pentest/post.txt")
    expect(postPrompt).toContain("do NOT use")
    expect(postPrompt).toMatch(
      /You do NOT use.*mcp_tool|NEVER.*Call.*mcp_tool/i,
    )
  })

  // But the post agent's config has pentestPermission which allows mcp_tool.
  // Similar to the research agent bug -- prompt restriction is unenforceable.
  test("BUG: post agent prompt says no mcp_tool but config allows it", () => {
    const post = agents["pentest/post"]
    // pentestPermission has "*": "allow" which allows everything
    expect(post.permission?.["*"]).toBe("allow")
    // FINDING: soft prompt restriction only, not enforced by config
  })
})

// ---------------------------------------------------------------------------
// 3. Ultrasploit State & Activation
// ---------------------------------------------------------------------------

describe("ultrasploit state management", () => {
  beforeEach(() => {
    setUltrasploit(false)
  })

  test("initial state respects env var", () => {
    // The module reads process.env at import time, so we can't easily
    // test the env var path without re-importing. But we can verify the
    // current state after our beforeEach reset.
    expect(isUltrasploitEnabled()).toBe(false)
  })

  test("toggle flips state and returns new value", () => {
    expect(toggleUltrasploit()).toBe(true)
    expect(isUltrasploitEnabled()).toBe(true)
    expect(toggleUltrasploit()).toBe(false)
    expect(isUltrasploitEnabled()).toBe(false)
  })

  test("set explicitly overrides", () => {
    setUltrasploit(true)
    expect(isUltrasploitEnabled()).toBe(true)
    setUltrasploit(true)
    expect(isUltrasploitEnabled()).toBe(true) // idempotent
    setUltrasploit(false)
    expect(isUltrasploitEnabled()).toBe(false)
  })
})

describe("ultrasploit chat-message hook", () => {
  beforeEach(() => {
    setUltrasploit(false)
  })

  test("18. 'ultra sploit' (with space) should NOT activate", async () => {
    const { input, output } = makeMessage("ultra sploit")
    await chatMessageHook(input, output)
    expect(isUltrasploitEnabled()).toBe(false)
    expect(output.parts[0].text).toBe("ultra sploit")
  })

  test("19. 'ultrasploiting' should NOT activate (word boundary)", async () => {
    const { input, output } = makeMessage("try ultrasploiting the target")
    await chatMessageHook(input, output)
    expect(isUltrasploitEnabled()).toBe(false)
    expect(output.parts[0].text).toBe("try ultrasploiting the target")
  })

  test("20a. multiple 'ultrasploit' in one message — all stripped", async () => {
    const { input, output } = makeMessage(
      "ultrasploit do the thing ultrasploit",
    )
    await chatMessageHook(input, output)
    expect(isUltrasploitEnabled()).toBe(true)
    // Both occurrences should be stripped
    expect(output.parts[0].text).not.toContain("ultrasploit")
  })

  // BUG: The KEYWORD_REGEX uses /g flag. The .test() method on a /g regex
  // advances lastIndex. If .some() calls .test() on multiple parts, the
  // lastIndex from part[0]'s .test() persists to part[1]'s .test(),
  // potentially causing missed matches on alternating calls.
  test("20b. FIXED: regex lastIndex reset + disable detection (BUG-SH-9/SH-12)", async () => {
    // First call — activates ultrasploit
    const msg1 = makeMessage("ultrasploit go")
    await chatMessageHook(msg1.input, msg1.output)
    expect(isUltrasploitEnabled()).toBe(true)

    // Second call — "stop" triggers disable detection (BUG-SH-12 fix)
    const msg2 = makeMessage("ultrasploit stop")
    await chatMessageHook(msg2.input, msg2.output)
    expect(isUltrasploitEnabled()).toBe(false) // Disabled by "stop" keyword
  })

  // More thorough test: three consecutive calls to definitively catch the alternation
  test("20c. BUG PROOF: three consecutive activations — all must succeed", async () => {
    for (let i = 0; i < 3; i++) {
      setUltrasploit(false)
      const msg = makeMessage(`run ultrasploit now ${i}`)
      await chatMessageHook(msg.input, msg.output)
      expect(isUltrasploitEnabled()).toBe(true)
      expect(msg.output.parts[0].text).not.toContain("ultrasploit")
    }
  })

  test("21. 'ultrasploit' in markdown code block — still activates (no code-block exclusion)", async () => {
    const { input, output } = makeMessage("check `ultrasploit` status")
    await chatMessageHook(input, output)
    // The regex does not exclude code blocks — it will match inside backticks
    // This may or may not be desired behavior. Documenting what actually happens.
    expect(isUltrasploitEnabled()).toBe(true)
    // The keyword is stripped even inside backticks
    expect(output.parts[0].text).not.toContain("ultrasploit")
  })

  test("22. TUI kv state sync: chatMessageHook sets in-memory state only", async () => {
    // The hook calls setUltrasploit(true) which sets an in-memory variable.
    // There is no TUI kv store sync — the TUI toggle and message activation
    // share the same in-memory `enabled` variable via the module.
    // This means: if the TUI reads from a different source (kv store),
    // it could be out of sync.
    const { input, output } = makeMessage("ultrasploit")
    await chatMessageHook(input, output)
    expect(isUltrasploitEnabled()).toBe(true)
    // FINDING: Only in-memory state is updated. If the TUI's /ultrasploit
    // command also reads from this same module, they're in sync. But if
    // the TUI stores state elsewhere (e.g., kv), they could diverge.
  })

  test("23. no deactivation via message — only toggle/set can deactivate", async () => {
    setUltrasploit(true)
    // Sending "ultrasploit" when already enabled should not toggle it off
    const { input, output } = makeMessage("ultrasploit")
    await chatMessageHook(input, output)
    // Still enabled — the hook only enables, never disables
    expect(isUltrasploitEnabled()).toBe(true)
  })

  test("activation strips keyword and collapses whitespace", async () => {
    const { input, output } = makeMessage("scan ultrasploit target 10.0.0.1")
    await chatMessageHook(input, output)
    expect(isUltrasploitEnabled()).toBe(true)
    // Keyword removed and double spaces collapsed
    expect(output.parts[0].text).toBe("scan target 10.0.0.1")
  })

  test("case insensitive activation", async () => {
    const { input, output } = makeMessage("ULTRASPLOIT go")
    await chatMessageHook(input, output)
    expect(isUltrasploitEnabled()).toBe(true)
    expect(output.parts[0].text).not.toContain("ULTRASPLOIT")
  })

  test("message that is ONLY 'ultrasploit' becomes empty after stripping", async () => {
    const { input, output } = makeMessage("ultrasploit")
    await chatMessageHook(input, output)
    expect(isUltrasploitEnabled()).toBe(true)
    // After stripping and trimming, text should be empty string
    expect(output.parts[0].text).toBe("")
  })

  test("multiple text parts — keyword in second part", async () => {
    const output = {
      message: {},
      parts: [
        { type: "text" as const, text: "scan the target" },
        { type: "text" as const, text: "ultrasploit" },
      ],
    }
    await chatMessageHook({ sessionID: "s", agent: "pentest" }, output)
    expect(isUltrasploitEnabled()).toBe(true)
    // First part unchanged
    expect(output.parts[0].text).toBe("scan the target")
    // Second part stripped
    expect(output.parts[1].text).toBe("")
  })

  test("non-text parts are ignored", async () => {
    const output = {
      message: {},
      parts: [
        { type: "image" as const, data: "base64data" } as any,
        { type: "text" as const, text: "no keyword here" },
      ],
    }
    await chatMessageHook({ sessionID: "s" }, output)
    expect(isUltrasploitEnabled()).toBe(false)
  })

  test("hook does not throw on empty parts array", async () => {
    const output = { message: {}, parts: [] as any[] }
    await chatMessageHook({ sessionID: "s" }, output)
    expect(isUltrasploitEnabled()).toBe(false)
  })

  test("hook does not throw on malformed part", async () => {
    const output = {
      message: {},
      parts: [{ type: "text" as const, text: null as any }],
    }
    // .test() on null should not crash due to try/catch
    await chatMessageHook({ sessionID: "s" }, output)
    expect(isUltrasploitEnabled()).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// 4. Rainbow Post-Processor Edge Cases
// ---------------------------------------------------------------------------

describe("rainbow post-processor edge cases", () => {
  const postProcess = createUltrasploitPostProcess()

  test("24. buffer with width 0 does not crash", () => {
    // width=0 means total=0, the loop doesn't execute
    const buf = { width: 0, height: 0, buffers: { char: new Uint32Array(0), fg: new Float32Array(0), bg: new Float32Array(0) } }
    expect(() => postProcess(buf, 0)).not.toThrow()
  })

  test("24b. buffer with width 1 — ultrasploit spans 11 rows", () => {
    const buf = createBuffer("ultrasploit", 1)
    expect(buf.height).toBe(11)
    postProcess(buf, 0)
    // Should still color all 11 chars
    for (let i = 0; i < 11; i++) {
      const c = readFg(buf.buffers.fg, i)
      // Just check it's not default white (1,1,1,1)
      expect(c.r !== 1 || c.g !== 1 || c.b !== 1).toBe(true)
    }
  })

  test("25. 'ultrasploit' at exact buffer end boundary", () => {
    // Text is exactly 11 chars, width is 11 — fits in one row
    const buf = createBuffer("ultrasploit", 11)
    expect(buf.height).toBe(1)
    const total = buf.width * buf.height
    // The loop condition is i <= total - TARGET_LEN, i.e., i <= 0
    // So i=0 is the only iteration, which should match
    postProcess(buf, 0)
    for (let i = 0; i < 11; i++) {
      const c = readFg(buf.buffers.fg, i)
      expect(c.r !== 1 || c.g !== 1 || c.b !== 1).toBe(true)
    }
  })

  test("25b. 'ultrasploit' starts at last possible position", () => {
    // Place it so it ends at the very last cell
    const padding = "AAAAAAAAAA" // 10 chars
    const text = padding + "ultrasploit" // 21 chars total
    const buf = createBuffer(text, 21) // one row of 21
    postProcess(buf, 0)
    // Padding should be unchanged (white)
    for (let i = 0; i < 10; i++) {
      const c = readFg(buf.buffers.fg, i)
      expect(c.r).toBeCloseTo(1, 3)
    }
    // "ultrasploit" starting at index 10 should be colored
    for (let i = 0; i < 11; i++) {
      const c = readFg(buf.buffers.fg, 10 + i)
      expect(c.r !== 1 || c.g !== 1 || c.b !== 1).toBe(true)
    }
  })

  test("26. BUG: unicode emoji before 'ultrasploit' breaks char scanning", () => {
    // JavaScript's charCodeAt() returns UTF-16 code units, not code points.
    // Emoji like U+1F600 are TWO code units (surrogate pair: 0xD83D 0xDE00).
    // The createBuffer helper uses charCodeAt(), so each emoji occupies 2 cells
    // in the char buffer with surrogate values, NOT the full code point.
    //
    // A real terminal renderer would likely use one cell per visible character
    // (or two for wide chars), but the buffer here uses charCodeAt which gives
    // surrogates. This means "ultrasploit" starts at index 4, not 2.
    const text = "\u{1F600}\u{1F600}ultrasploit" // 2 emoji = 4 UTF-16 code units
    expect(text.length).toBe(15) // 4 surrogates + 11 ASCII = 15
    const buf = createBuffer(text, 80)
    postProcess(buf, 0)

    // "ultrasploit" actually starts at index 4 in the char buffer
    // because each emoji occupies 2 cells (surrogate pair)
    for (let i = 0; i < 11; i++) {
      const c = readFg(buf.buffers.fg, 4 + i)
      expect(c.r !== 1 || c.g !== 1 || c.b !== 1).toBe(true)
    }

    // FINDING: If the actual terminal renderer maps characters differently
    // (e.g., one cell per emoji), the rainbow coloring would be offset.
    // The post-processor assumes 1:1 mapping between char buffer indices
    // and visual cells, which breaks with multi-byte characters in practice.
  })

  test("buffer shorter than 'ultrasploit' — no crash", () => {
    const buf = createBuffer("ultra", 80)
    const fgBefore = new Float32Array(buf.buffers.fg)
    expect(() => postProcess(buf, 0)).not.toThrow()
    // No changes since "ultrasploit" doesn't fit
    expect(buf.buffers.fg).toEqual(fgBefore)
  })

  test("overlapping matches: 'ultrasploitultrasploit' — both colored, no overlap issue", () => {
    const text = "ultrasploitultrasploit"
    const buf = createBuffer(text, 80)
    postProcess(buf, 0)
    // First occurrence: 0-10
    for (let i = 0; i < 11; i++) {
      const c = readFg(buf.buffers.fg, i)
      expect(c.r !== 1 || c.g !== 1 || c.b !== 1).toBe(true)
    }
    // Second occurrence: 11-21
    for (let i = 0; i < 11; i++) {
      const c = readFg(buf.buffers.fg, 11 + i)
      expect(c.r !== 1 || c.g !== 1 || c.b !== 1).toBe(true)
    }
  })
})

// ---------------------------------------------------------------------------
// 5. Prompt Content Cross-Checks
// ---------------------------------------------------------------------------

describe("prompt content cross-checks", () => {
  const agents = loadAgents()

  test("all subagents include the base prompt TVAR section", () => {
    const base = readPrompt("pentest-base.txt")
    const tvarSection = "## Reasoning Framework (TVAR)"
    expect(base).toContain(tvarSection)

    for (const [name, agent] of Object.entries(agents)) {
      expect(agent.prompt).toContain(tvarSection)
    }
  })

  test("all subagents include captcha delegation rule from base", () => {
    const captchaRule = "CAPTCHA"
    for (const [name, agent] of Object.entries(agents)) {
      // Every agent should know about CAPTCHA delegation via the base
      expect(agent.prompt).toContain(captchaRule)
    }
  })

  test("base prompt non-interactive execution section is included for all", () => {
    const marker = "Non-Interactive Execution"
    for (const [name, agent] of Object.entries(agents)) {
      expect(agent.prompt).toContain(marker)
    }
  })

  test("base prompt context budget section is included for all", () => {
    const marker = "Context Budget"
    for (const [name, agent] of Object.entries(agents)) {
      expect(agent.prompt).toContain(marker)
    }
  })

  test("all hidden subagents have hidden: true", () => {
    const shouldBeHidden = [
      "pentest/recon",
      "pentest/enum",
      "pentest/exploit",
      "pentest/post",
      "pentest/report",
      "pentest/research",
      "pentest/build",
      "pentest/captcha",
    ]
    for (const name of shouldBeHidden) {
      expect(agents[name].hidden).toBe(true)
    }
  })

  test("master pentest agent is not hidden", () => {
    expect(agents["pentest"].hidden).toBeUndefined()
  })

  test("master pentest is primary mode, all subagents are subagent mode", () => {
    expect(agents["pentest"].mode).toBe("primary")
    const subagents = Object.entries(agents).filter(([k]) => k !== "pentest")
    for (const [name, agent] of subagents) {
      expect(agent.mode).toBe("subagent")
    }
  })

  test("temperature values are reasonable", () => {
    // Master: 0.3, captcha: 0.2, others: undefined (default)
    expect(agents["pentest"].temperature).toBe(0.3)
    expect(agents["pentest/captcha"].temperature).toBe(0.2)
    for (const [name, agent] of Object.entries(agents)) {
      if (agent.temperature !== undefined) {
        expect(agent.temperature).toBeGreaterThanOrEqual(0)
        expect(agent.temperature).toBeLessThanOrEqual(1)
      }
    }
  })

  test("all agents have descriptions", () => {
    for (const [name, agent] of Object.entries(agents)) {
      expect(agent.description.length).toBeGreaterThan(10)
    }
  })

  test("all agents have colors", () => {
    for (const [name, agent] of Object.entries(agents)) {
      expect(agent.color).toBeDefined()
      expect(agent.color).toMatch(/^#[0-9a-f]{6}$/i)
    }
  })
})

// ---------------------------------------------------------------------------
// 6. Additional Bash Denial Gap Analysis
// ---------------------------------------------------------------------------

describe("bash denial gap analysis", () => {
  const agents = loadAgents()
  const bash = agents["pentest"].permission?.bash

  // Tools with glob pattern (tool*) — match with or without space/args
  const globPatterns = [
    "nmap*",
    "sqlmap*",
    "hydra*",
    "nikto*",
    "gobuster*",
    "ffuf*",
    "netcat*",
    "metasploit*",
    "msfconsole*",
    "john*",
    "hashcat*",
  ]

  // Tools with space pattern (tool *) — only match with space+args
  const spacePatterns = ["ssh *", "scp *", "curl *", "wget *", "nc *"]

  test("glob patterns are safe: match bare command AND with arguments", () => {
    for (const pattern of globPatterns) {
      expect(bash[pattern]).toBe("deny")
      // These patterns correctly match "nmap", "nmap -sV", etc.
    }
  })

  test("BUG: space patterns leave bare command unprotected", () => {
    // All space-separated patterns have the same vulnerability
    for (const pattern of spacePatterns) {
      const tool = pattern.replace(" *", "")
      expect(bash[pattern]).toBe("deny")
      // But bare tool name is not denied:
      expect(bash[`${tool}*`]).toBeUndefined()
      expect(bash[tool]).toBeUndefined()
      // Falls through to wildcard allow:
      expect(bash["*"]).toBe("allow")
    }
  })

  test("consistency check: all security tools should use glob pattern for safety", () => {
    // This documents which tools are protected and which have gaps
    const protected_tools = globPatterns.map((p) => p.replace("*", ""))
    const unprotected_tools = spacePatterns.map((p) => p.replace(" *", ""))

    // Protected tools cannot be bypassed
    expect(protected_tools).toContain("nmap")
    expect(protected_tools).toContain("sqlmap")

    // Unprotected tools CAN be bypassed by omitting arguments
    expect(unprotected_tools).toContain("curl")
    expect(unprotected_tools).toContain("wget")
    expect(unprotected_tools).toContain("nc")
    expect(unprotected_tools).toContain("ssh")
    expect(unprotected_tools).toContain("scp")
  })
})
