import { describe, expect, test } from "bun:test"
import { loadAgents } from "../../src/agents/index"

describe("agents.loadAgents", () => {
  const agents = loadAgents()
  const agentNames = Object.keys(agents)
  const subagentNames = agentNames.filter((n) => n !== "pentest")

  // --- Structural: catches missing/added agents ---

  test("returns exactly 9 agents", () => {
    expect(agentNames.length).toBe(9)
  })

  test("contains all expected agent names", () => {
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
      expect(agentNames).toContain(name)
    }
  })

  // --- Behavioral: primary vs subagent mode ---

  test("master agent is primary mode", () => {
    expect(agents["pentest"].mode).toBe("primary")
  })

  test("all sub-agents are subagent mode", () => {
    for (const name of subagentNames) {
      expect(agents[name].mode).toBe("subagent")
    }
  })

  test("all sub-agents are hidden", () => {
    for (const name of subagentNames) {
      expect(agents[name].hidden).toBe(true)
    }
  })

  // --- Security-critical: permission rules ---

  test("master agent allows question permission", () => {
    expect(agents["pentest"].permission?.question).toBe("allow")
  })

  test("report agent denies all bash", () => {
    expect(agents["pentest/report"].permission?.bash).toEqual({ "*": "deny" })
  })

  test("non-report agents deny security tools in bash but allow general commands", () => {
    const recon = agents["pentest/recon"]
    expect(recon.permission?.bash?.["*"]).toBe("allow")
    expect(recon.permission?.bash?.["nmap*"]).toBe("deny")
    expect(recon.permission?.bash?.["sqlmap*"]).toBe("deny")
    expect(recon.permission?.bash?.["hydra*"]).toBe("deny")
    expect(recon.permission?.bash?.["ssh *"]).toBe("deny")
    expect(recon.permission?.bash?.["curl *"]).toBe("deny")
  })

  test("session directory is allowed in external_directory permissions", () => {
    const recon = agents["pentest/recon"]
    expect(recon.permission?.external_directory?.["/tmp/opensploit-session-*"]).toBe("allow")
  })

  // --- Integration: prompts load correctly ---

  test("all agents have non-trivial prompts", () => {
    for (const [name, agent] of Object.entries(agents)) {
      expect(agent.prompt.length).toBeGreaterThan(100)
    }
  })

  test("all agents include TVAR reasoning framework from pentest-base", () => {
    for (const agent of Object.values(agents)) {
      expect(agent.prompt).toContain("TVAR")
    }
  })

  test("master prompt contains orchestration keywords", () => {
    const prompt = agents["pentest"].prompt
    expect(prompt).toContain("Master Penetration Testing Agent")
    expect(prompt).toContain("CAPTCHA")
  })

  test("report prompt contains reporting instructions", () => {
    expect(agents["pentest/report"].prompt).toContain("Reporting Subagent")
  })

  // --- Temperature: models that matter ---

  test("captcha agent has low temperature for precision", () => {
    expect(agents["pentest/captcha"].temperature).toBe(0.2)
  })

  test("master agent has low temperature for reliability", () => {
    expect(agents["pentest"].temperature).toBe(0.3)
  })
})
