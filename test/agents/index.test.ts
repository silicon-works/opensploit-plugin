import { describe, expect, test } from "bun:test"
import { loadAgents } from "../../src/agents/index"

describe("agents.loadAgents", () => {
  const agents = loadAgents()

  test("returns all 10 pentest agents", () => {
    const names = Object.keys(agents)
    expect(names).toContain("pentest")
    expect(names).toContain("pentest/recon")
    expect(names).toContain("pentest/enum")
    expect(names).toContain("pentest/exploit")
    expect(names).toContain("pentest/post")
    expect(names).toContain("pentest/report")
    expect(names).toContain("pentest/research")
    expect(names).toContain("pentest/build")
    expect(names).toContain("pentest/captcha")
    expect(names.length).toBe(9) // 9 keys: pentest + 8 sub-agents
  })

  test("master agent is primary mode", () => {
    expect(agents["pentest"].mode).toBe("primary")
  })

  test("sub-agents are subagent mode", () => {
    for (const name of Object.keys(agents)) {
      if (name === "pentest") continue
      expect(agents[name].mode).toBe("subagent")
    }
  })

  test("sub-agents are hidden", () => {
    for (const name of Object.keys(agents)) {
      if (name === "pentest") continue
      expect(agents[name].hidden).toBe(true)
    }
  })

  test("all agents have prompts", () => {
    for (const [name, agent] of Object.entries(agents)) {
      expect(agent.prompt).toBeTruthy()
      expect(agent.prompt.length).toBeGreaterThan(100)
    }
  })

  test("all agents include pentest-base prompt", () => {
    for (const [name, agent] of Object.entries(agents)) {
      // pentest-base.txt contains TVAR reasoning framework
      expect(agent.prompt).toContain("TVAR")
    }
  })

  test("master agent prompt includes orchestration instructions", () => {
    expect(agents["pentest"].prompt).toContain("pentest")
  })

  test("each agent has a color", () => {
    for (const agent of Object.values(agents)) {
      expect(agent.color).toMatch(/^#[0-9a-fA-F]{6}$/)
    }
  })

  test("each agent has a description", () => {
    for (const agent of Object.values(agents)) {
      expect(agent.description).toBeTruthy()
      expect(agent.description.length).toBeGreaterThan(10)
    }
  })

  test("pentest has question permission allowed", () => {
    expect(agents["pentest"].permission?.question).toBe("allow")
  })

  test("report agent has bash denied", () => {
    const report = agents["pentest/report"]
    expect(report.permission?.bash).toEqual({ "*": "deny" })
  })

  test("non-report agents deny security tools in bash", () => {
    const recon = agents["pentest/recon"]
    expect(recon.permission?.bash?.["nmap*"]).toBe("deny")
    expect(recon.permission?.bash?.["sqlmap*"]).toBe("deny")
    expect(recon.permission?.bash?.["hydra*"]).toBe("deny")
    expect(recon.permission?.bash?.["*"]).toBe("allow")
  })

  test("captcha agent has lower temperature", () => {
    expect(agents["pentest/captcha"].temperature).toBe(0.2)
  })

  test("master agent has standard low temperature", () => {
    expect(agents["pentest"].temperature).toBe(0.3)
  })
})
