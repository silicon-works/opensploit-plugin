import { describe, expect, test, beforeEach } from "bun:test"
import { PhaseGating } from "../../src/util/phase-gating"

describe("tool.phase-gating", () => {
  const testSessionId = "test-session-phase-gating"

  // Clean up before each test
  beforeEach(() => {
    PhaseGating.clearSession(testSessionId)
  })

  describe("PHASES", () => {
    test("has correct phase order", () => {
      expect(PhaseGating.PHASES).toEqual([
        "reconnaissance",
        "enumeration",
        "exploitation",
        "post-exploitation",
        "reporting",
      ])
    })
  })

  describe("getToolPhase", () => {
    test("maps reconnaissance tools correctly", () => {
      expect(PhaseGating.getToolPhase("nmap")).toBe("reconnaissance")
      expect(PhaseGating.getToolPhase("masscan")).toBe("reconnaissance")
      expect(PhaseGating.getToolPhase("web-fingerprint")).toBe("reconnaissance")
    })

    test("maps enumeration tools correctly", () => {
      expect(PhaseGating.getToolPhase("ffuf")).toBe("enumeration")
      expect(PhaseGating.getToolPhase("gobuster")).toBe("enumeration")
      expect(PhaseGating.getToolPhase("nikto")).toBe("enumeration")
      expect(PhaseGating.getToolPhase("nuclei")).toBe("enumeration")
    })

    test("maps exploitation tools correctly", () => {
      expect(PhaseGating.getToolPhase("sqlmap")).toBe("exploitation")
      expect(PhaseGating.getToolPhase("hydra")).toBe("exploitation")
      expect(PhaseGating.getToolPhase("metasploit")).toBe("exploitation")
    })

    test("maps post-exploitation tools correctly", () => {
      expect(PhaseGating.getToolPhase("privesc")).toBe("post-exploitation")
      expect(PhaseGating.getToolPhase("shell-session")).toBe("post-exploitation")
      expect(PhaseGating.getToolPhase("ssh")).toBe("post-exploitation")
    })

    test("returns undefined for unknown tools", () => {
      expect(PhaseGating.getToolPhase("unknown-tool")).toBeUndefined()
    })
  })

  describe("recordPhase", () => {
    test("records a phase for a session", () => {
      PhaseGating.recordPhase(testSessionId, "reconnaissance")
      expect(PhaseGating.hasCompletedPhase(testSessionId, "reconnaissance")).toBe(true)
    })

    test("can record multiple phases", () => {
      PhaseGating.recordPhase(testSessionId, "reconnaissance")
      PhaseGating.recordPhase(testSessionId, "enumeration")
      expect(PhaseGating.hasCompletedPhase(testSessionId, "reconnaissance")).toBe(true)
      expect(PhaseGating.hasCompletedPhase(testSessionId, "enumeration")).toBe(true)
    })
  })

  describe("getCompletedPhases", () => {
    test("returns empty array for new session", () => {
      expect(PhaseGating.getCompletedPhases(testSessionId)).toEqual([])
    })

    test("returns completed phases", () => {
      PhaseGating.recordPhase(testSessionId, "reconnaissance")
      PhaseGating.recordPhase(testSessionId, "enumeration")
      const completed = PhaseGating.getCompletedPhases(testSessionId)
      expect(completed).toContain("reconnaissance")
      expect(completed).toContain("enumeration")
    })
  })

  describe("checkPrerequisites", () => {
    test("reconnaissance has no prerequisites", () => {
      const result = PhaseGating.checkPrerequisites(testSessionId, "reconnaissance")
      expect(result.satisfied).toBe(true)
      expect(result.missing).toEqual([])
    })

    test("enumeration requires reconnaissance", () => {
      const result = PhaseGating.checkPrerequisites(testSessionId, "enumeration")
      expect(result.satisfied).toBe(false)
      expect(result.missing).toEqual(["reconnaissance"])
    })

    test("enumeration satisfied after reconnaissance", () => {
      PhaseGating.recordPhase(testSessionId, "reconnaissance")
      const result = PhaseGating.checkPrerequisites(testSessionId, "enumeration")
      expect(result.satisfied).toBe(true)
      expect(result.missing).toEqual([])
    })

    test("exploitation requires recon and enum", () => {
      const result = PhaseGating.checkPrerequisites(testSessionId, "exploitation")
      expect(result.satisfied).toBe(false)
      expect(result.missing).toContain("reconnaissance")
      expect(result.missing).toContain("enumeration")
    })

    test("post-exploitation requires exploitation", () => {
      const result = PhaseGating.checkPrerequisites(testSessionId, "post-exploitation")
      expect(result.satisfied).toBe(false)
      expect(result.missing).toEqual(["exploitation"])
    })
  })

  describe("checkToolInvocation", () => {
    test("returns no warning for recon tool on fresh session", () => {
      const result = PhaseGating.checkToolInvocation(testSessionId, "nmap")
      expect(result.warning).toBeUndefined()
      expect(result.phase).toBe("reconnaissance")
    })

    test("returns warning when skipping to enumeration", () => {
      const result = PhaseGating.checkToolInvocation(testSessionId, "ffuf")
      expect(result.warning).toContain("PHASE WARNING")
      expect(result.warning).toContain("reconnaissance")
      expect(result.phase).toBe("enumeration")
    })

    test("returns warning when skipping to exploitation", () => {
      const result = PhaseGating.checkToolInvocation(testSessionId, "sqlmap")
      expect(result.warning).toContain("PHASE WARNING")
      expect(result.warning).toContain("reconnaissance")
      expect(result.warning).toContain("enumeration")
    })

    test("records phase when used correctly", () => {
      // Start with recon
      PhaseGating.checkToolInvocation(testSessionId, "nmap")
      expect(PhaseGating.hasCompletedPhase(testSessionId, "reconnaissance")).toBe(true)

      // Then enum (should not warn)
      const result = PhaseGating.checkToolInvocation(testSessionId, "ffuf")
      expect(result.warning).toBeUndefined()
      expect(PhaseGating.hasCompletedPhase(testSessionId, "enumeration")).toBe(true)
    })

    test("returns empty for unknown tools", () => {
      const result = PhaseGating.checkToolInvocation(testSessionId, "unknown-tool")
      expect(result.warning).toBeUndefined()
      expect(result.phase).toBeUndefined()
    })
  })

  describe("clearSession", () => {
    test("clears session phase data", () => {
      PhaseGating.recordPhase(testSessionId, "reconnaissance")
      PhaseGating.recordPhase(testSessionId, "enumeration")
      expect(PhaseGating.getCompletedPhases(testSessionId).length).toBe(2)

      PhaseGating.clearSession(testSessionId)
      expect(PhaseGating.getCompletedPhases(testSessionId).length).toBe(0)
    })
  })

  describe("formatPhaseStatus", () => {
    test("returns 'No phases started' for fresh session", () => {
      const status = PhaseGating.formatPhaseStatus(testSessionId)
      expect(status).toBe("No phases started")
    })

    test("shows checkmarks for completed phases", () => {
      PhaseGating.recordPhase(testSessionId, "reconnaissance")
      PhaseGating.recordPhase(testSessionId, "enumeration")
      const status = PhaseGating.formatPhaseStatus(testSessionId)
      expect(status).toContain("✓ Reconnaissance")
      expect(status).toContain("✓ Enumeration")
      expect(status).toContain("○ Exploitation")
    })
  })
})
