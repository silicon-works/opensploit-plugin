import { createLog } from "./log"

const log = createLog("tool.phase")

/**
 * Phase gating for penetration testing methodology
 * Warns when agents attempt to skip phases
 */
export namespace PhaseGating {
  /**
   * Penetration testing phases in order
   */
  export const PHASES = [
    "reconnaissance",
    "enumeration",
    "exploitation",
    "post-exploitation",
    "reporting",
  ] as const

  export type Phase = (typeof PHASES)[number]

  /**
   * Track session phases
   */
  const sessionPhases = new Map<string, Set<Phase>>()

  /**
   * Tool to phase mapping
   */
  const TOOL_PHASES: Record<string, Phase> = {
    // Reconnaissance tools
    nmap: "reconnaissance",
    masscan: "reconnaissance",
    "web-fingerprint": "reconnaissance",
    "cve-lookup": "reconnaissance",

    // Enumeration tools
    ffuf: "enumeration",
    gobuster: "enumeration",
    nikto: "enumeration",
    nuclei: "enumeration",
    "enum4linux-ng": "enumeration",
    wpscan: "enumeration",

    // Exploitation tools
    sqlmap: "exploitation",
    nosqlmap: "exploitation",
    hydra: "exploitation",
    metasploit: "exploitation",
    "exploit-runner": "exploitation",
    "lfi-rfi": "exploitation",

    // Post-exploitation tools
    privesc: "post-exploitation",
    ssh: "post-exploitation",
    "shell-session": "post-exploitation",
    mysql: "post-exploitation",
    mongodb: "post-exploitation",
    sqlite: "post-exploitation",
    tunnel: "post-exploitation",

    // Multi-phase tools (state management - allowed in all phases)
    // target-tracker is intentionally omitted - it's a utility tool for all phases
  }

  /**
   * Phase prerequisites - what phases should be completed before starting this one
   */
  const PHASE_PREREQUISITES: Record<Phase, Phase[]> = {
    reconnaissance: [],
    enumeration: ["reconnaissance"],
    exploitation: ["reconnaissance", "enumeration"],
    "post-exploitation": ["exploitation"],
    reporting: ["reconnaissance"],
  }

  /**
   * Get the phase for a tool
   */
  export function getToolPhase(toolName: string): Phase | undefined {
    return TOOL_PHASES[toolName]
  }

  /**
   * Record that a phase has been started for a session
   */
  export function recordPhase(sessionId: string, phase: Phase): void {
    let phases = sessionPhases.get(sessionId)
    if (!phases) {
      phases = new Set()
      sessionPhases.set(sessionId, phases)
    }
    phases.add(phase)
    log.info("phase recorded", { sessionId, phase })
  }

  /**
   * Get completed phases for a session
   */
  export function getCompletedPhases(sessionId: string): Phase[] {
    return Array.from(sessionPhases.get(sessionId) || [])
  }

  /**
   * Check if a phase has been completed
   */
  export function hasCompletedPhase(sessionId: string, phase: Phase): boolean {
    return sessionPhases.get(sessionId)?.has(phase) ?? false
  }

  /**
   * Check if prerequisites for a phase are met
   */
  export function checkPrerequisites(
    sessionId: string,
    phase: Phase
  ): { satisfied: boolean; missing: Phase[] } {
    const prerequisites = PHASE_PREREQUISITES[phase]
    const completed = sessionPhases.get(sessionId) || new Set()
    const missing = prerequisites.filter((p) => !completed.has(p))

    return {
      satisfied: missing.length === 0,
      missing,
    }
  }

  /**
   * Check tool invocation and generate warnings if phases are being skipped
   */
  export function checkToolInvocation(
    sessionId: string,
    toolName: string
  ): { warning?: string; phase?: Phase } {
    const phase = getToolPhase(toolName)

    if (!phase) {
      // Unknown tool phase, no warning
      return {}
    }

    const check = checkPrerequisites(sessionId, phase)

    if (!check.satisfied) {
      const missingStr = check.missing.join(", ")
      const warning = `⚠️  PHASE WARNING: You are attempting to use "${toolName}" (${phase} phase) without completing prior phases.\n\nMissing phases: ${missingStr}\n\nPentesting best practice is to complete phases in order:\n1. Reconnaissance - Identify targets and services\n2. Enumeration - Deep dive into discovered services\n3. Exploitation - Attempt to gain access\n4. Post-Exploitation - Maintain access and gather data\n5. Reporting - Document findings\n\nSkipping phases may cause you to miss vulnerabilities. Proceed with caution.`

      log.warn("phase skip detected", { sessionId, toolName, phase, missing: check.missing })

      return { warning, phase }
    }

    // Record that we're working on this phase
    recordPhase(sessionId, phase)

    return { phase }
  }

  /**
   * Clear session phase data
   */
  export function clearSession(sessionId: string): void {
    sessionPhases.delete(sessionId)
  }

  /**
   * Format phase status for display
   */
  export function formatPhaseStatus(sessionId: string): string {
    const completed = getCompletedPhases(sessionId)

    if (completed.length === 0) {
      return "No phases started"
    }

    const lines = PHASES.map((phase) => {
      const status = completed.includes(phase) ? "✓" : "○"
      return `${status} ${phase.charAt(0).toUpperCase() + phase.slice(1)}`
    })

    return lines.join("\n")
  }
}
