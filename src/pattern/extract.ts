/**
 * Pattern Extraction Helpers
 *
 * Implements Doc 13 §Helper Function Implementations (lines 1382-1630)
 *
 * Extracts attack pattern data from engagement state and trajectory.
 * Used by capturePattern() to build AttackPattern records.
 */

import { createLog } from "../util/log"
import type { EngagementState, StateSnapshot } from "../tools/engagement-state"
import type { Trajectory } from "../session/trajectory"
import type { AttackPhase, AttackPattern } from "../memory/schema"

const log = createLog("pattern.extract")

// =============================================================================
// OS Detection
// =============================================================================

/**
 * Detect OS from engagement state
 * Doc 13 §detectOS (lines 1393-1417)
 *
 * Uses service banners, port patterns, and explicit detection.
 */
export function detectOS(state: EngagementState): "linux" | "windows" | "unknown" {
  const ports = state.ports ?? []

  // Check for explicit OS indicators in service versions
  for (const port of ports) {
    const version = port.version?.toLowerCase() ?? ""
    if (
      version.includes("ubuntu") ||
      version.includes("debian") ||
      version.includes("centos") ||
      version.includes("linux") ||
      version.includes("fedora") ||
      version.includes("redhat")
    ) {
      return "linux"
    }
    if (version.includes("windows") || version.includes("microsoft") || version.includes("iis")) {
      return "windows"
    }
  }

  // Heuristic: SMB/RDP typically Windows, SSH typically Linux
  const services = ports.map((p) => p.service?.toLowerCase() ?? "")
  if (services.includes("microsoft-ds") || services.includes("ms-wbt-server") || services.includes("netbios-ssn")) {
    return "windows"
  }
  if (services.includes("ssh") && !services.includes("microsoft-ds")) {
    return "linux"
  }

  return "unknown"
}

// =============================================================================
// Technology Extraction
// =============================================================================

/**
 * Extract technologies from engagement state
 * Doc 13 §extractTechnologies (lines 1419-1465)
 *
 * Parses service banners and vulnerability names.
 */
export function extractTechnologies(state: EngagementState): string[] {
  const technologies = new Set<string>()
  const ports = state.ports ?? []
  const vulnerabilities = state.vulnerabilities ?? []

  // From service versions and banners
  for (const port of ports) {
    const version = port.version?.toLowerCase() ?? ""
    const banner = port.banner?.toLowerCase() ?? ""
    const combined = `${version} ${banner}`

    // Web servers
    if (combined.includes("apache")) technologies.add("apache")
    if (combined.includes("nginx")) technologies.add("nginx")
    if (combined.includes("iis")) technologies.add("iis")
    if (combined.includes("lighttpd")) technologies.add("lighttpd")

    // Languages/frameworks
    if (combined.includes("php")) technologies.add("php")
    if (combined.includes("python")) technologies.add("python")
    if (combined.includes("node") || combined.includes("express")) technologies.add("nodejs")
    if (combined.includes("tomcat")) technologies.add("tomcat")
    if (combined.includes("java") || combined.includes("jboss")) technologies.add("java")
    if (combined.includes("asp.net") || combined.includes("aspnet")) technologies.add("aspnet")

    // CMS
    if (combined.includes("wordpress") || combined.includes("wp-")) technologies.add("wordpress")
    if (combined.includes("drupal")) technologies.add("drupal")
    if (combined.includes("joomla")) technologies.add("joomla")

    // Databases
    if (combined.includes("mysql") || combined.includes("mariadb")) technologies.add("mysql")
    if (combined.includes("postgres")) technologies.add("postgresql")
    if (combined.includes("mssql") || combined.includes("sql server")) technologies.add("mssql")
    if (combined.includes("mongodb")) technologies.add("mongodb")
    if (combined.includes("redis")) technologies.add("redis")
  }

  // From vulnerability names
  for (const vuln of vulnerabilities) {
    const name = vuln.name?.toLowerCase() ?? ""
    if (name.includes("wordpress")) technologies.add("wordpress")
    if (name.includes("php")) technologies.add("php")
    if (name.includes("apache")) technologies.add("apache")
    if (name.includes("tomcat")) technologies.add("tomcat")
    if (name.includes("sql")) technologies.add("sql")
  }

  return Array.from(technologies)
}

// =============================================================================
// Characteristics Inference
// =============================================================================

/**
 * Infer target characteristics from trajectory
 * Doc 13 §inferCharacteristics (lines 1467-1512)
 *
 * Uses Trajectory.Step format to identify patterns like login forms, file uploads.
 */
export function inferCharacteristics(trajectory: Trajectory.Data): string[] {
  const characteristics = new Set<string>()

  for (const step of trajectory.trajectory) {
    // Analyze result text
    const result = step.result?.toLowerCase() ?? ""
    const thought = step.thought?.toLowerCase() ?? ""
    const combined = `${result} ${thought}`

    // Web characteristics
    if (combined.includes("login") || combined.includes("signin") || combined.includes("authentication")) {
      characteristics.add("login_form")
    }
    if (combined.includes("upload") || combined.includes("multipart") || combined.includes("file input")) {
      characteristics.add("file_upload")
    }
    if (combined.includes("api") || combined.includes("json") || combined.includes("rest") || combined.includes("graphql")) {
      characteristics.add("api_endpoint")
    }
    if (combined.includes("wordpress") || combined.includes("wp-content") || combined.includes("wp-admin")) {
      characteristics.add("wp_plugins")
    }
    if (combined.includes("admin") || combined.includes("dashboard") || combined.includes("management")) {
      characteristics.add("admin_panel")
    }

    // Shell characteristics (for privesc patterns)
    const tool = step.toolCall?.tool ?? ""
    if (tool === "ssh" || tool === "shell-session" || tool === "netcat") {
      characteristics.add("user_shell")
    }
    if (combined.includes("sudo") || combined.includes("sudoers")) {
      characteristics.add("sudo_available")
    }
    if (combined.includes("suid") || combined.includes("setuid")) {
      characteristics.add("suid_binaries")
    }
    if (combined.includes("cron") || combined.includes("scheduled")) {
      characteristics.add("cron_jobs")
    }
  }

  return Array.from(characteristics)
}

// =============================================================================
// Vulnerability Type Derivation
// =============================================================================

/**
 * Derive normalized vulnerability type from human-readable name
 * Doc 13 §deriveVulnType (lines 1514-1558)
 */
export function deriveVulnType(name: string): string {
  const normalized = name.toLowerCase()

  // SQL Injection variants
  if (normalized.includes("sql injection") || normalized.includes("sqli") || normalized.includes("blind sql")) return "sqli"

  // Deserialization (check before RCE — "deserialization rce" is more specific)
  if (normalized.includes("deseriali")) return "deserialization"

  // Remote Code Execution
  if (
    normalized.includes("rce") ||
    normalized.includes("remote code") ||
    normalized.includes("command injection") ||
    normalized.includes("os command")
  )
    return "rce"

  // Local/Remote File Inclusion
  if (normalized.includes("lfi") || normalized.includes("local file inclusion")) return "lfi"
  if (normalized.includes("rfi") || normalized.includes("remote file inclusion")) return "rfi"

  // Path Traversal
  if (normalized.includes("path traversal") || normalized.includes("directory traversal")) return "path_traversal"

  // Server-Side Request Forgery
  if (normalized.includes("ssrf") || normalized.includes("server-side request")) return "ssrf"

  // XML External Entity
  if (normalized.includes("xxe") || normalized.includes("xml external")) return "xxe"

  // Cross-Site Scripting
  if (normalized.includes("xss") || normalized.includes("cross-site scripting")) return "xss"

  // Authentication issues
  if (normalized.includes("auth bypass") || normalized.includes("authentication bypass")) return "auth_bypass"
  if (normalized.includes("default cred") || normalized.includes("weak password") || normalized.includes("weak cred"))
    return "weak_auth"

  // File upload
  if (normalized.includes("file upload") || normalized.includes("unrestricted upload")) return "file_upload"

  // SSTI
  if (normalized.includes("ssti") || normalized.includes("template injection")) return "ssti"

  return "unknown"
}

/**
 * Map severity string to CVSS-like score for ranking
 */
export function severityToScore(severity?: string): number {
  switch (severity?.toLowerCase()) {
    case "critical":
      return 9.5
    case "high":
      return 7.5
    case "medium":
      return 5.0
    case "low":
      return 2.5
    default:
      return 0
  }
}

// =============================================================================
// Vulnerability Extraction
// =============================================================================

/**
 * Extract the primary vulnerability that led to access
 * Doc 13 §extractPrimaryVulnerability (lines 1573-1620)
 */
export function extractPrimaryVulnerability(
  state: EngagementState,
  trajectory: Trajectory.Data
): AttackPattern["vulnerability"] {
  const vulnerabilities = state.vulnerabilities ?? []

  // Find exploited vulnerability with highest access gained
  const exploitedVulns = vulnerabilities.filter((v) => v.exploited)

  if (exploitedVulns.length > 0) {
    // Prioritize by access gained, then severity
    const sorted = exploitedVulns.sort((a, b) => {
      const accessOrder: Record<string, number> = { root: 3, user: 2, none: 1 }
      const accessDiff = (accessOrder[b.accessGained ?? "none"] ?? 0) - (accessOrder[a.accessGained ?? "none"] ?? 0)
      if (accessDiff !== 0) return accessDiff
      return severityToScore(b.severity) - severityToScore(a.severity)
    })

    const primary = sorted[0]
    return {
      type: deriveVulnType(primary.name),
      description: primary.name,
      cve: primary.cve,
      cvss: severityToScore(primary.severity),
    }
  }

  // Fallback: infer from trajectory using tool calls
  const exploitTools = ["sqlmap", "metasploit", "exploit-runner", "hydra", "curl", "nuclei"]
  const exploitStep = trajectory.trajectory.find(
    (s) => s.toolCall?.success && s.toolCall?.tool && exploitTools.includes(s.toolCall.tool)
  )

  if (exploitStep) {
    return {
      type: inferVulnTypeFromStep(exploitStep),
      description: `Exploited via ${exploitStep.toolCall?.tool}`,
    }
  }

  return {
    type: "unknown",
    description: "Vulnerability type not captured",
  }
}

/**
 * Infer vulnerability type from trajectory step
 */
function inferVulnTypeFromStep(step: Trajectory.Step): string {
  const tool = step.toolCall?.tool?.toLowerCase() ?? ""
  const result = step.result?.toLowerCase() ?? ""

  if (tool === "sqlmap" || result.includes("sql injection")) return "sqli"
  if (tool === "hydra" || result.includes("credential") || result.includes("password found")) return "weak_auth"
  if (result.includes("lfi") || result.includes("file inclusion")) return "lfi"
  if (result.includes("rce") || result.includes("command execution")) return "rce"

  return "unknown"
}

// =============================================================================
// Pivotal Step Detection
// =============================================================================

/**
 * Detect pivotal steps based on state changes
 * Doc 13 §Pivotal Step Detection (lines 1283-1352)
 *
 * A step is pivotal if it caused a significant breakthrough:
 * - Access level changed (none → user → root)
 * - New validated credentials discovered
 * - Vulnerability successfully exploited
 * - Flag captured
 * - Agent explicitly marked as [PIVOTAL]
 */
export function detectPivotalSteps(
  trajectory: Trajectory.Data,
  stateSnapshots: StateSnapshot[]
): Set<number> {
  const pivotalSteps = new Set<number>()

  // Build a map of stepIndex -> snapshot for O(1) lookup
  const snapshotMap = new Map<number, StateSnapshot>()
  for (const snapshot of stateSnapshots) {
    snapshotMap.set(snapshot.stepIndex, snapshot)
  }

  for (let i = 1; i < trajectory.trajectory.length; i++) {
    const prevSnapshot = snapshotMap.get(i - 1)
    const currSnapshot = snapshotMap.get(i)
    const step = trajectory.trajectory[i]

    // Method 1: Agent marking (in TVAR)
    if (step.thought?.includes("[PIVOTAL]") || step.result?.includes("[PIVOTAL]")) {
      pivotalSteps.add(i)
      continue
    }

    // If we don't have state snapshots, can't do state-based detection
    if (!prevSnapshot || !currSnapshot) continue

    const prevState = prevSnapshot.state
    const currState = currSnapshot.state

    // Access level changed (major breakthrough)
    const prevAccess = prevState.accessLevel ?? "none"
    const currAccess = currState.accessLevel ?? "none"
    if (prevAccess !== currAccess && currAccess !== "none") {
      pivotalSteps.add(i)
      log.debug("pivotal: access level changed", { step: i, from: prevAccess, to: currAccess })
      continue
    }

    // New validated credentials
    const prevCreds = prevState.credentials ?? []
    const currCreds = currState.credentials ?? []
    const newValidatedCreds = currCreds.filter(
      (c) => c.validated && !prevCreds.some((pc) => pc.username === c.username && pc.service === c.service && pc.validated)
    )
    if (newValidatedCreds.length > 0) {
      pivotalSteps.add(i)
      log.debug("pivotal: new validated credentials", { step: i, count: newValidatedCreds.length })
      continue
    }

    // Vulnerability exploited
    const prevVulns = prevState.vulnerabilities ?? []
    const currVulns = currState.vulnerabilities ?? []
    const newlyExploited = currVulns.filter(
      (v) => v.exploited && !prevVulns.some((pv) => pv.name === v.name && pv.exploited)
    )
    if (newlyExploited.length > 0) {
      pivotalSteps.add(i)
      log.debug("pivotal: vulnerability exploited", { step: i, vulns: newlyExploited.map((v) => v.name) })
      continue
    }

    // New flag captured
    const prevFlags = prevState.flags ?? []
    const currFlags = currState.flags ?? []
    const newFlags = currFlags.filter((f) => !prevFlags.includes(f))
    if (newFlags.length > 0) {
      pivotalSteps.add(i)
      log.debug("pivotal: flag captured", { step: i, count: newFlags.length })
      continue
    }
  }

  return pivotalSteps
}

// =============================================================================
// Methodology Extraction
// =============================================================================

/**
 * Generate methodology summary from trajectory
 */
export function generateMethodologySummary(
  trajectory: Trajectory.Data,
  state: EngagementState,
  pivotalSteps: Set<number>
): string {
  const parts: string[] = []

  // Get pivotal step summaries
  for (const stepIdx of Array.from(pivotalSteps).sort((a, b) => a - b)) {
    const step = trajectory.trajectory[stepIdx]
    if (step) {
      const tool = step.toolCall?.tool ?? "manual"
      // Extract key action from thought or result
      const action = extractActionSummary(step)
      if (action) {
        parts.push(`${tool}: ${action}`)
      }
    }
  }

  // Build summary
  if (parts.length > 0) {
    return parts.join(" → ")
  }

  // Fallback: use access level
  const access = state.accessLevel ?? "none"
  const vulns = state.vulnerabilities?.filter((v) => v.exploited) ?? []
  if (vulns.length > 0) {
    return `${vulns[0].name} → ${access} access`
  }

  return `Attack achieving ${access} access`
}

/**
 * Extract a brief action summary from a trajectory step
 */
function extractActionSummary(step: Trajectory.Step): string {
  // Try to extract from thought (first sentence or line)
  if (step.thought) {
    const firstLine = step.thought.split("\n")[0].trim()
    if (firstLine.length > 0 && firstLine.length < 100) {
      return firstLine
    }
  }

  // Fallback to tool name
  if (step.toolCall?.tool) {
    return step.toolCall.success ? `${step.toolCall.tool} succeeded` : `${step.toolCall.tool} attempted`
  }

  return ""
}

/**
 * Extract phases from trajectory
 * Converts Trajectory.Step to AttackPhase format
 */
export function extractPhases(trajectory: Trajectory.Data, pivotalSteps: Set<number>): AttackPhase[] {
  const phases: AttackPhase[] = []

  for (let i = 0; i < trajectory.trajectory.length; i++) {
    const step = trajectory.trajectory[i]
    if (!step.toolCall?.tool) continue // Skip steps without tool calls

    const phase: AttackPhase = {
      phase: step.phase ?? "reconnaissance",
      action: extractActionSummary(step) || `Used ${step.toolCall.tool}`,
      tool: step.toolCall.tool,
      result: step.result?.substring(0, 200) ?? "",
      pivotal: pivotalSteps.has(i),
    }

    phases.push(phase)
  }

  return phases
}

/**
 * Extract tool sequence from trajectory
 */
export function extractToolSequence(trajectory: Trajectory.Data): string[] {
  const tools: string[] = []
  const seen = new Set<string>()

  for (const step of trajectory.trajectory) {
    const tool = step.toolCall?.tool
    if (tool && !seen.has(tool)) {
      tools.push(tool)
      seen.add(tool)
    }
  }

  return tools
}

/**
 * Extract key insights from pivotal steps
 */
export function extractInsights(trajectory: Trajectory.Data, pivotalSteps: Set<number>): string[] {
  const insights: string[] = []

  for (const stepIdx of pivotalSteps) {
    const step = trajectory.trajectory[stepIdx]
    if (!step) continue

    // Look for explicit insights marked with "[INSIGHT]" or in verify blocks
    if (step.verify) {
      const verifyLines = step.verify.split("\n").filter((l) => l.trim().length > 0)
      for (const line of verifyLines.slice(0, 2)) {
        // Take first 2 lines
        if (line.length < 150) {
          insights.push(line.trim())
        }
      }
    }

    // Extract from result if it's a successful exploitation
    if (step.toolCall?.success && step.result) {
      const resultLower = step.result.toLowerCase()
      if (
        resultLower.includes("found") ||
        resultLower.includes("discovered") ||
        resultLower.includes("vulnerable") ||
        resultLower.includes("success")
      ) {
        const firstSentence = step.result.split(".")[0].trim()
        if (firstSentence.length < 150 && !insights.includes(firstSentence)) {
          insights.push(firstSentence)
        }
      }
    }
  }

  // Limit to 5 insights
  return insights.slice(0, 5)
}

/**
 * Calculate duration from trajectory
 */
export function calculateDuration(trajectory: Trajectory.Data): number {
  if (!trajectory.startTime) return 0

  const start = new Date(trajectory.startTime).getTime()
  const end = trajectory.endTime ? new Date(trajectory.endTime).getTime() : Date.now()

  return Math.round((end - start) / 60000) // Convert to minutes
}
