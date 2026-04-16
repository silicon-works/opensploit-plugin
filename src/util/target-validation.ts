import { createLog } from "./log"

const log = createLog("tool.target")

/**
 * IP address classification and target validation for pentest safety
 */
export namespace TargetValidation {
  /**
   * Check if an IP address is in a private network range
   * Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8
   */
  export function isPrivateIP(ip: string): boolean {
    // BUG-SH-1 fix: handle IPv6 private/loopback addresses
    if (ip.includes(":")) {
      const normalized = ip.toLowerCase().replace(/^\[|\]$/g, "") // strip brackets
      // Loopback
      if (normalized === "::1") return true
      // Link-local (fe80::/10)
      if (normalized.startsWith("fe80:") || normalized.startsWith("fe80::")) return true
      // Unique local (fc00::/7 — fc00:: and fd00::)
      if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true
      return false
    }

    // Handle IPv4
    const parts = ip.split(".")
    if (parts.length !== 4) {
      return false
    }

    const octets = parts.map((p) => parseInt(p, 10))
    if (octets.some((o) => isNaN(o) || o < 0 || o > 255)) {
      return false
    }

    const [a, b] = octets

    // 10.0.0.0/8 - Class A private
    if (a === 10) return true

    // 172.16.0.0/12 - Class B private
    if (a === 172 && b >= 16 && b <= 31) return true

    // 192.168.0.0/16 - Class C private
    if (a === 192 && b === 168) return true

    // 127.0.0.0/8 - Loopback
    if (a === 127) return true

    // 169.254.0.0/16 - Link-local
    if (a === 169 && b === 254) return true

    return false
  }

  /**
   * Check if a hostname is likely internal (HTB, lab, etc.)
   */
  export function isInternalHostname(hostname: string): boolean {
    const internalPatterns = [
      /\.htb$/i, // HackTheBox
      /\.local$/i, // Local network
      /\.internal$/i, // Internal network
      /\.lab$/i, // Lab environment
      /\.test$/i, // Test environment
      /\.example$/i, // Example domain
      /\.localhost$/i, // Localhost
      /\.lan$/i, // LAN
      /\.home$/i, // Home network
      /\.corp$/i, // Corporate
      /\.intranet$/i, // Intranet
    ]

    return internalPatterns.some((pattern) => pattern.test(hostname))
  }

  /**
   * Extract target from various input formats (URL, IP, hostname)
   */
  export function extractTarget(input: string): { ip?: string; hostname?: string } {
    // BUG-SH-3 fix: URL-decode bare encoded strings (e.g., %31%30%2e%31%30%2e%31%30%2e%31)
    let decoded = input
    try {
      if (input.includes("%")) decoded = decodeURIComponent(input)
    } catch { /* not URL-encoded, continue with original */ }

    // Try to parse as URL
    try {
      const url = new URL(input)
      const hostname = url.hostname
      // Only use URL parsing if it produced a real hostname
      // (e.g., "target.htb:80" parses as URL with empty hostname — fall through)
      if (hostname) {
        // IPv4
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
          return { ip: hostname }
        }
        // IPv6 (URL parser may return with or without brackets)
        const bareHostname = hostname.replace(/^\[|\]$/g, "")
        if (bareHostname.includes(":") && /^[0-9a-fA-F:]+$/.test(bareHostname)) {
          return { ip: bareHostname }
        }
        return { hostname }
      }
    } catch {
      // Not a URL, try as bare IP or hostname
    }

    // BUG-SH-4 fix: strip port suffix (e.g., 10.10.10.1:8080 → 10.10.10.1)
    // BUG-SH-2 fix: strip CIDR suffix (e.g., 10.0.0.0/8 → 10.0.0.0)
    const withoutPort = decoded.replace(/:\d+$/, "").replace(/\/\d{1,3}$/, "")

    // Check if it's an IPv4 address
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(withoutPort)) {
      return { ip: withoutPort }
    }

    // BUG-SH-1 fix: check if it's an IPv6 address (contains ":" and hex chars)
    // Strip brackets for [::1] format
    const maybeIPv6 = decoded.replace(/^\[|\]$/g, "")
    if (maybeIPv6.includes(":") && /^[0-9a-fA-F:]+$/.test(maybeIPv6)) {
      return { ip: maybeIPv6 }
    }

    // Treat as hostname (also strip port from hostnames like target.htb:80)
    return { hostname: withoutPort || decoded }
  }

  /**
   * Classification of a target
   */
  export type TargetType = "private" | "internal" | "external" | "unknown"

  export interface TargetInfo {
    original: string
    ip?: string
    hostname?: string
    type: TargetType
    isExternal: boolean
    requiresConfirmation: boolean
    warningMessage?: string
  }

  /**
   * Classify a target and determine if it requires confirmation
   */
  export function classifyTarget(target: string): TargetInfo {
    const extracted = extractTarget(target)

    let type: TargetType = "unknown"
    let isExternal = false
    let warningMessage: string | undefined

    if (extracted.ip) {
      if (isPrivateIP(extracted.ip)) {
        type = "private"
        isExternal = false
      } else {
        type = "external"
        isExternal = true
        warningMessage = `Target ${extracted.ip} is an external IP address. Ensure you have authorization to scan this target.`
      }
    } else if (extracted.hostname) {
      if (isInternalHostname(extracted.hostname)) {
        type = "internal"
        isExternal = false
      } else {
        type = "external"
        isExternal = true
        warningMessage = `Target ${extracted.hostname} may be an external host. Ensure you have authorization to scan this target.`
      }
    }

    return {
      original: target,
      ...extracted,
      type,
      isExternal,
      requiresConfirmation: isExternal,
      warningMessage,
    }
  }

  /**
   * High-risk target patterns (government, military, critical infrastructure)
   * These are warned about but NOT blocked - the user may have legitimate authorization
   */
  const HIGH_RISK_PATTERNS = [
    { pattern: /\.gov$/i, category: "government" },
    { pattern: /\.gov\.[a-z]{2}$/i, category: "government" }, // .gov.uk, .gov.au, etc.
    { pattern: /\.mil$/i, category: "military" },
    { pattern: /\.mil\.[a-z]{2}$/i, category: "military" },
    { pattern: /\.edu$/i, category: "educational" },
    { pattern: /\.ac\.[a-z]{2}$/i, category: "academic" },
  ]

  /**
   * Check if a target is high-risk (government, military, educational)
   * Returns a warning but does NOT block - legitimate pentests may target these
   */
  export function isHighRiskTarget(target: string): { highRisk: boolean; category?: string; warning?: string } {
    const extracted = extractTarget(target)

    if (extracted.hostname) {
      for (const { pattern, category } of HIGH_RISK_PATTERNS) {
        if (pattern.test(extracted.hostname)) {
          return {
            highRisk: true,
            category,
            warning: `⚠️  HIGH-RISK TARGET: ${extracted.hostname} appears to be a ${category} institution.\n\nEnsure you have EXPLICIT WRITTEN AUTHORIZATION before proceeding.\nUnauthorized scanning of ${category} systems carries severe legal consequences.`,
          }
        }
      }
    }

    return { highRisk: false }
  }

  /**
   * @deprecated Use isHighRiskTarget instead - this is kept for backwards compatibility
   */
  export function isForbiddenTarget(target: string): { forbidden: boolean; reason?: string } {
    const result = isHighRiskTarget(target)
    return {
      forbidden: false, // Never block, only warn
      reason: result.warning,
    }
  }

  /**
   * Validate a target and return a summary
   */
  export function validateTarget(target: string): {
    valid: boolean
    info: TargetInfo
    forbidden: boolean
    forbiddenReason?: string
    highRisk: boolean
    highRiskWarning?: string
  } {
    const info = classifyTarget(target)
    const highRiskCheck = isHighRiskTarget(target)

    log.info("target validated", {
      target,
      type: info.type,
      isExternal: info.isExternal,
      highRisk: highRiskCheck.highRisk,
    })

    return {
      valid: true, // Never block - always allow with appropriate warnings
      info,
      forbidden: false, // Deprecated - kept for compatibility
      forbiddenReason: highRiskCheck.warning,
      highRisk: highRiskCheck.highRisk,
      highRiskWarning: highRiskCheck.warning,
    }
  }

  /**
   * Format a warning message for display
   */
  export function formatWarning(info: TargetInfo): string {
    if (!info.isExternal) {
      return ""
    }

    return `
⚠️  EXTERNAL TARGET WARNING

Target: ${info.original}
Type: ${info.type.toUpperCase()}

${info.warningMessage}

Please confirm:
1. You have written authorization to scan this target
2. This is part of an authorized penetration test
3. You understand the legal implications

Scanning unauthorized targets is illegal and unethical.
`
  }
}
