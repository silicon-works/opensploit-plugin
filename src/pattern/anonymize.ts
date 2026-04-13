/**
 * Pattern Anonymization Module
 *
 * Implements Doc 13 §Anonymization (lines 825-900)
 *
 * Removes PII from patterns before storage to:
 * 1. Future-proof for potential sharing (P2 feature)
 * 2. Prevent accidental exposure if backups are shared
 * 3. Remove noise (specific IPs, usernames) that doesn't help retrieval
 *
 * Anonymization rules (Doc 13 lines 838-848):
 * - IP addresses → 10.10.10.X (preserves HTB-style format)
 * - Hostnames → target.htb
 * - Usernames → user1, user2, etc.
 * - Passwords → [REDACTED]
 * - SSH keys → [SSH_KEY_REDACTED]
 * - API keys → [API_KEY_REDACTED]
 * - Home directories → /home/user/ or C:\Users\user\
 * - Session IDs → removed
 */

import { createLog } from "../util/log"
import type { AttackPattern, AttackPhase } from "../memory/schema"

const log = createLog("pattern.anonymize")

// =============================================================================
// Anonymization Options
// =============================================================================

export interface AnonymizeOptions {
  /** Enable/disable anonymization (default: true) */
  enabled?: boolean
  /** Map of original IPs to anonymized IPs (for consistent replacement) */
  ipMapping?: Map<string, string>
  /** Map of original hostnames to anonymized hostnames */
  hostnameMapping?: Map<string, string>
  /** Map of original usernames to anonymized usernames */
  usernameMapping?: Map<string, string>
  /** Counter for generating unique IP suffixes */
  ipCounter?: number
  /** Counter for generating unique hostname suffixes */
  hostCounter?: number
  /** Counter for generating unique username suffixes */
  userCounter?: number
}

// =============================================================================
// Regex Patterns
// =============================================================================

// IP addresses (IPv4)
const IPV4_PATTERN = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g

// Hostnames with common TLDs
const HOSTNAME_PATTERN = /\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|io|co|local|internal|corp|htb|lan|home|localdomain)\b/gi

// Username patterns in various contexts (require = or : separator, not just whitespace)
const USERNAME_PATTERNS = [
  /username[=:][\s]*["']?([a-z0-9_.-]+)["']?/gi,
  /user[=:][\s]*["']?([a-z0-9_.-]+)["']?/gi,
  /login[=:][\s]*["']?([a-z0-9_.-]+)["']?/gi,
  /-u\s+([a-z0-9_.-]+)/gi,
  /--user(?:name)?[=\s]+([a-z0-9_.-]+)/gi,
]

// Password patterns
const PASSWORD_PATTERNS = [
  /password[=:\s]["']?([^"'\s]+)["']?/gi,
  /passwd[=:\s]["']?([^"'\s]+)["']?/gi,
  /pwd[=:\s]["']?([^"'\s]+)["']?/gi,
  /-p\s+["']?([^"'\s]+)["']?/gi,
  /--password[=\s]+["']?([^"'\s]+)["']?/gi,
  /secret[=:\s]["']?([^"'\s]+)["']?/gi,
]

// SSH keys (PEM format)
const SSH_KEY_PATTERN = /-----BEGIN[\s\S]*?-----[\s\S]*?-----END[^-]*-----/g

// API keys and tokens (32+ alphanumeric chars, or common prefixes)
const API_KEY_PATTERNS = [
  /\b[A-Za-z0-9]{32,}\b/g, // Generic long alphanumeric (no underscores)
  /\b(?:sk|pk|api|key|token|bearer)[-_][A-Za-z0-9_-]{20,}\b/gi, // Prefixed tokens with separator
  /Bearer\s+[A-Za-z0-9._-]+/gi, // Bearer tokens
]

// Home directories
const HOME_DIR_PATTERNS = [
  /\/home\/[a-z0-9_-]+\//gi, // Linux
  /C:\\Users\\[^\\]+\\/gi, // Windows
  /\/Users\/[a-z0-9_-]+\//gi, // macOS
]

// Email addresses
const EMAIL_PATTERN = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g

// Common domains to preserve (not anonymize)
const PRESERVED_DOMAINS = [
  "github.com",
  "google.com",
  "localhost",
  "htb",
  "hackthebox.com",
  "target.htb",
  "10.10.10.",
  "127.0.0.1",
]

// =============================================================================
// Text Anonymization
// =============================================================================

/**
 * Anonymize text by replacing PII with generic placeholders
 * Doc 13 §anonymizeText (lines 875-899)
 *
 * Uses consistent mapping so the same IP/hostname/username gets the same
 * replacement throughout the pattern.
 */
export function anonymizeText(text: string, options: AnonymizeOptions = {}): string {
  if (options.enabled === false) return text
  if (!text) return text

  let result = text

  // Initialize mappings and counters
  const ipMap = options.ipMapping ?? new Map<string, string>()
  const hostMap = options.hostnameMapping ?? new Map<string, string>()
  const userMap = options.usernameMapping ?? new Map<string, string>()
  let ipCounter = options.ipCounter ?? 1
  let hostCounter = options.hostCounter ?? 1
  let userCounter = options.userCounter ?? 1

  // 1. SSH keys (do first as they're large and might contain other patterns)
  result = result.replace(SSH_KEY_PATTERN, "[SSH_KEY_REDACTED]")

  // 2. API keys and tokens
  for (const pattern of API_KEY_PATTERNS) {
    result = result.replace(pattern, (match) => {
      // Don't redact if it's already redacted or looks like a hash
      if (match.includes("REDACTED") || match.includes("[")) return match
      // Preserve common non-sensitive long strings
      if (match.toLowerCase().startsWith("bearer ")) {
        return "Bearer [API_KEY_REDACTED]"
      }
      return "[API_KEY_REDACTED]"
    })
  }

  // 3. IP addresses
  result = result.replace(IPV4_PATTERN, (match) => {
    // Preserve localhost and already-anonymized IPs
    if (match === "127.0.0.1" || match.startsWith("10.10.10.")) return match

    if (!ipMap.has(match)) {
      ipMap.set(match, `10.10.10.${ipCounter++}`)
    }
    return ipMap.get(match)!
  })

  // 4. Email addresses (before hostnames to prevent domain replacement)
  result = result.replace(EMAIL_PATTERN, (match) => {
    // Replace with generic email
    const domain = match.split("@")[1]?.toLowerCase()
    if (domain && PRESERVED_DOMAINS.some((d) => domain.includes(d))) return match
    return "user@target.htb"
  })

  // 5. Hostnames
  result = result.replace(HOSTNAME_PATTERN, (match) => {
    const lowerMatch = match.toLowerCase()
    // Preserve common/safe domains
    if (PRESERVED_DOMAINS.some((d) => lowerMatch.includes(d))) return match

    if (!hostMap.has(lowerMatch)) {
      hostMap.set(lowerMatch, hostCounter === 1 ? "target.htb" : `target${hostCounter}.htb`)
      hostCounter++
    }
    return hostMap.get(lowerMatch)!
  })

  // 6. Passwords
  for (const pattern of PASSWORD_PATTERNS) {
    result = result.replace(pattern, (match, value) => {
      if (!value || value.includes("REDACTED")) return match
      return match.replace(value, "[REDACTED]")
    })
  }

  // 7. Usernames (be careful not to break tool syntax)
  for (const pattern of USERNAME_PATTERNS) {
    result = result.replace(pattern, (match, username) => {
      if (!username) return match
      // Preserve common system users
      const sysUsers = ["root", "admin", "www-data", "nobody", "daemon", "user", "user1"]
      if (sysUsers.includes(username.toLowerCase())) return match

      if (!userMap.has(username.toLowerCase())) {
        userMap.set(username.toLowerCase(), `user${userCounter++}`)
      }
      return match.replace(username, userMap.get(username.toLowerCase())!)
    })
  }

  // 8. Home directories
  for (const pattern of HOME_DIR_PATTERNS) {
    result = result.replace(pattern, (match) => {
      if (match.toLowerCase().includes("/user/") || match.toLowerCase().includes("\\user\\")) {
        return match // Already anonymized
      }
      if (match.startsWith("/home/")) return "/home/user/"
      if (match.startsWith("/Users/")) return "/Users/user/"
      if (match.toLowerCase().startsWith("c:\\users\\")) return "C:\\Users\\user\\"
      return match
    })
  }

  // Update options with final counters for consistent follow-up calls
  if (options.ipMapping) options.ipCounter = ipCounter
  if (options.hostnameMapping) options.hostCounter = hostCounter
  if (options.usernameMapping) options.userCounter = userCounter

  return result
}

// =============================================================================
// Pattern Anonymization
// =============================================================================

/**
 * Anonymize an attack pattern
 * Doc 13 §anonymizePattern (lines 853-873)
 *
 * Removes PII from all text fields and removes session reference.
 * Returns a new pattern object (does not mutate input).
 */
export function anonymizePattern(pattern: AttackPattern): AttackPattern {
  log.debug("anonymizing pattern", { patternId: pattern.id })

  // Create deep clone to avoid mutating original
  const anonymized: AttackPattern = JSON.parse(JSON.stringify(pattern))

  // Shared options for consistent anonymization across fields
  const options: AnonymizeOptions = {
    enabled: true,
    ipMapping: new Map(),
    hostnameMapping: new Map(),
    usernameMapping: new Map(),
    ipCounter: 1,
    hostCounter: 1,
    userCounter: 1,
  }

  // Remove session reference
  anonymized.metadata.session_id = undefined
  anonymized.metadata.anonymized = true

  // Anonymize vulnerability description
  if (anonymized.vulnerability.description) {
    anonymized.vulnerability.description = anonymizeText(anonymized.vulnerability.description, options)
  }

  // Anonymize methodology
  if (anonymized.methodology.summary) {
    anonymized.methodology.summary = anonymizeText(anonymized.methodology.summary, options)
  }

  // Anonymize key insights
  if (anonymized.methodology.key_insights) {
    anonymized.methodology.key_insights = anonymized.methodology.key_insights.map((insight) =>
      anonymizeText(insight, options)
    )
  }

  // Anonymize phases
  if (anonymized.methodology.phases) {
    anonymized.methodology.phases = anonymized.methodology.phases.map((phase): AttackPhase => ({
      ...phase,
      action: anonymizeText(phase.action, options),
      result: anonymizeText(phase.result, options),
    }))
  }

  // Anonymize target profile characteristics (might contain IPs/hostnames in descriptions)
  if (anonymized.target_profile.characteristics) {
    anonymized.target_profile.characteristics = anonymized.target_profile.characteristics.map((char) =>
      anonymizeText(char, options)
    )
  }

  log.debug("anonymization complete", {
    patternId: pattern.id,
    ipsReplaced: options.ipMapping?.size ?? 0,
    hostsReplaced: options.hostnameMapping?.size ?? 0,
    usersReplaced: options.usernameMapping?.size ?? 0,
  })

  return anonymized
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Check if text contains potentially sensitive information
 * Useful for validation/testing
 */
export function containsSensitiveData(text: string): boolean {
  if (!text) return false

  // Check for real IP addresses (not 10.10.10.X or 127.0.0.1)
  const ipMatches = text.match(IPV4_PATTERN) ?? []
  for (const ip of ipMatches) {
    if (!ip.startsWith("10.10.10.") && ip !== "127.0.0.1") {
      return true
    }
  }

  // Check for non-htb hostnames
  const hostMatches = text.match(HOSTNAME_PATTERN) ?? []
  for (const host of hostMatches) {
    const lower = host.toLowerCase()
    if (!PRESERVED_DOMAINS.some((d) => lower.includes(d))) {
      return true
    }
  }

  // Check for SSH keys
  if (SSH_KEY_PATTERN.test(text)) return true

  // Check for potential API keys (reset pattern state)
  for (const pattern of API_KEY_PATTERNS) {
    pattern.lastIndex = 0
    if (pattern.test(text) && !text.includes("REDACTED")) {
      return true
    }
  }

  return false
}

/**
 * Get anonymization statistics for a pattern
 */
export function getAnonymizationStats(original: AttackPattern, anonymized: AttackPattern): {
  fieldsModified: string[]
  sensitiveDataRemoved: boolean
} {
  const fieldsModified: string[] = []

  if (original.vulnerability.description !== anonymized.vulnerability.description) {
    fieldsModified.push("vulnerability.description")
  }
  if (original.methodology.summary !== anonymized.methodology.summary) {
    fieldsModified.push("methodology.summary")
  }
  if (JSON.stringify(original.methodology.key_insights) !== JSON.stringify(anonymized.methodology.key_insights)) {
    fieldsModified.push("methodology.key_insights")
  }
  if (JSON.stringify(original.methodology.phases) !== JSON.stringify(anonymized.methodology.phases)) {
    fieldsModified.push("methodology.phases")
  }
  if (original.metadata.session_id !== anonymized.metadata.session_id) {
    fieldsModified.push("metadata.session_id")
  }

  // Check if anonymized version still contains sensitive data
  const allText = [
    anonymized.vulnerability.description,
    anonymized.methodology.summary,
    ...(anonymized.methodology.key_insights ?? []),
    ...(anonymized.methodology.phases?.map((p) => `${p.action} ${p.result}`) ?? []),
  ].join(" ")

  return {
    fieldsModified,
    sensitiveDataRemoved: !containsSensitiveData(allText),
  }
}
