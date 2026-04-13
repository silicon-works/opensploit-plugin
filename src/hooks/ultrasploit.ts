/**
 * Ultrasploit mode — auto-approve all permission requests.
 *
 * When enabled, the permission.ask hook sets status to "allow" for
 * every permission request, bypassing user confirmation. Used for
 * fast iteration during CTF/HTB engagements.
 *
 * Toggled via /ultrasploit command in TUI (sets the shared state)
 * or OPENSPLOIT_ULTRASPLOIT=true environment variable.
 */

/** In-memory state — shared between TUI toggle and server hook. */
let enabled = process.env["OPENSPLOIT_ULTRASPLOIT"] === "true"

export function isUltrasploitEnabled(): boolean {
  return enabled
}

export function setUltrasploit(value: boolean): void {
  enabled = value
}

export function toggleUltrasploit(): boolean {
  enabled = !enabled
  return enabled
}
