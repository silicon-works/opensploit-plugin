/**
 * chat.message hook
 *
 * Detects "ultrasploit" keyword in user messages. When found:
 * 1. Enables auto-approve mode (all permissions granted without prompt)
 * 2. Strips the keyword from the message so the LLM doesn't see it
 *
 * This matches the fat fork's behavior: typing "ultrasploit" in any
 * message activates the mode silently.
 */

import { setUltrasploit, isUltrasploitEnabled } from "./ultrasploit.js"
import { createLog } from "../util/log.js"

const log = createLog("hook.chat-message")

const KEYWORD_REGEX = /\bultrasploit\b/gi

export async function chatMessageHook(
  input: {
    sessionID: string
    agent?: string
    model?: { providerID: string; modelID: string }
    messageID?: string
    variant?: string
  },
  output: { message: any; parts: any[] },
): Promise<void> {
  try {
    // Check if any text part contains "ultrasploit"
    const hasKeyword = output.parts.some(
      (p: any) => {
        if (p.type !== "text") return false
        KEYWORD_REGEX.lastIndex = 0 // Reset stateful /g regex before .test()
        return KEYWORD_REGEX.test(p.text)
      },
    )

    if (!hasKeyword) return

    // Enable ultrasploit mode if not already enabled
    if (!isUltrasploitEnabled()) {
      setUltrasploit(true)
      log.info("ultrasploit mode activated", { sessionID: input.sessionID })
    }

    // Strip "ultrasploit" keyword from text parts so LLM doesn't see it
    for (const part of output.parts) {
      if (part.type === "text" && typeof part.text === "string") {
        const stripped = part.text
          .replace(KEYWORD_REGEX, "")
          .replace(/\s{2,}/g, " ")
          .trim()
        if (stripped !== part.text) {
          part.text = stripped
        }
      }
    }
  } catch (error) {
    log.error("hook failed, proceeding without modification", {
      error: error instanceof Error ? error.message : String(error),
    })
  }
}
