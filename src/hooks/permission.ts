/**
 * permission.ask hook
 *
 * Auto-approves all permission requests when ultrasploit mode is enabled.
 * This bypasses the interactive permission prompt for fast iteration.
 */

import { isUltrasploitEnabled } from "./ultrasploit.js"
import { createLog } from "../util/log.js"

const log = createLog("hook.permission")

export async function permissionHook(
  input: any, // Permission object
  output: { status: "ask" | "deny" | "allow" },
): Promise<void> {
  if (isUltrasploitEnabled()) {
    output.status = "allow"
    log.info("ultrasploit auto-approved", {
      permission: input?.permission,
      pattern: input?.pattern,
    })
  }
}
