/**
 * Trajectory Type Stub
 *
 * Minimal type definitions for the Trajectory namespace consumed by the pattern module.
 * Full implementation lives in the fat fork (packages/opencode/src/session/trajectory.ts).
 * This stub provides the types and a placeholder for fromSessionTree().
 */

export type Phase = "reconnaissance" | "enumeration" | "exploitation" | "post_exploitation" | "reporting"

export namespace Trajectory {
  /**
   * A single step in the trajectory
   */
  export interface Step {
    step: number
    timestamp: string
    phase?: Phase
    thought: string
    verify: string
    action?: string
    result?: string
    toolCall?: {
      tool: string
      method?: string
      success: boolean
    }
    durationMs?: number
    /** Agent that performed this step (master or sub-agent name) */
    agentName?: string
  }

  /**
   * Complete trajectory for a session
   */
  export interface Data {
    sessionID: string
    target?: string
    model: string
    startTime: string
    endTime?: string
    trajectory: Step[]
    outcome?: {
      success: boolean
      accessAchieved?: "none" | "user" | "root"
      flagsCaptured?: string[]
      notes?: string
    }
    metadata?: Record<string, unknown>
  }

  /**
   * Build a merged trajectory from the full session tree (root + sub-agents).
   * Placeholder - will be wired to the host app's session system.
   */
  export async function fromSessionTree(_rootSessionID: string): Promise<Data | null> {
    // TODO: Wire to host app's session/trajectory infrastructure
    return null
  }
}
