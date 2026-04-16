/**
 * Session Hierarchy Tracker
 *
 * Tracks parent-child relationships between sessions for permission bubbling.
 * This module is designed to be imported by both Session and Permission
 * without causing circular dependencies.
 *
 * Requirements:
 * - REQ-AGT-004: Permission requests from sub-agents SHALL bubble to root session
 * - Avoids schema changes by using in-memory cache
 * - Session.parentID remains source of truth
 */

import { createLog } from "../util/log"

const log = createLog("session.hierarchy")

/**
 * Maps child session IDs to their root session ID.
 * Populated when sessions are created, used for permission bubbling.
 */
const rootSessionMap = new Map<string, string>()

/**
 * Register a session's root session.
 * Called by Task tool when spawning sub-agents.
 */
export function registerRootSession(sessionID: string, rootSessionID: string): void {
  rootSessionMap.set(sessionID, rootSessionID)
  log.info("registered", { sessionID: sessionID.slice(-8), rootSessionID: rootSessionID.slice(-8) })
}

/**
 * Get the root session for a given session ID.
 * Returns the sessionID itself if it's a root session (no parent registered).
 */
export function getRootSession(sessionID: string): string {
  let current = sessionID
  const visited = new Set<string>()
  while (rootSessionMap.has(current) && rootSessionMap.get(current) !== current) {
    if (visited.has(current)) break // Prevent infinite loops
    visited.add(current)
    current = rootSessionMap.get(current)!
  }
  return current
}

/**
 * Check if a session has a registered parent (is a sub-agent session).
 */
export function hasParent(sessionID: string): boolean {
  const root = rootSessionMap.get(sessionID)
  return root !== undefined && root !== sessionID
}

/**
 * Clear registration for a session.
 * Called when session is deleted.
 */
export function unregister(sessionID: string): void {
  rootSessionMap.delete(sessionID)
  log.info("unregistered", { sessionID: sessionID.slice(-8) })
}

/**
 * Get all child sessions registered under a root session.
 */
export function getChildren(rootSessionID: string): string[] {
  const children: string[] = []
  for (const [childID, rootID] of rootSessionMap.entries()) {
    if (rootID === rootSessionID && childID !== rootSessionID) {
      children.push(childID)
    }
  }
  return children
}

/**
 * Clear all registrations for a root session and its children.
 * Called when root session is deleted to clean up the entire tree.
 */
export function unregisterTree(rootSessionID: string): void {
  // Find ALL sessions whose root resolves to this rootSessionID
  const toDelete: string[] = []
  for (const [childID] of rootSessionMap.entries()) {
    if (getRootSession(childID) === rootSessionID) {
      toDelete.push(childID)
    }
  }
  for (const childID of toDelete) {
    rootSessionMap.delete(childID)
  }
  rootSessionMap.delete(rootSessionID)
  log.info("unregistered_tree", { rootSessionID: rootSessionID.slice(-8), childCount: toDelete.length })
}
