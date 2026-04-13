import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import {
  registerRootSession,
  getRootSession,
  hasParent,
  unregister,
  getChildren,
  unregisterTree,
} from "../../src/session/hierarchy"

describe("session.hierarchy", () => {
  // Clean up after each test
  afterEach(() => {
    // Unregister all test sessions
    unregister("child-1")
    unregister("child-2")
    unregister("grandchild-1")
    unregister("root-1")
  })

  test("getRootSession returns sessionID for unregistered sessions", () => {
    const result = getRootSession("unknown-session")
    expect(result).toBe("unknown-session")
  })

  test("registerRootSession and getRootSession work correctly", () => {
    registerRootSession("child-1", "root-1")
    expect(getRootSession("child-1")).toBe("root-1")
  })

  test("hasParent returns false for root sessions", () => {
    expect(hasParent("root-1")).toBe(false)
  })

  test("hasParent returns true for child sessions", () => {
    registerRootSession("child-1", "root-1")
    expect(hasParent("child-1")).toBe(true)
  })

  test("unregister removes session from map", () => {
    registerRootSession("child-1", "root-1")
    expect(getRootSession("child-1")).toBe("root-1")

    unregister("child-1")
    expect(getRootSession("child-1")).toBe("child-1") // Falls back to self
  })

  test("getChildren returns all children of a root session", () => {
    registerRootSession("child-1", "root-1")
    registerRootSession("child-2", "root-1")
    registerRootSession("grandchild-1", "root-1")

    const children = getChildren("root-1")
    expect(children).toContain("child-1")
    expect(children).toContain("child-2")
    expect(children).toContain("grandchild-1")
    expect(children.length).toBe(3)
  })

  test("getChildren returns empty array for session with no children", () => {
    const children = getChildren("root-1")
    expect(children).toEqual([])
  })

  test("unregisterTree removes root and all children", () => {
    registerRootSession("child-1", "root-1")
    registerRootSession("child-2", "root-1")

    unregisterTree("root-1")

    // All should now return themselves (not in map)
    expect(getRootSession("child-1")).toBe("child-1")
    expect(getRootSession("child-2")).toBe("child-2")
    expect(getChildren("root-1")).toEqual([])
  })

  test("nested hierarchy tracks all to root", () => {
    // root-1 -> child-1 -> grandchild-1
    // All should map to root-1
    registerRootSession("child-1", "root-1")
    registerRootSession("grandchild-1", "root-1")

    expect(getRootSession("child-1")).toBe("root-1")
    expect(getRootSession("grandchild-1")).toBe("root-1")
  })
})
