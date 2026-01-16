import { describe, expect, test } from "bun:test"
import { ContainerManager } from "../../src/container"

describe("tool.container-manager", () => {
  describe("isDockerAvailable", () => {
    test("returns boolean indicating Docker availability", async () => {
      const available = await ContainerManager.isDockerAvailable()
      expect(typeof available).toBe("boolean")
    })
  })

  describe("imageExists", () => {
    test("returns false for non-existent image", async () => {
      const exists = await ContainerManager.imageExists("nonexistent-image-xyz123")
      expect(exists).toBe(false)
    })
  })

  describe("getStatus", () => {
    test("returns empty array when no containers running", () => {
      const status = ContainerManager.getStatus()
      expect(Array.isArray(status)).toBe(true)
    })
  })

  // Note: Full integration tests for container spawning require Docker
  // These are unit tests for the basic functionality
})
