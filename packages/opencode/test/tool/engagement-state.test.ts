import { describe, expect, test } from "bun:test"
import path from "path"
import fs from "fs/promises"
import yaml from "js-yaml"
import { tmpdir } from "../fixture/fixture"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import {
  loadEngagementState,
  getEngagementStateForInjection,
  getFindingsDir,
  mergeState,
} from "../../src/tool/engagement-state"

describe("tool.engagement-state", () => {
  test("loadEngagementState returns empty object when no state file exists", async () => {
    await using tmp = await tmpdir()

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const session = await Session.create({})
        const state = await loadEngagementState(session.id)
        expect(state).toEqual({})
      },
    })
  })

  test("loadEngagementState loads state from state.yaml", async () => {
    await using tmp = await tmpdir()

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const session = await Session.create({})

        // Write a state file
        const stateContent = yaml.dump({
          target: { ip: "10.10.10.1", hostname: "target.htb" },
          ports: [{ port: 22, protocol: "tcp", service: "ssh" }],
          accessLevel: "none",
        })
        await fs.writeFile(path.join(session.directory, "state.yaml"), stateContent)

        const state = await loadEngagementState(session.id)
        expect(state.target?.ip).toBe("10.10.10.1")
        expect(state.ports?.length).toBe(1)
        expect(state.ports?.[0].port).toBe(22)
        expect(state.accessLevel).toBe("none")
      },
    })
  })

  test("getEngagementStateForInjection returns null when no state exists", async () => {
    await using tmp = await tmpdir()

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const session = await Session.create({})
        const injection = await getEngagementStateForInjection(session.id)
        expect(injection).toBeNull()
      },
    })
  })

  test("getEngagementStateForInjection returns formatted state when state exists", async () => {
    await using tmp = await tmpdir()

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const session = await Session.create({})

        // Write a state file
        const stateContent = yaml.dump({
          target: { ip: "10.10.10.1" },
          ports: [{ port: 80, protocol: "tcp", service: "http" }],
        })
        await fs.writeFile(path.join(session.directory, "state.yaml"), stateContent)

        const injection = await getEngagementStateForInjection(session.id)
        expect(injection).not.toBeNull()
        expect(injection).toContain("## Current Engagement State")
        expect(injection).toContain("10.10.10.1")
        expect(injection).toContain("port: 80")
      },
    })
  })

  test("getFindingsDir creates findings directory", async () => {
    await using tmp = await tmpdir()

    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const session = await Session.create({})
        const findingsDir = await getFindingsDir(session.id)

        expect(findingsDir).toBe(path.join(session.directory, "findings"))

        // Verify directory was created
        const stat = await fs.stat(findingsDir)
        expect(stat.isDirectory()).toBe(true)
      },
    })
  })

  // ---------------------------------------------------------------------------
  // Merge Semantics Tests
  // ---------------------------------------------------------------------------

  describe("mergeState", () => {
    test("replaces scalar values", () => {
      const existing = { accessLevel: "none" as const }
      const updates = { accessLevel: "user" as const }
      const result = mergeState(existing, updates)
      expect(result.accessLevel).toBe("user")
    })

    test("merges target object", () => {
      const existing = { target: { ip: "10.10.10.1" } }
      const updates = { target: { ip: "10.10.10.1", hostname: "target.htb" } }
      const result = mergeState(existing, updates)
      expect(result.target?.ip).toBe("10.10.10.1")
      expect(result.target?.hostname).toBe("target.htb")
    })

    test("appends to ports array with deduplication", () => {
      const existing = {
        ports: [{ port: 22, protocol: "tcp" as const, service: "ssh" }],
      }
      const updates = {
        ports: [
          { port: 22, protocol: "tcp" as const, version: "OpenSSH 8.2" }, // Update existing
          { port: 80, protocol: "tcp" as const, service: "http" }, // New port
        ],
      }
      const result = mergeState(existing, updates)

      expect(result.ports?.length).toBe(2)
      // Port 22 should be updated with version
      const port22 = result.ports?.find((p) => p.port === 22)
      expect(port22?.service).toBe("ssh")
      expect(port22?.version).toBe("OpenSSH 8.2")
      // Port 80 should be added
      const port80 = result.ports?.find((p) => p.port === 80)
      expect(port80?.service).toBe("http")
    })

    test("appends to credentials array with deduplication", () => {
      const existing = {
        credentials: [{ username: "admin", service: "http", password: "old" }],
      }
      const updates = {
        credentials: [
          { username: "admin", service: "http", password: "new", validated: true }, // Update existing
          { username: "root", service: "ssh" }, // New credential
        ],
      }
      const result = mergeState(existing, updates)

      expect(result.credentials?.length).toBe(2)
      // admin@http should be updated
      const adminHttp = result.credentials?.find(
        (c) => c.username === "admin" && c.service === "http"
      )
      expect(adminHttp?.password).toBe("new")
      expect(adminHttp?.validated).toBe(true)
      // root@ssh should be added
      const rootSsh = result.credentials?.find(
        (c) => c.username === "root" && c.service === "ssh"
      )
      expect(rootSsh).toBeDefined()
    })

    test("appends to sessions array with deduplication by id", () => {
      const existing = {
        sessions: [{ id: "shell-1", user: "www-data" }],
      }
      const updates = {
        sessions: [
          { id: "shell-1", privileged: true }, // Update existing
          { id: "shell-2", user: "root" }, // New session
        ],
      }
      const result = mergeState(existing, updates)

      expect(result.sessions?.length).toBe(2)
      const shell1 = result.sessions?.find((s) => s.id === "shell-1")
      expect(shell1?.user).toBe("www-data")
      expect(shell1?.privileged).toBe(true)
    })

    test("deduplicates flags as a set", () => {
      const existing = { flags: ["flag1", "flag2"] }
      const updates = { flags: ["flag2", "flag3"] }
      const result = mergeState(existing, updates)

      expect(result.flags?.length).toBe(3)
      expect(result.flags).toContain("flag1")
      expect(result.flags).toContain("flag2")
      expect(result.flags).toContain("flag3")
    })

    test("appends to failedAttempts without deduplication", () => {
      const existing = {
        failedAttempts: [{ action: "SSH brute force", reason: "No password" }],
      }
      const updates = {
        failedAttempts: [{ action: "SQL injection", reason: "Input sanitized" }],
      }
      const result = mergeState(existing, updates)

      expect(result.failedAttempts?.length).toBe(2)
    })

    test("appends to vulnerabilities without deduplication", () => {
      const existing = {
        vulnerabilities: [{ name: "SQLi", severity: "high" as const }],
      }
      const updates = {
        vulnerabilities: [{ name: "XSS", severity: "medium" as const }],
      }
      const result = mergeState(existing, updates)

      expect(result.vulnerabilities?.length).toBe(2)
    })

    test("handles empty existing state", () => {
      const existing = {}
      const updates = {
        target: { ip: "10.10.10.1" },
        ports: [{ port: 22, protocol: "tcp" as const }],
        accessLevel: "none" as const,
      }
      const result = mergeState(existing, updates)

      expect(result.target?.ip).toBe("10.10.10.1")
      expect(result.ports?.length).toBe(1)
      expect(result.accessLevel).toBe("none")
    })

    test("ignores null and undefined values", () => {
      const existing = { accessLevel: "user" as const }
      const updates = { accessLevel: undefined, target: null } as any
      const result = mergeState(existing, updates)

      expect(result.accessLevel).toBe("user")
      expect(result.target).toBeUndefined()
    })
  })
})
