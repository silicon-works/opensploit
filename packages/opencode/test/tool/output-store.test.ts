import { describe, test, expect, beforeEach, afterEach } from "bun:test"
import * as OutputStore from "../../src/tool/output-store"
import {
  normalize,
  normalizeNmap,
  normalizeFfuf,
  normalizeNikto,
  normalizeGeneric,
} from "../../src/tool/output-normalizers"
import fs from "fs"
import path from "path"
import os from "os"

const TEST_SESSION_ID = "test-session-output-store"
const OUTPUTS_DIR = path.join(os.homedir(), ".opensploit", "outputs", TEST_SESSION_ID)

describe("Output Normalizers", () => {
  describe("normalizeNmap", () => {
    test("normalizes nmap port scan data to flat records", () => {
      const nmapData = {
        hosts: [
          {
            ip: "10.10.10.1",
            hostname: "target.htb",
            ports: [
              { port: 22, protocol: "tcp", state: "open", service: { name: "ssh", version: "8.2p1" } },
              { port: 80, protocol: "tcp", state: "open", service: { name: "http", product: "Apache" } },
              { port: 443, protocol: "tcp", state: "filtered" },
            ],
          },
        ],
      }

      const records = normalizeNmap(nmapData)

      expect(records.length).toBe(3)
      expect(records[0].type).toBe("port")
      expect(records[0].port).toBe(22)
      expect(records[0].service).toBe("ssh")
      expect(records[0].state).toBe("open")
      expect(records[1].port).toBe(80)
      expect(records[2].state).toBe("filtered")
    })

    test("handles empty hosts array", () => {
      const records = normalizeNmap({ hosts: [] })
      expect(records).toEqual([])
    })

    test("handles missing ports", () => {
      const records = normalizeNmap({ hosts: [{ ip: "10.10.10.1" }] })
      expect(records).toEqual([])
    })
  })

  describe("normalizeFfuf", () => {
    test("normalizes ffuf fuzzing results to flat records", () => {
      const ffufData = {
        results: [
          { input: "admin", url: "http://target.com/admin", status: 200, length: 1234 },
          { input: "login", url: "http://target.com/login", status: 301, length: 0 },
          { input: "secret", url: "http://target.com/secret", status: 403, length: 287 },
        ],
      }

      const records = normalizeFfuf(ffufData)

      expect(records.length).toBe(3)
      expect(records[0].type).toBe("directory")
      expect(records[0].path).toBe("admin")
      expect(records[0].status).toBe(200)
      expect(records[1].status).toBe(301)
      expect(records[2].status).toBe(403)
    })

    test("handles empty results", () => {
      const records = normalizeFfuf({ results: [] })
      expect(records).toEqual([])
    })
  })

  describe("normalizeNikto", () => {
    test("normalizes nikto vulnerability findings", () => {
      const niktoData = {
        vulnerabilities: [
          { id: "OSVDB-123", uri: "/admin", description: "Admin panel exposed" },
          { id: "OSVDB-456", uri: "/backup.sql", description: "SQL backup file" },
        ],
      }

      const records = normalizeNikto(niktoData)

      expect(records.length).toBe(2)
      expect(records[0].type).toBe("vulnerability")
      expect(records[0].id).toBe("OSVDB-123")
      expect(records[0].uri).toBe("/admin")
    })
  })

  describe("normalizeGeneric", () => {
    test("flattens arrays in unknown data structure", () => {
      const data = {
        items: [
          { name: "item1", value: 100 },
          { name: "item2", value: 200 },
        ],
      }

      const records = normalizeGeneric(data)

      expect(records.length).toBe(2)
      expect(records[0].type).toBe("item") // "items" -> "item"
      expect(records[0].name).toBe("item1")
    })

    test("falls back to line-based records from raw output", () => {
      const records = normalizeGeneric({}, "line one\nline two\nshort\nline four is longer")

      // "short" is filtered out (< 5 chars)
      expect(records.length).toBe(3)
      expect(records[0].type).toBe("line")
      expect(records[0].text).toBe("line one")
    })
  })

  describe("normalize (dispatcher)", () => {
    test("uses nmap normalizer for nmap tools", () => {
      const data = { hosts: [{ ip: "10.10.10.1", ports: [{ port: 22, state: "open" }] }] }
      const records = normalize("nmap_port_scan", data)

      expect(records.length).toBe(1)
      expect(records[0].type).toBe("port")
    })

    test("uses ffuf normalizer for ffuf tools", () => {
      const data = { results: [{ input: "admin", status: 200 }] }
      const records = normalize("ffuf_dir_fuzz", data)

      expect(records.length).toBe(1)
      expect(records[0].type).toBe("directory")
    })

    test("falls back to generic for unknown tools", () => {
      const data = { findings: [{ name: "test" }] }
      const records = normalize("unknown_tool", data)

      expect(records.length).toBe(1)
      expect(records[0].type).toBe("finding")
    })
  })
})

describe("Output Store", () => {
  beforeEach(() => {
    // Clean up test directory
    if (fs.existsSync(OUTPUTS_DIR)) {
      fs.rmSync(OUTPUTS_DIR, { recursive: true })
    }
  })

  afterEach(() => {
    // Clean up after tests
    if (fs.existsSync(OUTPUTS_DIR)) {
      fs.rmSync(OUTPUTS_DIR, { recursive: true })
    }
  })

  describe("store", () => {
    test("returns direct output for small content", async () => {
      const result = await OutputStore.store({
        sessionId: TEST_SESSION_ID,
        tool: "nmap",
        method: "port_scan",
        data: { hosts: [{ ip: "10.10.10.1", ports: [{ port: 22, state: "open" }] }] },
        rawOutput: "small output",
      })

      expect(result.stored).toBe(false)
      expect(result.outputId).toBeUndefined()
    })

    test("stores large output and returns summary", async () => {
      // Create large data that exceeds threshold
      const largePorts = Array.from({ length: 100 }, (_, i) => ({
        port: 1000 + i,
        protocol: "tcp",
        state: i % 2 === 0 ? "open" : "filtered",
        service: { name: `service${i}` },
      }))

      const result = await OutputStore.store({
        sessionId: TEST_SESSION_ID,
        tool: "nmap",
        method: "port_scan",
        data: { hosts: [{ ip: "10.10.10.1", ports: largePorts }] },
        rawOutput: "x".repeat(5000), // Large raw output
      })

      expect(result.stored).toBe(true)
      expect(result.outputId).toBeDefined()
      expect(result.output).toContain("nmap.port_scan Result")
      expect(result.output).toContain("read_tool_output")
      expect(result.output).toContain(result.outputId!)
    })

    test("creates session directory if not exists", async () => {
      const largePorts = Array.from({ length: 100 }, (_, i) => ({
        port: 1000 + i,
        state: "open",
      }))

      await OutputStore.store({
        sessionId: TEST_SESSION_ID,
        tool: "nmap",
        method: "port_scan",
        data: { hosts: [{ ip: "10.10.10.1", ports: largePorts }] },
        rawOutput: "x".repeat(5000),
      })

      expect(fs.existsSync(OUTPUTS_DIR)).toBe(true)
    })
  })

  describe("query", () => {
    let outputId: string

    beforeEach(async () => {
      // Store test data
      const ports = Array.from({ length: 50 }, (_, i) => ({
        port: 1000 + i,
        protocol: "tcp",
        state: i < 25 ? "open" : "filtered",
        service: { name: i < 10 ? "ssh" : `service${i}` },
      }))

      const result = await OutputStore.store({
        sessionId: TEST_SESSION_ID,
        tool: "nmap",
        method: "port_scan",
        data: { hosts: [{ ip: "10.10.10.1", ports }] },
        rawOutput: "x".repeat(5000),
      })

      outputId = result.outputId!
    })

    test("queries all records without filter", async () => {
      const result = await OutputStore.query({
        sessionId: TEST_SESSION_ID,
        outputId,
      })

      expect(result.found).toBe(true)
      expect(result.total).toBe(50)
      expect(result.records.length).toBeLessThanOrEqual(50)
    })

    test("queries with field:value syntax", async () => {
      const result = await OutputStore.query({
        sessionId: TEST_SESSION_ID,
        outputId,
        query: "state:open",
      })

      expect(result.found).toBe(true)
      expect(result.total).toBe(25) // First 25 are open
    })

    test("queries with numeric field:value", async () => {
      const result = await OutputStore.query({
        sessionId: TEST_SESSION_ID,
        outputId,
        query: "port:1005",
      })

      expect(result.found).toBe(true)
      expect(result.total).toBe(1)
      expect(result.records[0].port).toBe(1005)
    })

    test("queries with text search", async () => {
      const result = await OutputStore.query({
        sessionId: TEST_SESSION_ID,
        outputId,
        query: "ssh",
      })

      expect(result.found).toBe(true)
      expect(result.total).toBe(10) // First 10 have service "ssh"
    })

    test("respects limit parameter", async () => {
      const result = await OutputStore.query({
        sessionId: TEST_SESSION_ID,
        outputId,
        limit: 5,
      })

      expect(result.found).toBe(true)
      expect(result.records.length).toBe(5)
      expect(result.total).toBe(50) // Total is still 50
    })

    test("returns not found for invalid output ID", async () => {
      const result = await OutputStore.query({
        sessionId: TEST_SESSION_ID,
        outputId: "nonexistent",
      })

      expect(result.found).toBe(false)
      expect(result.error).toContain("not found")
    })

    test("filters by type", async () => {
      const result = await OutputStore.query({
        sessionId: TEST_SESSION_ID,
        outputId,
        type: "port",
      })

      expect(result.found).toBe(true)
      expect(result.records.every((r) => r.type === "port")).toBe(true)
    })
  })

  describe("formatQueryResults", () => {
    test("formats port records as table", () => {
      const records = [
        { type: "port", port: 22, protocol: "tcp", state: "open", service: "ssh", version: "8.2" },
        { type: "port", port: 80, protocol: "tcp", state: "open", service: "http", version: "" },
      ]

      const output = OutputStore.formatQueryResults(records, 2, 50)

      expect(output).toContain("| Port |")
      expect(output).toContain("| 22 |")
      expect(output).toContain("| 80 |")
    })

    test("formats directory records as table", () => {
      const records = [
        { type: "directory", path: "admin", status: 200, length: 1234 },
        { type: "directory", path: "login", status: 301, length: 0 },
      ]

      const output = OutputStore.formatQueryResults(records, 2, 50)

      expect(output).toContain("| Path |")
      expect(output).toContain("admin")
      expect(output).toContain("200")
    })

    test("shows truncation notice when total > returned", () => {
      const records = [{ type: "port", port: 22 }]

      const output = OutputStore.formatQueryResults(records, 100, 50)

      expect(output).toContain("Showing 1 of 100")
    })
  })

  describe("cleanup", () => {
    test("removes old outputs", async () => {
      // Create a directory with an old file
      fs.mkdirSync(OUTPUTS_DIR, { recursive: true })

      // Create an "old" output file (fake timestamp)
      const oldOutput = {
        id: "out_old_12345678",
        tool: "nmap",
        method: "port_scan",
        timestamp: Date.now() - 25 * 60 * 60 * 1000, // 25 hours ago
        records: [],
        summary: { total: 0, byType: {} },
        rawOutput: "",
        sizeBytes: 100,
      }

      const oldFilePath = path.join(OUTPUTS_DIR, "out_old_12345678.json")
      fs.writeFileSync(oldFilePath, JSON.stringify(oldOutput))

      // Run cleanup
      const result = await OutputStore.cleanup()

      expect(result.deleted).toBeGreaterThanOrEqual(1)
      expect(fs.existsSync(oldFilePath)).toBe(false)
    })
  })

  describe("cleanupSession", () => {
    test("removes entire session directory", async () => {
      // Create session with files
      fs.mkdirSync(OUTPUTS_DIR, { recursive: true })
      fs.writeFileSync(path.join(OUTPUTS_DIR, "test.json"), "{}")

      expect(fs.existsSync(OUTPUTS_DIR)).toBe(true)

      await OutputStore.cleanupSession(TEST_SESSION_ID)

      expect(fs.existsSync(OUTPUTS_DIR)).toBe(false)
    })
  })

  describe("getMetadata", () => {
    test("returns metadata for stored output", async () => {
      const ports = Array.from({ length: 50 }, (_, i) => ({ port: 1000 + i, state: "open" }))

      const storeResult = await OutputStore.store({
        sessionId: TEST_SESSION_ID,
        tool: "nmap",
        method: "port_scan",
        data: { hosts: [{ ip: "10.10.10.1", ports }] },
        rawOutput: "x".repeat(5000),
      })

      const metadata = await OutputStore.getMetadata(TEST_SESSION_ID, storeResult.outputId!)

      expect(metadata.found).toBe(true)
      expect(metadata.tool).toBe("nmap")
      expect(metadata.method).toBe("port_scan")
      expect(metadata.recordCount).toBe(50)
    })

    test("returns not found for invalid ID", async () => {
      const metadata = await OutputStore.getMetadata(TEST_SESSION_ID, "nonexistent")

      expect(metadata.found).toBe(false)
    })
  })
})
