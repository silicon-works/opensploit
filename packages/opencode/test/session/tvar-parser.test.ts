import { describe, expect, test } from "bun:test"
import {
  parseTVAR,
  hasTVAR,
  extractPhase,
  validateTVARBeforeToolCall,
  stripTVARBlocks,
  type TVARBlock,
} from "../../src/session/tvar-parser"

describe("parseTVAR", () => {
  test("should parse complete TVAR block with all fields", () => {
    const text = `
<thought>
I need to scan the target for open ports to identify potential attack vectors.
This is the reconnaissance phase.
</thought>

<verify>
Using nmap is appropriate for port scanning during reconnaissance phase.
Not an anti-pattern - this is the recommended tool for port discovery.
</verify>

<action>
Running nmap TCP SYN scan on target 10.10.10.1
</action>

<result>
Found open ports: 22 (SSH), 80 (HTTP), 443 (HTTPS)
</result>
`
    const blocks = parseTVAR(text)
    expect(blocks.length).toBe(1)
    expect(blocks[0].thought).toContain("scan the target for open ports")
    expect(blocks[0].verify).toContain("nmap is appropriate")
    expect(blocks[0].action).toContain("Running nmap")
    expect(blocks[0].result).toContain("Found open ports")
  })

  test("should parse minimal TVAR block with only thought and verify", () => {
    const text = `
<thought>Analyzing the results from the port scan</thought>
<verify>Proceeding to enumeration phase based on findings</verify>
`
    const blocks = parseTVAR(text)
    expect(blocks.length).toBe(1)
    expect(blocks[0].thought).toBe("Analyzing the results from the port scan")
    expect(blocks[0].verify).toBe("Proceeding to enumeration phase based on findings")
    expect(blocks[0].action).toBeUndefined()
    expect(blocks[0].result).toBeUndefined()
  })

  test("should not parse incomplete block missing verify", () => {
    const text = `
<thought>Just a thought without verification</thought>
Some other text
`
    const blocks = parseTVAR(text)
    expect(blocks.length).toBe(0)
  })

  test("should parse multiple TVAR blocks", () => {
    const text = `
<thought>First thought</thought>
<verify>First verify</verify>

Some text between blocks

<thought>Second thought</thought>
<verify>Second verify</verify>
<action>Second action</action>
`
    const blocks = parseTVAR(text)
    expect(blocks.length).toBe(2)
    expect(blocks[0].thought).toBe("First thought")
    expect(blocks[1].thought).toBe("Second thought")
    expect(blocks[1].action).toBe("Second action")
  })

  test("should include position information for stripping", () => {
    const text = "prefix<thought>t</thought><verify>v</verify>suffix"
    const blocks = parseTVAR(text)
    expect(blocks.length).toBe(1)
    expect(blocks[0].startIndex).toBe(6) // after "prefix"
    expect(blocks[0].endIndex).toBe(44) // before "suffix"
    expect(blocks[0].raw).toBe("<thought>t</thought><verify>v</verify>")
  })

  test("should be case insensitive for tags", () => {
    const text = "<THOUGHT>Uppercase</THOUGHT><VERIFY>Also uppercase</VERIFY>"
    const blocks = parseTVAR(text)
    expect(blocks.length).toBe(1)
    expect(blocks[0].thought).toBe("Uppercase")
  })
})

describe("hasTVAR", () => {
  test("should return true for complete TVAR", () => {
    expect(hasTVAR("<thought>t</thought><verify>v</verify>")).toBe(true)
  })

  test("should return false for missing thought", () => {
    expect(hasTVAR("<verify>v</verify>")).toBe(false)
  })

  test("should return false for missing verify", () => {
    expect(hasTVAR("<thought>t</thought>")).toBe(false)
  })

  test("should return false for empty string", () => {
    expect(hasTVAR("")).toBe(false)
  })
})

describe("extractPhase", () => {
  test("should extract reconnaissance phase", () => {
    const block: TVARBlock = {
      thought: "I need to perform reconnaissance to discover the attack surface",
      verify: "Using nmap for initial port scan",
      raw: "",
      startIndex: 0,
      endIndex: 0,
    }
    expect(extractPhase(block)).toBe("reconnaissance")
  })

  test("should extract enumeration phase", () => {
    const block: TVARBlock = {
      thought: "Enumerating web directories to find hidden endpoints",
      verify: "Directory fuzzing is appropriate here",
      raw: "",
      startIndex: 0,
      endIndex: 0,
    }
    expect(extractPhase(block)).toBe("enumeration")
  })

  test("should extract exploitation phase", () => {
    const block: TVARBlock = {
      thought: "Time to exploit the SQL injection vulnerability",
      verify: "Using sqlmap for injection testing",
      raw: "",
      startIndex: 0,
      endIndex: 0,
    }
    expect(extractPhase(block)).toBe("exploitation")
  })

  test("should extract post_exploitation phase", () => {
    const block: TVARBlock = {
      thought: "Need to escalate privileges to root",
      verify: "Checking for privesc vectors",
      raw: "",
      startIndex: 0,
      endIndex: 0,
    }
    expect(extractPhase(block)).toBe("post_exploitation")
  })

  test("should extract reporting phase", () => {
    const block: TVARBlock = {
      thought: "Generating final report of findings",
      verify: "Summary of all discovered vulnerabilities",
      raw: "",
      startIndex: 0,
      endIndex: 0,
    }
    expect(extractPhase(block)).toBe("reporting")
  })

  test("should return undefined for unclear phase", () => {
    const block: TVARBlock = {
      thought: "Doing something generic",
      verify: "Checking things",
      raw: "",
      startIndex: 0,
      endIndex: 0,
    }
    expect(extractPhase(block)).toBeUndefined()
  })
})

describe("validateTVARBeforeToolCall", () => {
  test("should pass valid TVAR block", () => {
    const block: TVARBlock = {
      thought: "I need to scan the target for open ports to understand the attack surface",
      verify: "Using nmap is the appropriate tool for port scanning during reconnaissance",
      raw: "",
      startIndex: 0,
      endIndex: 0,
    }
    const result = validateTVARBeforeToolCall(block)
    expect(result.valid).toBe(true)
    expect(result.issues.length).toBe(0)
  })

  test("should fail for too brief thought", () => {
    const block: TVARBlock = {
      thought: "Scan it",
      verify: "Using nmap tool",
      raw: "",
      startIndex: 0,
      endIndex: 0,
    }
    const result = validateTVARBeforeToolCall(block)
    expect(result.valid).toBe(false)
    expect(result.issues).toContain("Thought is too brief - should explain objective and context")
  })

  test("should warn about curl for SQL injection", () => {
    const block: TVARBlock = {
      thought: "Testing for SQL injection vulnerability on the login form",
      verify: "Using curl to send SQL payloads to the endpoint",
      raw: "",
      startIndex: 0,
      endIndex: 0,
    }
    const result = validateTVARBeforeToolCall(block)
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.includes("curl") && i.includes("specialized tool"))).toBe(true)
  })

  test("should warn about custom code", () => {
    const block: TVARBlock = {
      thought: "Need to write an exploit for this vulnerability",
      verify: "Writing custom code to exploit the buffer overflow",
      raw: "",
      startIndex: 0,
      endIndex: 0,
    }
    const result = validateTVARBeforeToolCall(block)
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.includes("custom code"))).toBe(true)
  })
})

describe("stripTVARBlocks", () => {
  test("should strip single TVAR block", () => {
    const text = "prefix<thought>t</thought><verify>v</verify>suffix"
    const blocks = parseTVAR(text)
    const stripped = stripTVARBlocks(text, blocks)
    expect(stripped).toBe("prefixsuffix")
  })

  test("should strip multiple TVAR blocks", () => {
    const text = "a<thought>1</thought><verify>1</verify>b<thought>2</thought><verify>2</verify>c"
    const blocks = parseTVAR(text)
    const stripped = stripTVARBlocks(text, blocks)
    expect(stripped).toBe("abc")
  })

  test("should handle empty blocks array", () => {
    const text = "no tvar here"
    const stripped = stripTVARBlocks(text, [])
    expect(stripped).toBe("no tvar here")
  })

  test("should trim result", () => {
    const text = "  <thought>t</thought><verify>v</verify>  "
    const blocks = parseTVAR(text)
    const stripped = stripTVARBlocks(text, blocks)
    expect(stripped).toBe("")
  })
})
