import { describe, expect, test } from "bun:test"
import { TargetValidation } from "../../src/util/target-validation"

describe("tool.target-validation", () => {
  describe("isPrivateIP", () => {
    test("detects 10.x.x.x as private", () => {
      expect(TargetValidation.isPrivateIP("10.0.0.1")).toBe(true)
      expect(TargetValidation.isPrivateIP("10.10.10.1")).toBe(true)
      expect(TargetValidation.isPrivateIP("10.255.255.255")).toBe(true)
    })

    test("detects 172.16-31.x.x as private", () => {
      expect(TargetValidation.isPrivateIP("172.16.0.1")).toBe(true)
      expect(TargetValidation.isPrivateIP("172.20.0.1")).toBe(true)
      expect(TargetValidation.isPrivateIP("172.31.255.255")).toBe(true)
    })

    test("detects 172.15.x.x as NOT private", () => {
      expect(TargetValidation.isPrivateIP("172.15.0.1")).toBe(false)
      expect(TargetValidation.isPrivateIP("172.32.0.1")).toBe(false)
    })

    test("detects 192.168.x.x as private", () => {
      expect(TargetValidation.isPrivateIP("192.168.0.1")).toBe(true)
      expect(TargetValidation.isPrivateIP("192.168.1.100")).toBe(true)
    })

    test("detects 127.x.x.x as private (loopback)", () => {
      expect(TargetValidation.isPrivateIP("127.0.0.1")).toBe(true)
      expect(TargetValidation.isPrivateIP("127.0.1.1")).toBe(true)
    })

    test("detects 169.254.x.x as private (link-local)", () => {
      expect(TargetValidation.isPrivateIP("169.254.0.1")).toBe(true)
      expect(TargetValidation.isPrivateIP("169.254.255.255")).toBe(true)
    })

    test("detects public IPs as NOT private", () => {
      expect(TargetValidation.isPrivateIP("8.8.8.8")).toBe(false)
      expect(TargetValidation.isPrivateIP("1.1.1.1")).toBe(false)
      expect(TargetValidation.isPrivateIP("142.250.185.46")).toBe(false)
    })

    test("handles invalid IPs", () => {
      expect(TargetValidation.isPrivateIP("invalid")).toBe(false)
      expect(TargetValidation.isPrivateIP("256.0.0.1")).toBe(false)
      expect(TargetValidation.isPrivateIP("10.0.0")).toBe(false)
    })
  })

  describe("isInternalHostname", () => {
    test("detects .htb as internal (HackTheBox)", () => {
      expect(TargetValidation.isInternalHostname("target.htb")).toBe(true)
      expect(TargetValidation.isInternalHostname("box.htb")).toBe(true)
    })

    test("detects .local as internal", () => {
      expect(TargetValidation.isInternalHostname("myserver.local")).toBe(true)
    })

    test("detects .internal as internal", () => {
      expect(TargetValidation.isInternalHostname("corp.internal")).toBe(true)
    })

    test("detects .lab as internal", () => {
      expect(TargetValidation.isInternalHostname("lab1.lab")).toBe(true)
    })

    test("detects external hostnames", () => {
      expect(TargetValidation.isInternalHostname("google.com")).toBe(false)
      expect(TargetValidation.isInternalHostname("example.org")).toBe(false)
    })
  })

  describe("extractTarget", () => {
    test("extracts IP from bare IP", () => {
      const result = TargetValidation.extractTarget("10.10.10.1")
      expect(result.ip).toBe("10.10.10.1")
      expect(result.hostname).toBeUndefined()
    })

    test("extracts IP from URL", () => {
      const result = TargetValidation.extractTarget("http://10.10.10.1:8080/path")
      expect(result.ip).toBe("10.10.10.1")
      expect(result.hostname).toBeUndefined()
    })

    test("extracts hostname from URL", () => {
      const result = TargetValidation.extractTarget("https://target.htb/admin")
      expect(result.hostname).toBe("target.htb")
      expect(result.ip).toBeUndefined()
    })

    test("extracts hostname from bare hostname", () => {
      const result = TargetValidation.extractTarget("target.htb")
      expect(result.hostname).toBe("target.htb")
      expect(result.ip).toBeUndefined()
    })
  })

  describe("classifyTarget", () => {
    test("classifies private IP as private", () => {
      const info = TargetValidation.classifyTarget("10.10.10.1")
      expect(info.type).toBe("private")
      expect(info.isExternal).toBe(false)
      expect(info.requiresConfirmation).toBe(false)
    })

    test("classifies public IP as external", () => {
      const info = TargetValidation.classifyTarget("8.8.8.8")
      expect(info.type).toBe("external")
      expect(info.isExternal).toBe(true)
      expect(info.requiresConfirmation).toBe(true)
    })

    test("classifies .htb hostname as internal", () => {
      const info = TargetValidation.classifyTarget("target.htb")
      expect(info.type).toBe("internal")
      expect(info.isExternal).toBe(false)
    })

    test("classifies .com hostname as external", () => {
      const info = TargetValidation.classifyTarget("example.com")
      expect(info.type).toBe("external")
      expect(info.isExternal).toBe(true)
    })
  })

  describe("isHighRiskTarget", () => {
    test("detects .gov as high-risk", () => {
      const result = TargetValidation.isHighRiskTarget("whitehouse.gov")
      expect(result.highRisk).toBe(true)
      expect(result.category).toBe("government")
    })

    test("detects .gov.xx as high-risk", () => {
      const result = TargetValidation.isHighRiskTarget("service.gov.uk")
      expect(result.highRisk).toBe(true)
      expect(result.category).toBe("government")
    })

    test("detects .mil as high-risk", () => {
      const result = TargetValidation.isHighRiskTarget("army.mil")
      expect(result.highRisk).toBe(true)
      expect(result.category).toBe("military")
    })

    test("detects .edu as high-risk", () => {
      const result = TargetValidation.isHighRiskTarget("mit.edu")
      expect(result.highRisk).toBe(true)
      expect(result.category).toBe("educational")
    })

    test("does not flag .com as high-risk", () => {
      const result = TargetValidation.isHighRiskTarget("example.com")
      expect(result.highRisk).toBe(false)
    })

    test("does not flag .htb as high-risk", () => {
      const result = TargetValidation.isHighRiskTarget("target.htb")
      expect(result.highRisk).toBe(false)
    })
  })

  describe("validateTarget", () => {
    test("validates private IP without warnings", () => {
      const result = TargetValidation.validateTarget("10.10.10.1")
      expect(result.valid).toBe(true)
      expect(result.info.isExternal).toBe(false)
      expect(result.highRisk).toBe(false)
    })

    test("validates public IP with external warning", () => {
      const result = TargetValidation.validateTarget("8.8.8.8")
      expect(result.valid).toBe(true)
      expect(result.info.isExternal).toBe(true)
      expect(result.highRisk).toBe(false)
    })

    test("validates .gov with high-risk warning", () => {
      const result = TargetValidation.validateTarget("https://whitehouse.gov")
      expect(result.valid).toBe(true)
      expect(result.highRisk).toBe(true)
      expect(result.highRiskWarning).toContain("government")
    })

    test("never blocks targets (always valid)", () => {
      // Even high-risk targets should be valid - just warned
      const result = TargetValidation.validateTarget("pentagon.mil")
      expect(result.valid).toBe(true)
      expect(result.forbidden).toBe(false)
    })
  })
})
