import { describe, it, expect } from "vitest";
import { serviceName } from "./services";

describe("serviceName", () => {
  it("names well-known ports and returns null for non-standard ports", () => {
    expect(serviceName(443)).toBe("HTTPS");
    expect(serviceName(22)).toBe("SSH");
    expect(serviceName(53)).toBe("DNS");
    expect(serviceName(3389)).toBe("RDP");
    expect(serviceName(44444)).toBeNull();
    expect(serviceName(0)).toBeNull();
  });
});
