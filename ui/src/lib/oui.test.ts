import { describe, it, expect } from "vitest";
import { vendorForMac } from "./oui";

describe("vendorForMac", () => {
  it("identifies well-known OUIs case-insensitively", () => {
    expect(vendorForMac("00:0c:29:ab:cd:ef")).toBe("VMware");
    expect(vendorForMac("B8:27:EB:12:34:56")).toBe("Raspberry Pi");
    expect(vendorForMac("52:54:00:aa:bb:cc")).toBe("QEMU / KVM");
  });

  it("returns null for an unknown or malformed MAC", () => {
    expect(vendorForMac("de:ad:be:ef:00:01")).toBeNull();
    expect(vendorForMac("")).toBeNull();
    expect(vendorForMac("00:0c")).toBeNull();
  });
});
