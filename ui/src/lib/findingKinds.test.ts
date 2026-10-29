import { describe, it, expect } from "vitest";
import { Activity } from "lucide-react";
import { KIND_META, kindLabel, kindMeta } from "./findingKinds";
import type { FindingKind } from "../types";

describe("findingKinds", () => {
  it("labels the exposed-remote-access kind", () => {
    expect(kindLabel("exposed_remote_access")).toBe("Exposed Remote Access");
    expect(KIND_META.exposed_remote_access.Icon).not.toBe(Activity); // a dedicated, non-fallback icon
  });

  it("labels the Windows identity-attack kinds with dedicated icons", () => {
    expect(kindLabel("kerberoasting")).toBe("Kerberoasting");
    expect(kindLabel("asrep_roasting")).toBe("AS-REP Roasting");
    expect(kindLabel("dcsync")).toBe("DCSync");
    expect(kindLabel("ad_recon")).toBe("AD Reconnaissance");
    expect(kindLabel("legacy_auth")).toBe("Legacy Auth Crypto");
    expect(kindLabel("remote_service_exec")).toBe("Remote Service Execution");
    expect(kindLabel("password_spray")).toBe("Password Spray");
    for (const k of [
      "kerberoasting",
      "asrep_roasting",
      "dcsync",
      "ad_recon",
      "legacy_auth",
      "remote_service_exec",
      "password_spray",
    ] as const) {
      expect(KIND_META[k].Icon, k).not.toBe(Activity);
    }
  });

  it("every known kind has a non-empty label", () => {
    for (const [kind, meta] of Object.entries(KIND_META)) {
      expect(meta.label.length, kind).toBeGreaterThan(0);
      expect(kindLabel(kind as FindingKind)).toBe(meta.label);
    }
  });

  it("falls back to a title-cased label + generic icon for an unknown kind", () => {
    expect(kindLabel("some_new_kind")).toBe("Some New Kind");
    expect(kindMeta("some_new_kind").Icon).toBe(Activity);
  });
});
