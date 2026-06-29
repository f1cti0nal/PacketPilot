import { describe, expect, it } from "vitest";
import { resolveRoute } from "./route";

describe("resolveRoute", () => {
  it("maps /admin and subpaths to admin", () => {
    expect(resolveRoute("/admin")).toBe("admin");
    expect(resolveRoute("/admin/")).toBe("admin");
    expect(resolveRoute("/admin/users")).toBe("admin");
  });
  it("maps /app and subpaths to app", () => {
    expect(resolveRoute("/app")).toBe("app");
    expect(resolveRoute("/app/flows")).toBe("app");
  });
  it("maps /account and subpaths to account", () => {
    expect(resolveRoute("/account")).toBe("account");
    expect(resolveRoute("/account/")).toBe("account");
    expect(resolveRoute("/account/billing")).toBe("account");
  });
  it("maps the legal paths to legal", () => {
    expect(resolveRoute("/security")).toBe("legal");
    expect(resolveRoute("/privacy")).toBe("legal");
    expect(resolveRoute("/terms")).toBe("legal");
    expect(resolveRoute("/terms/")).toBe("legal");
  });
  it("does not match near-misses of the legal paths", () => {
    expect(resolveRoute("/security-policy")).toBe("landing");
    expect(resolveRoute("/privacy/extra")).toBe("landing");
  });
  it("maps /pricing to pricing (exact only)", () => {
    expect(resolveRoute("/pricing")).toBe("pricing");
    expect(resolveRoute("/pricing/")).toBe("pricing");
    expect(resolveRoute("/pricing-plans")).toBe("landing");
  });
  it("maps the SEO tool slugs to tool", () => {
    expect(resolveRoute("/analyze-pcap-online")).toBe("tool");
    expect(resolveRoute("/wireshark-alternative")).toBe("tool");
    expect(resolveRoute("/extract-files-from-pcap/")).toBe("tool");
    expect(resolveRoute("/analyze-pcap")).toBe("landing"); // near-miss
  });
  it("maps everything else to landing", () => {
    expect(resolveRoute("/")).toBe("landing");
    expect(resolveRoute("/features")).toBe("landing");
    expect(resolveRoute("/administrator")).toBe("landing");
    expect(resolveRoute("/accounts")).toBe("landing");
  });
});
