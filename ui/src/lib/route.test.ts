import { describe, expect, it } from "vitest";
import { resolveRoute, isAdminHost, resolveRouteFor } from "./route";

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
  it("maps the retired gated-SaaS paths to landing (routes removed in the free pivot)", () => {
    expect(resolveRoute("/pricing")).toBe("landing");
    expect(resolveRoute("/login")).toBe("landing");
    expect(resolveRoute("/signup")).toBe("landing");
    expect(resolveRoute("/logout")).toBe("landing");
    expect(resolveRoute("/account")).toBe("landing");
    expect(resolveRoute("/account/billing")).toBe("landing");
  });
  it("maps the SEO tool slugs to tool", () => {
    expect(resolveRoute("/analyze-pcap-online")).toBe("tool");
    expect(resolveRoute("/wireshark-alternative")).toBe("tool");
    expect(resolveRoute("/extract-files-from-pcap/")).toBe("tool");
    expect(resolveRoute("/analyze-pcap")).toBe("landing"); // near-miss
  });
  it("maps /blog and post paths to blog", () => {
    expect(resolveRoute("/blog")).toBe("blog");
    expect(resolveRoute("/blog/")).toBe("blog");
    expect(resolveRoute("/blog/anatomy-of-a-pcap-kill-chain")).toBe("blog");
    expect(resolveRoute("/blogger")).toBe("landing"); // near-miss
  });
  it("maps everything else to landing", () => {
    expect(resolveRoute("/")).toBe("landing");
    expect(resolveRoute("/features")).toBe("landing");
    expect(resolveRoute("/administrator")).toBe("landing");
    expect(resolveRoute("/accounts")).toBe("landing");
  });
});

describe("admin subdomain isolation", () => {
  it("recognizes the admin subdomain host", () => {
    expect(isAdminHost("admin.packetpilot.app")).toBe(true);
    expect(isAdminHost("ADMIN.packetpilot.app")).toBe(true);
    expect(isAdminHost("packetpilot.app")).toBe(false);
    expect(isAdminHost("admincentral.packetpilot.app")).toBe(false); // must be the "admin." label
    expect(isAdminHost("www.packetpilot.app")).toBe(false);
  });

  it("serves admin for any path on the admin host", () => {
    expect(resolveRouteFor("admin.packetpilot.app", "/")).toBe("admin");
    expect(resolveRouteFor("admin.packetpilot.app", "/anything")).toBe("admin");
  });

  it("routes by pathname on the main host (admin still reachable there for now)", () => {
    expect(resolveRouteFor("packetpilot.app", "/")).toBe("landing");
    expect(resolveRouteFor("packetpilot.app", "/app")).toBe("app");
    expect(resolveRouteFor("packetpilot.app", "/admin")).toBe("admin");
    expect(resolveRouteFor("packetpilot.app", "/pricing")).toBe("landing");
  });
});
