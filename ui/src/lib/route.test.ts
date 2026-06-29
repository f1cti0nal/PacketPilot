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
  it("maps everything else to landing", () => {
    expect(resolveRoute("/")).toBe("landing");
    expect(resolveRoute("/pricing")).toBe("landing");
    expect(resolveRoute("/administrator")).toBe("landing");
    expect(resolveRoute("/accounts")).toBe("landing");
  });
});
