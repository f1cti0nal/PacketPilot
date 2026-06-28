import { describe, expect, it } from "vitest";
import { TAB_IDS } from "../../types";
import { ADMIN_SECTIONS } from "../../admin/sections";
import { ROUTES_FOR_TESTS } from "./track";

describe("tracker route allowlist drift guard", () => {
  it("covers every app tab and admin section", () => {
    for (const t of TAB_IDS) expect(ROUTES_FOR_TESTS.has(`/app#${t}`)).toBe(true);
    for (const s of ADMIN_SECTIONS) expect(ROUTES_FOR_TESTS.has(`/admin#${s.id}`)).toBe(true);
    expect(ROUTES_FOR_TESTS.has("/")).toBe(true);
  });
});
