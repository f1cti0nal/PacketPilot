import { describe, expect, it } from "vitest";
import { socialProviders } from "./socialProviders";

describe("socialProviders", () => {
  it("defaults to Google + GitHub when the env is unset", () => {
    const out = socialProviders(undefined);
    expect(out.map((p) => p.provider)).toEqual(["google", "github"]);
    expect(out.map((p) => p.label)).toEqual(["Google", "GitHub"]);
  });

  it("honors the env order and a subset", () => {
    expect(socialProviders("github,google").map((p) => p.provider)).toEqual(["github", "google"]);
    expect(socialProviders("google").map((p) => p.provider)).toEqual(["google"]);
  });

  it("ignores unknown provider ids and de-dupes", () => {
    expect(socialProviders("google,facebook,google").map((p) => p.provider)).toEqual(["google"]);
  });

  it("returns none for an empty / whitespace list", () => {
    expect(socialProviders("")).toEqual([]);
    expect(socialProviders("  ,  ")).toEqual([]);
  });
});
