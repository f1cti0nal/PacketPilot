import { describe, it, expect } from "vitest";
import { render, screen } from "../test/render";
import { CaptureIntegrity } from "./CaptureIntegrity";
import { makeOutput } from "../test/fixtures";

describe("CaptureIntegrity", () => {
  it("renders the integrity card", () => {
    render(<CaptureIntegrity output={makeOutput()} />);
    expect(screen.getByText(/Capture integrity/i)).toBeInTheDocument();
  });
  it("does not crash when source_sha256 is null", () => {
    const o = makeOutput({ source_sha256: null as unknown as string });
    expect(() => render(<CaptureIntegrity output={o} />)).not.toThrow();
  });
});
