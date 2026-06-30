import { describe, it, expect } from "vitest";
import { render, screen } from "../test/render";
import { CarvedFilesCard } from "./CarvedFilesCard";

describe("CarvedFilesCard", () => {
  it("shows each carved file's hash + a known-bad badge", () => {
    render(
      <CarvedFilesCard
        files={[
          {
            client: "10.0.0.9",
            server: "93.184.216.34",
            sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            size: 68,
            known_bad: true,
          },
          {
            client: "10.0.0.5",
            server: "1.2.3.4",
            sha256: "aaaa021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651ffff",
            size: 4096,
            known_bad: false,
          },
        ]}
      />,
    );
    expect(screen.getByText("Carved files")).toBeInTheDocument();
    expect(screen.getByText(/275a021bbfb6489e54d4/)).toBeInTheDocument();
    expect(screen.getByText("known-bad")).toBeInTheDocument(); // only the known-bad row
    expect(screen.getByText("10.0.0.9")).toBeInTheDocument();
  });

  it("renders nothing when nothing was carved", () => {
    render(<CarvedFilesCard files={[]} />);
    expect(screen.queryByText("Carved files")).toBeNull();
  });

  it("renders content-signature chips for a carved file", () => {
    render(
      <CarvedFilesCard
        files={[{
          client: "10.0.0.9", server: "1.2.3.4", sha256: "a".repeat(64), size: 4096, known_bad: false,
          signatures: ["PE/DOS executable", "UPX-packed executable"],
        }]}
      />,
    );
    expect(screen.getByText("PE/DOS executable")).toBeInTheDocument();
    expect(screen.getByText("UPX-packed executable")).toBeInTheDocument();
  });

  it("shows a malicious VirusTotal badge with the threat label, linking to the report", () => {
    render(
      <CarvedFilesCard
        files={[{
          client: "10.0.0.9", server: "1.2.3.4", sha256: "f".repeat(64), size: 2048, known_bad: false,
          reputation: [{ source: "virustotal", status: "malicious", malicious: true, score: 60, tags: ["trojan.emotet"], link: "https://www.virustotal.com/gui/file/abc", fetched_at: 1 }],
        }]}
      />,
    );
    const badge = screen.getByRole("link", { name: /trojan\.emotet/i });
    expect(badge.getAttribute("href")).toContain("virustotal.com");
  });

  it("shows a faint clean VirusTotal badge (no link) when there are no detections", () => {
    render(
      <CarvedFilesCard
        files={[{
          client: "10.0.0.9", server: "1.2.3.4", sha256: "f".repeat(64), size: 2048, known_bad: false,
          reputation: [{ source: "virustotal", status: "clean", malicious: false, score: 0, tags: [], link: null, fetched_at: 1 }],
        }]}
      />,
    );
    expect(screen.getByText(/VT/)).toBeInTheDocument();
    expect(screen.queryByRole("link")).toBeNull();
  });

  it("renders no VirusTotal badge when there is no reputation verdict", () => {
    render(
      <CarvedFilesCard
        files={[{ client: "10.0.0.9", server: "1.2.3.4", sha256: "f".repeat(64), size: 2048, known_bad: false }]}
      />,
    );
    expect(screen.queryByText(/VT/)).toBeNull();
  });

  it("renders no badge for an inconclusive (suspicious-only / unknown) verdict — only confirmed-malicious gets a chip", () => {
    render(
      <CarvedFilesCard
        files={[{
          client: "10.0.0.9", server: "1.2.3.4", sha256: "f".repeat(64), size: 2048, known_bad: false,
          reputation: [{ source: "virustotal", status: "unknown", malicious: false, score: 0, tags: [], link: null, fetched_at: 1 }],
        }]}
      />,
    );
    expect(screen.queryByText(/VT/)).toBeNull();
  });
});
