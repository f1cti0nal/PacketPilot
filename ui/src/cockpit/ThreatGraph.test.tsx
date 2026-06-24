import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "../test/render";
import { ThreatGraph } from "./ThreatGraph";
import { makeOutput } from "../test/fixtures";
import type { Finding } from "../types";

describe("ThreatGraph", () => {
  it("renders related hosts as clickable nodes and jumps to flows on click or Enter", () => {
    const s = makeOutput().summary;
    const onJump = vi.fn();
    render(<ThreatGraph findings={s.findings ?? []} threats={s.ip_threats ?? []} onJump={onJump} />);
    expect(screen.getByLabelText("Threat relationship graph")).toBeInTheDocument();
    const node = screen.getByRole("button", { name: /View flows for 45\.77\.13\.37/ });
    fireEvent.click(node);
    expect(onJump).toHaveBeenCalledWith("45.77.13.37");
    // Keyboard activation jumps too.
    fireEvent.keyDown(screen.getByRole("button", { name: /View flows for 185\.220\.101\.5/ }), { key: "Enter" });
    expect(onJump).toHaveBeenCalledWith("185.220.101.5");
  });

  it("renders nothing when fewer than two hosts are related", () => {
    const findings: Finding[] = [
      {
        kind: "host_sweep", severity: "high", score: 65, src_ip: "10.0.0.5", dst_ip: null,
        dst_port: null, attack: [], evidence: [], interval_ns: null, jitter_cv: null,
        contacts: null, title: "sweep",
      },
    ];
    const { container } = render(<ThreatGraph findings={findings} threats={[]} />);
    expect(container.querySelector('[data-component="ThreatGraph"]')).toBeNull();
  });
});
