import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { FindingTarget } from "./FindingTarget";

describe("FindingTarget", () => {
  it("renders src → ip:port when a finding names a peer host and port", () => {
    render(<FindingTarget finding={{ src_ip: "10.0.0.5", dst_ip: "8.8.8.8", dst_port: 443 }} />);
    expect(screen.getByText("10.0.0.5")).toBeInTheDocument();
    expect(screen.getByText("8.8.8.8:443")).toBeInTheDocument();
  });

  it("renders 'port N' when a finding names only a service port (per-port anomaly)", () => {
    const { container } = render(
      <FindingTarget finding={{ src_ip: "10.0.0.5", dst_ip: null, dst_port: 4444 }} />,
    );
    expect(screen.getByText("port 4444")).toBeInTheDocument();
    expect(container.firstChild).not.toBeNull();
  });

  it("renders nothing for a finding that names no destination", () => {
    const { container } = render(
      <FindingTarget finding={{ src_ip: "10.0.0.5", dst_ip: null, dst_port: null }} />,
    );
    expect(container.firstChild).toBeNull();
  });
});
