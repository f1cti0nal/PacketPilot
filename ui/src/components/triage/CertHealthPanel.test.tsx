import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "../../test/render";
import { CertHealthPanel } from "./CertHealthPanel";
import type { Finding } from "../../types";

const certFinding = (over: Partial<Finding> = {}): Finding => ({
  kind: "tls_cert_health",
  severity: "high",
  score: 68,
  title: "Suspicious TLS certificate: 10.0.0.5 -> 203.0.113.9:443 (self-signed, name-mismatch)",
  src_ip: "10.0.0.5",
  dst_ip: "203.0.113.9",
  dst_port: 443,
  attack: ["T1573", "T1557"],
  evidence: [
    "self-signed certificate (issuer matches subject — not chained to a trusted CA)",
    'certificate does not match the requested host "good.example" (no SAN/CN match)',
  ],
  interval_ns: null,
  jitter_cv: null,
  contacts: null,
  ...over,
});

describe("CertHealthPanel", () => {
  it("renders cert findings with evidence, endpoints, and ATT&CK tags", () => {
    render(<CertHealthPanel findings={[certFinding()]} />);
    expect(screen.getByText(/Suspicious TLS certificate/)).toBeInTheDocument();
    expect(screen.getByText(/self-signed certificate/)).toBeInTheDocument();
    expect(screen.getByText("203.0.113.9:443")).toBeInTheDocument();
    expect(screen.getByText("T1573")).toBeInTheDocument();
    expect(screen.getByText("T1557")).toBeInTheDocument();
  });

  it("renders nothing when there are no cert-health findings", () => {
    const { container } = render(
      <CertHealthPanel findings={[{ ...certFinding(), kind: "beacon" }]} />,
    );
    expect(container.querySelector('[data-component="CertHealthPanel"]')).toBeNull();
  });

  it("jumps to the server IP when a card is activated", () => {
    const onJump = vi.fn();
    render(<CertHealthPanel findings={[certFinding()]} onJump={onJump} />);
    fireEvent.click(screen.getByRole("button", { name: /View flows for 203\.0\.113\.9/ }));
    expect(onJump).toHaveBeenCalledWith("203.0.113.9");
  });
});
