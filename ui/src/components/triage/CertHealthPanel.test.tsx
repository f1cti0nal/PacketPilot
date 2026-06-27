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

const weakFinding = (over: Partial<Finding> = {}): Finding => ({
  ...certFinding(),
  kind: "weak_tls",
  severity: "medium",
  score: 44,
  title: "Weak TLS: 10.0.0.5 -> 198.51.100.7:443 (weak-cipher)",
  dst_ip: "198.51.100.7",
  attack: ["T1040"],
  evidence: ["weak cipher suite negotiated: TLS_RSA_WITH_RC4_128_SHA"],
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

  it("also renders weak-TLS findings in the same panel", () => {
    render(<CertHealthPanel findings={[certFinding(), weakFinding()]} />);
    expect(screen.getByText(/Suspicious TLS certificate/)).toBeInTheDocument();
    expect(screen.getByText(/Weak TLS/)).toBeInTheDocument();
    expect(screen.getByText(/RC4/)).toBeInTheDocument();
    expect(screen.getByText("198.51.100.7:443")).toBeInTheDocument();
  });

  it("renders nothing when there are no TLS findings", () => {
    const { container } = render(
      <CertHealthPanel findings={[{ ...certFinding(), kind: "beacon" }]} />,
    );
    expect(container.firstChild).toBeNull();
  });

  it("jumps to the server IP when a card is activated", () => {
    const onJump = vi.fn();
    render(<CertHealthPanel findings={[certFinding()]} onJump={onJump} />);
    fireEvent.click(screen.getByRole("button", { name: /View flows for 203\.0\.113\.9/ }));
    expect(onJump).toHaveBeenCalledWith("203.0.113.9");
  });
});
