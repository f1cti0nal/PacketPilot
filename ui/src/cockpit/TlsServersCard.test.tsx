import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { TlsServersCard } from "./TlsServersCard";
import type { TlsServerPosture } from "../types";

function server(over: Partial<TlsServerPosture> = {}): TlsServerPosture {
  return {
    server: "185.220.101.9",
    port: 443,
    tls_version: "TLS 1.3",
    tls_cipher: "TLS_AES_128_GCM_SHA256",
    ja3s: null,
    ja4s: "t130200_1301_234ea6891581",
    sni: "api.example.com",
    flows: 12,
    bytes: 40_000,
    clients: 3,
    ...over,
  };
}

describe("TlsServersCard", () => {
  it("hides itself when no server handshake was observed", () => {
    const { container } = render(<TlsServersCard servers={[]} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders the endpoint, negotiated version, and the modern server fingerprint", () => {
    render(<TlsServersCard servers={[server()]} />);
    expect(screen.getByText("185.220.101.9:443")).toBeTruthy();
    expect(screen.getByText("TLS 1.3")).toBeTruthy();
    // JA4S is preferred over the legacy JA3S when both are present.
    expect(screen.getByText(/JA4S/)).toBeTruthy();
  });

  it("falls back to JA3S when no JA4S was recovered", () => {
    render(
      <TlsServersCard
        servers={[server({ ja4s: null, ja3s: "a1b2c3d4e5f60718293a4b5c6d7e8f90" })]}
      />,
    );
    expect(screen.getByText(/JA3S/)).toBeTruthy();
  });

  it("pivots to the flows view when a server is clicked", async () => {
    const onJump = vi.fn();
    render(<TlsServersCard servers={[server()]} onJump={onJump} />);
    await userEvent.click(screen.getByText("185.220.101.9:443"));
    expect(onJump).toHaveBeenCalledWith("185.220.101.9");
  });
});
