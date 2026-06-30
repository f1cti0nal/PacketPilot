import { describe, it, expect, vi } from "vitest";
import { act } from "react";
import { render, screen, userEvent, sizeScrollElement } from "../test/render";
import type { RenderResult } from "@testing-library/react";
import { PacketInspector } from "./PacketInspector";
import { makePackets, makeFlows } from "../test/fixtures";

const flow = makeFlows(1)[0];

// jsdom doesn't implement File.text() (it's standard in real browsers, the deploy target),
// so give the test file a working text() that returns its content.
function keylogFile(content = "CLIENT_TRAFFIC_SECRET_0 ab cd\n"): File {
  const f = new File([content], "keys.log", { type: "text/plain" });
  Object.defineProperty(f, "text", { value: () => Promise.resolve(content) });
  return f;
}

describe("PacketInspector", () => {
  it("loading state renders Extracting text", () => {
    render(<PacketInspector flow={flow} packets={null} loading error={null} onClose={() => {}} />);
    expect(screen.getByText(/extracting/i)).toBeInTheDocument();
  });

  it("empty state renders no-packets message", () => {
    render(
      <PacketInspector
        flow={flow}
        packets={{ total: 0, truncated: false, packets: [] }}
        loading={false}
        error={null}
        onClose={() => {}}
      />
    );
    expect(screen.getByText(/no packets/i)).toBeInTheDocument();
  });

  it("error state renders the error message", () => {
    render(
      <PacketInspector
        flow={flow}
        packets={null}
        loading={false}
        error="Failed to extract packets"
        onClose={() => {}}
      />
    );
    expect(screen.getByText(/Failed to extract packets/)).toBeInTheDocument();
  });

  it("renders rows and selected packet hex in the viewer (row 0 default-selected)", async () => {
    render(
      <PacketInspector
        flow={flow}
        packets={makePackets()}
        loading={false}
        error={null}
        onClose={() => {}}
      />
    );

    // The hex viewer (bottom panel) is NOT virtualized and renders immediately.
    // Packet 0 payload is "GET / HTTP/1.1\r\n" — 16 bytes.
    // hexLines produces exactly one row: offset "00000000", hex, and ascii.
    // Assert on the hex bytes column — proves hexLines ran on the real payload.
    expect(screen.getByText("47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a")).toBeInTheDocument();

    // Size the scroll container so the virtualizer materializes list rows.
    // Must be wrapped in act() so React processes the ResizeObserver-triggered re-render.
    const scrollEl = document.querySelector(".min-h-0.flex-1.overflow-y-auto") as HTMLElement;
    act(() => { sizeScrollElement(scrollEl); });

    // Now the list rows should be visible — packet index 0 row.
    // The ascii preview for "GET / HTTP/1.1\r\n" is "GET / HTTP/1.1.." (dots for \r\n).
    const previews = screen.getAllByText(/GET \/ HTTP/);
    // At least one match: the ascii-preview column in the list row.
    expect(previews.length).toBeGreaterThanOrEqual(1);
  });

  it("selecting a different packet updates the hex viewer", async () => {
    const u = userEvent.setup();
    render(
      <PacketInspector
        flow={flow}
        packets={makePackets()}
        loading={false}
        error={null}
        onClose={() => {}}
      />
    );

    // Size the scroll container so virtualizer renders rows.
    // Must be wrapped in act() so React processes the ResizeObserver-triggered re-render.
    const scrollEl = document.querySelector(".min-h-0.flex-1.overflow-y-auto") as HTMLElement;
    act(() => { sizeScrollElement(scrollEl); });

    // Click the second row (index 1, "HTTP/1.1 200 OK\r\n").
    // asciiPreview of "HTTP/1.1 200 OK\r\n" is "HTTP/1.1 200 OK.."
    // Use getAllByText to handle potential multi-match and pick the list row span.
    const row1Previews = screen.getAllByText(/HTTP\/1\.1 200 OK/);
    await u.click(row1Previews[0]);

    // After clicking row 1, hex viewer should show payload for "HTTP/1.1 200 OK\r\n".
    // H=48, T=54, T=54, P=50, /=2f, 1=31, .=2e, 1=31, space=20, 2=32, 0=30, 0=30, space=20, O=4f, K=4b, \r=0d
    // \n=0a — wait, "HTTP/1.1 200 OK\r\n" = 17 bytes → two hex rows (16 + 1).
    // First row hex: 48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d
    expect(screen.getByText("48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d")).toBeInTheDocument();
  });

  it("Escape key calls onClose", async () => {
    const u = userEvent.setup();
    const onClose = vi.fn();
    render(
      <PacketInspector
        flow={flow}
        packets={makePackets()}
        loading={false}
        error={null}
        onClose={onClose}
      />
    );
    await u.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledOnce();
  });

  it("close button calls onClose", async () => {
    const u = userEvent.setup();
    const onClose = vi.fn();
    render(
      <PacketInspector
        flow={flow}
        packets={makePackets()}
        loading={false}
        error={null}
        onClose={onClose}
      />
    );
    await u.click(screen.getByRole("button", { name: /close packet inspector/i }));
    expect(onClose).toHaveBeenCalledOnce();
  });

  it("truncated notice shown when packets.truncated is true", () => {
    render(
      <PacketInspector
        flow={flow}
        packets={makePackets({ truncated: true, total: 5000 })}
        loading={false}
        error={null}
        onClose={() => {}}
      />
    );
    // Header shows "first N of 5,000 packets"
    expect(screen.getByText(/first.*of.*5,000/i)).toBeInTheDocument();
  });

  it("Stream view reassembles the conversation into client/server segments", async () => {
    const u = userEvent.setup();
    render(<PacketInspector flow={flow} packets={makePackets()} loading={false} error={null} onClose={() => {}} />);
    await u.click(screen.getByRole("button", { name: "stream" }));
    // Two segments from the fixture: client request, then server response (empty packet skipped).
    expect(screen.getByText(/client → server/)).toBeInTheDocument();
    expect(screen.getByText(/server → client/)).toBeInTheDocument();
    // The reassembled client bytes contain the GET request line.
    expect(screen.getByText(/GET \/ HTTP/)).toBeInTheDocument();
  });

  it("shows a Decrypt tab only when onDecrypt is provided, with a key-log prompt", async () => {
    const u = userEvent.setup();
    const onDecrypt = vi.fn();
    render(<PacketInspector flow={flow} packets={makePackets()} loading={false} error={null} onClose={() => {}} onDecrypt={onDecrypt} />);
    await u.click(screen.getByRole("button", { name: "decrypt" }));
    expect(screen.getByText(/SSLKEYLOGFILE/)).toBeInTheDocument();
    expect(screen.getByText(/never leaves your browser/i)).toBeInTheDocument();
    expect(onDecrypt).not.toHaveBeenCalled();
  });

  it("decrypts a key-log: re-analyzed HTTP, carved files, and raw records", async () => {
    const u = userEvent.setup();
    const onDecrypt = vi.fn().mockResolvedValue({
      supported: true, sessionFound: true, version: 0x0304, cipher: 0x1301,
      cipherName: "TLS_AES_128_GCM_SHA256", keylogSessions: 1, truncated: false, reason: null,
      records: [{ direction: "c2s", seq: 0, innerType: 23, plaintext: new TextEncoder().encode("GET /payload.bin HTTP/1.1") }],
      appProto: "http/1.1",
      http: [{ method: "GET", target: "/payload.bin", host: "evil.test", status: 200, content_type: "application/octet-stream", resp_bytes: 4096 }],
      carved: [{ sha256: "a".repeat(64), size: 4096, known_bad: false, signatures: ["PE/DOS executable", "UPX-packed executable"] }],
    });
    render(<PacketInspector flow={flow} packets={makePackets()} loading={false} error={null} onClose={() => {}} onDecrypt={onDecrypt} />);
    await u.click(screen.getByRole("button", { name: "decrypt" }));
    await u.upload(screen.getByLabelText(/SSLKEYLOGFILE/i), keylogFile());

    // Default sub-view is the re-analyzed HTTP: the request hidden inside HTTPS.
    expect(await screen.findByText("/payload.bin")).toBeInTheDocument();
    expect(screen.getByText("evil.test")).toBeInTheDocument();

    // Files sub-view: the download carved from the decrypted response, with signature chips.
    await u.click(screen.getByRole("button", { name: /^Files/ }));
    expect(screen.getByText("UPX-packed executable")).toBeInTheDocument();

    // Records sub-view: the raw decrypted plaintext.
    await u.click(screen.getByRole("button", { name: /^Records/ }));
    expect(screen.getByText(/GET \/payload.bin HTTP\/1.1/)).toBeInTheDocument();
    expect(onDecrypt).toHaveBeenCalledOnce();
  });

  it("HTTP/2 with no recovered transactions explains the HPACK frames, not 'not decoded'", async () => {
    const u = userEvent.setup();
    const onDecrypt = vi.fn().mockResolvedValue({
      supported: true, sessionFound: true, version: 0x0304, cipher: 0x1301,
      cipherName: "TLS_AES_128_GCM_SHA256", keylogSessions: 1, truncated: false, reason: null,
      records: [{ direction: "c2s", seq: 0, innerType: 23, plaintext: new TextEncoder().encode("PRI * HTTP/2.0") }],
      appProto: "http/2", http: [], carved: [],
    });
    render(<PacketInspector flow={flow} packets={makePackets()} loading={false} error={null} onClose={() => {}} onDecrypt={onDecrypt} />);
    await u.click(screen.getByRole("button", { name: "decrypt" }));
    await u.upload(screen.getByLabelText(/SSLKEYLOGFILE/i), keylogFile());
    expect(await screen.findByText(/HTTP\/2.*HPACK-compressed frames/)).toBeInTheDocument();
  });

  it("surfaces the reason for an unsupported cipher suite", async () => {
    const u = userEvent.setup();
    const onDecrypt = vi.fn().mockResolvedValue({
      supported: false, sessionFound: false, version: 0x0304, cipher: 0x1302,
      cipherName: "TLS_AES_256_GCM_SHA384", keylogSessions: 1, truncated: false,
      reason: "cipher suite TLS_AES_256_GCM_SHA384 not yet supported (only TLS_AES_128_GCM_SHA256)",
      records: [],
    });
    render(<PacketInspector flow={flow} packets={makePackets()} loading={false} error={null} onClose={() => {}} onDecrypt={onDecrypt} />);
    await u.click(screen.getByRole("button", { name: "decrypt" }));
    await u.upload(screen.getByLabelText(/SSLKEYLOGFILE/i), keylogFile("x"));
    expect(await screen.findByText(/not yet supported/)).toBeInTheDocument();
  });

  it("resets selection to row 0 when packets prop changes", async () => {
    // Render with first packet set.
    const firstPackets = makePackets();
    const { rerender } = render(
      <PacketInspector
        flow={flow}
        packets={firstPackets}
        loading={false}
        error={null}
        onClose={() => {}}
      />
    ) as RenderResult & { rerender: (element: React.ReactElement) => void };

    // Hex viewer should show the first packet's payload ("GET / HTTP/1.1\r\n").
    expect(screen.getByText("47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a")).toBeInTheDocument();

    // Size scroll container and select a different row (index 1).
    const scrollEl = document.querySelector(".min-h-0.flex-1.overflow-y-auto") as HTMLElement;
    act(() => { sizeScrollElement(scrollEl); });

    const u2 = userEvent.setup();
    const row1Previews = screen.getAllByText(/HTTP\/1\.1 200 OK/);
    await u2.click(row1Previews[0]);

    // Verify row 1 is now selected (hex viewer shows "HTTP/1.1 200 OK\r\n").
    expect(screen.getByText("48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d")).toBeInTheDocument();

    // Create a DIFFERENT packet object (new identity).
    const secondPackets = makePackets();

    // Rerender with the new packets prop.
    rerender(
      <PacketInspector
        flow={flow}
        packets={secondPackets}
        loading={false}
        error={null}
        onClose={() => {}}
      />
    );

    // Selection should have reset to row 0, so hex viewer shows the first packet's payload again.
    expect(screen.getByText("47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a")).toBeInTheDocument();
  });
});
