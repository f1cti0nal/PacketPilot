import { describe, it, expect } from "vitest";
import { render, screen } from "../test/render";
import { EncryptedDnsCard } from "./EncryptedDnsCard";

describe("EncryptedDnsCard", () => {
  it("lists hosts with their DoH/DoT resolver", () => {
    render(
      <EncryptedDnsCard
        hosts={[
          { host: "10.0.0.9", resolver: "cloudflare-dns.com", flows: 4 },
          { host: "10.0.0.8", resolver: "9.9.9.9 (DoT)", flows: 1 },
        ]}
      />,
    );
    expect(screen.getByText("Encrypted DNS")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.9")).toBeInTheDocument();
    expect(screen.getByText("cloudflare-dns.com")).toBeInTheDocument();
    expect(screen.getByText("9.9.9.9 (DoT)")).toBeInTheDocument();
  });

  it("renders nothing when no encrypted DNS was seen", () => {
    render(<EncryptedDnsCard hosts={[]} />);
    expect(screen.queryByText("Encrypted DNS")).toBeNull();
  });
});
