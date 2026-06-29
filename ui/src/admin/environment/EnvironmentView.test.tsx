import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";

vi.mock("../settings/useAdminAppSettings", () => ({
  useAdminAppSettings: () => ({
    state: { status: "ready", settings: [{ key: "branding", value: { product_name: "PacketPilot" }, description: "Branding", updated_at: "2026-06-20T00:00:00Z" }] },
    reload: vi.fn(),
  }),
}));

import { EnvironmentView } from "./EnvironmentView";

describe("EnvironmentView", () => {
  it("shows public vars masked and a server-secret checklist with no values", () => {
    render(<EnvironmentView />);
    expect(screen.getByText("VITE_SUPABASE_URL")).toBeInTheDocument();
    // Server secrets listed by name with a 'Server-managed' label and NO value
    const secrets = screen.getByRole("table", { name: /server secrets/i });
    expect(within(secrets).getByText("STRIPE_SECRET_KEY")).toBeInTheDocument();
    expect(within(secrets).getByText("AI_API_KEY")).toBeInTheDocument();
    expect(within(secrets).getByText("VIRUSTOTAL_KEY")).toBeInTheDocument();
    expect(within(secrets).getAllByText(/server-managed/i).length).toBeGreaterThan(0);
    // No raw secret value is ever rendered (key names like SUPABASE_SERVICE_ROLE_KEY are expected; actual values are not)
    expect(screen.queryByText(/^sk_live|^sk_test|^whsec_/i)).not.toBeInTheDocument();
  });
  it("shows the read-only app settings mirror", () => {
    render(<EnvironmentView />);
    expect(screen.getByText("branding")).toBeInTheDocument();
  });
});
