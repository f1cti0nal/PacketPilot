import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";

const hook = vi.hoisted(() => ({ useAccount: vi.fn() }));
vi.mock("./useAccount", () => hook);
// Stub the heavy sections so this test focuses on AccountPage's composition + states.
vi.mock("./sections/AccountSection", () => ({ AccountSection: () => <div>account-section</div> }));
vi.mock("./sections/SecuritySection", () => ({ SecuritySection: () => <div>security-section</div> }));
vi.mock("./sections/BillingSection", () => ({ BillingSection: () => <div>billing-section</div> }));
vi.mock("./sections/PreferencesSection", () => ({ PreferencesSection: () => <div>preferences-section</div> }));

import { AccountPage } from "./AccountPage";
import type { SessionState } from "../auth/useSession";

const session = {
  status: "authed",
  email: "a@b.com",
  emailVerified: true,
  profile: { email: "a@b.com", full_name: "A", plan: "pro", hasBilling: true, trialEndsAt: null },
  resendVerification: vi.fn(),
  signOut: vi.fn(),
} as Extract<SessionState, { status: "authed" }>;

beforeEach(() => {
  vi.clearAllMocks();
});

describe("AccountPage", () => {
  it("renders all four sections when ready", () => {
    hook.useAccount.mockReturnValue({
      state: {
        status: "ready",
        profile: { id: "u1", email: "a@b.com", full_name: "A", avatar_url: null, role: "user", created_at: "2026-01-01" },
        subscription: null,
      },
      reload: vi.fn(),
    });
    render(<AccountPage session={session} />);
    expect(screen.getByText("account-section")).toBeInTheDocument();
    expect(screen.getByText("security-section")).toBeInTheDocument();
    expect(screen.getByText("billing-section")).toBeInTheDocument();
    expect(screen.getByText("preferences-section")).toBeInTheDocument();
  });

  it("shows an error state when the load fails", () => {
    hook.useAccount.mockReturnValue({ state: { status: "error", error: "nope" }, reload: vi.fn() });
    render(<AccountPage session={session} />);
    expect(screen.getByText(/couldn't load your account/i)).toBeInTheDocument();
  });
});
