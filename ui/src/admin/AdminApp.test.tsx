import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";

const mockSession = vi.fn();
vi.mock("./useAdminSession", () => ({ useAdminSession: () => mockSession() }));
// Keep the shell/login light so this test targets the gate only.
vi.mock("./AdminShell", () => ({ AdminShell: () => <div>SHELL</div> }));
vi.mock("./AdminLogin", () => ({ AdminLogin: (p: { session: { status: string } }) => <div>LOGIN:{p.session.status}</div> }));

import AdminApp from "./AdminApp";

describe("AdminApp gate", () => {
  it("shows the loading state while resolving", () => {
    mockSession.mockReturnValue({ status: "loading" });
    render(<AdminApp />);
    expect(screen.getByRole("status")).toBeInTheDocument();
  });

  it("renders the shell for an admin", () => {
    mockSession.mockReturnValue({ status: "admin", email: "a@b.com", profile: {}, signOut: vi.fn() });
    render(<AdminApp />);
    expect(screen.getByText("SHELL")).toBeInTheDocument();
  });

  it("renders the login for anon / forbidden / unconfigured", () => {
    for (const status of ["anon", "forbidden", "unconfigured"]) {
      mockSession.mockReturnValue({ status, email: "u@b.com", signIn: vi.fn(), signOut: vi.fn() });
      const { unmount } = render(<AdminApp />);
      expect(screen.getByText(`LOGIN:${status}`)).toBeInTheDocument();
      unmount();
    }
  });
});
