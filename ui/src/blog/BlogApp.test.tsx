import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { BlogApp } from "./BlogApp";
import { BLOG_POSTS } from "./registry";

const origUrl = window.location;
const setPath = (pathname: string) =>
  Object.defineProperty(window, "location", { writable: true, value: { ...origUrl, pathname } });

beforeEach(() => {
  setPath("/");
});
afterEach(() => {
  Object.defineProperty(window, "location", { writable: true, value: origUrl });
});

describe("BlogApp", () => {
  it("renders the index at /blog listing every post", () => {
    setPath("/blog");
    render(<BlogApp />);
    expect(screen.getByRole("heading", { level: 1, name: /PacketPilot blog/i })).toBeInTheDocument();
    for (const p of BLOG_POSTS) {
      expect(screen.getByRole("heading", { level: 2, name: p.title })).toBeInTheDocument();
    }
  });

  it("renders a post at /blog/<slug> and sets the document title", () => {
    const post = BLOG_POSTS[0];
    setPath(`/blog/${post.slug}`);
    render(<BlogApp />);
    expect(screen.getByRole("heading", { level: 1, name: post.title })).toBeInTheDocument();
    expect(document.title).toBe(post.metaTitle);
  });

  it("shows a not-found state for an unknown post", () => {
    setPath("/blog/nope-not-real");
    render(<BlogApp />);
    expect(screen.getByText(/doesn't exist/i)).toBeInTheDocument();
  });
});
