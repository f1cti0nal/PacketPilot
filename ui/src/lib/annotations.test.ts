import { describe, it, expect, beforeEach } from "vitest";
import {
  getAnnotation,
  setAnnotation,
  clearAnnotation,
  annotationsForCapture,
} from "./annotations";

beforeEach(() => localStorage.clear());

describe("annotations", () => {
  it("sets and reads a status + note, scoped per capture and host", () => {
    setAnnotation("capA", "10.0.0.1", { status: "escalated", note: "owned" }, 111);
    expect(getAnnotation("capA", "10.0.0.1")).toEqual({
      status: "escalated",
      note: "owned",
      updatedAt: 111,
    });
    expect(getAnnotation("capA", "10.0.0.2")).toBeNull();
    expect(getAnnotation("capB", "10.0.0.1")).toBeNull();
  });

  it("merges a patch, keeping the prior status or note", () => {
    setAnnotation("c", "ip", { status: "investigating" }, 1);
    setAnnotation("c", "ip", { note: "looking" }, 2);
    expect(getAnnotation("c", "ip")).toEqual({ status: "investigating", note: "looking", updatedAt: 2 });
  });

  it("removes an annotation that collapses back to the default", () => {
    setAnnotation("c", "ip", { status: "cleared", note: "x" }, 1);
    setAnnotation("c", "ip", { status: "new", note: "" }, 2);
    expect(getAnnotation("c", "ip")).toBeNull();
    expect(annotationsForCapture("c")).toEqual({});
  });

  it("clearAnnotation removes the entry", () => {
    setAnnotation("c", "ip", { status: "escalated" }, 1);
    clearAnnotation("c", "ip");
    expect(getAnnotation("c", "ip")).toBeNull();
  });

  it("never throws on malformed storage", () => {
    localStorage.setItem("packetpilot.annotations.v1", "{not json");
    expect(getAnnotation("c", "ip")).toBeNull();
    expect(() => setAnnotation("c", "ip", { status: "cleared" })).not.toThrow();
  });

  it("dispatches a change event on every write", () => {
    let fired = 0;
    const h = () => {
      fired++;
    };
    window.addEventListener("packetpilot:annotations", h);
    setAnnotation("c", "ip", { status: "cleared" }, 1);
    window.removeEventListener("packetpilot:annotations", h);
    expect(fired).toBeGreaterThan(0);
  });
});
