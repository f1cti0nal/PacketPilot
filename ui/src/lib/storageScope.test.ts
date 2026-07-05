import { describe, it, expect, beforeEach } from "vitest";
import "fake-indexeddb/auto";
import {
  setStorageScope,
  getStorageScope,
  scopedKey,
  scopedDbName,
  onStorageScopeChange,
  purgeLegacyGlobalStores,
} from "./storageScope";
import { recordRecent, listRecent } from "./recent";
import { makeOutput } from "../test/fixtures";

function record(id: string) {
  return recordRecent({
    id,
    name: `${id}.pcap`,
    sizeBytes: 1000,
    origin: "wasm",
    summary: makeOutput(),
    flowCount: 0,
    flowsCached: false,
  });
}

describe("storageScope", () => {
  beforeEach(() => {
    localStorage.clear();
    setStorageScope(null); // reset to the anon namespace between tests
  });

  it("namespaces localStorage keys and IndexedDB names by the current account", () => {
    setStorageScope(null);
    expect(getStorageScope()).toBe("anon");
    expect(scopedKey("k")).toBe("k::anon");
    expect(scopedDbName("db")).toBe("db__anon");

    setStorageScope("abc");
    expect(getStorageScope()).toBe("u_abc");
    expect(scopedKey("k")).toBe("k::u_abc");
    expect(scopedDbName("db")).toBe("db__u_abc");
  });

  it("notifies subscribers only when the scope actually changes", () => {
    setStorageScope("a");
    let n = 0;
    const off = onStorageScopeChange(() => {
      n++;
    });
    setStorageScope("a"); // same scope → no notification
    expect(n).toBe(0);
    setStorageScope("b"); // changed
    expect(n).toBe(1);
    off();
    setStorageScope("c"); // unsubscribed
    expect(n).toBe(1);
  });

  it("isolates recent captures across accounts on one browser profile (the leak fix)", () => {
    // Alice analyzes a capture.
    setStorageScope("alice");
    record("cap-alice");
    expect(listRecent().map((e) => e.id)).toEqual(["cap-alice"]);

    // Switch to Bob on the SAME machine — he must NOT see Alice's capture analysis.
    setStorageScope("bob");
    expect(listRecent()).toEqual([]);
    record("cap-bob");
    expect(listRecent().map((e) => e.id)).toEqual(["cap-bob"]);

    // Back to Alice: her capture is still there; Bob's is not visible to her.
    setStorageScope("alice");
    expect(listRecent().map((e) => e.id)).toEqual(["cap-alice"]);
  });

  it("purges legacy un-namespaced stores exactly once", () => {
    localStorage.setItem("packetpilot.recent.v1", "[legacy recents]");
    localStorage.setItem("packetpilot.ruleSets.v1", "[legacy rules]");
    localStorage.setItem("pp.rep.consent", "1");

    purgeLegacyGlobalStores();
    expect(localStorage.getItem("packetpilot.recent.v1")).toBeNull();
    expect(localStorage.getItem("packetpilot.ruleSets.v1")).toBeNull();
    expect(localStorage.getItem("pp.rep.consent")).toBeNull();

    // Idempotent: after the one-time purge, re-created legacy data is left untouched.
    localStorage.setItem("packetpilot.recent.v1", "[re-added]");
    purgeLegacyGlobalStores();
    expect(localStorage.getItem("packetpilot.recent.v1")).toBe("[re-added]");
  });
});
