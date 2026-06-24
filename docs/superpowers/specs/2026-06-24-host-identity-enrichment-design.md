# Host-view identity enrichment — design

Status: design · 2026-06-24 · Feature: show a host's passive-DNS domain and L2 MAC/vendor **inline**
in the incident detail flyout — tying the host-context rollups to the view analysts examine.

## Problem

This segment added passive DNS (IP → domain) and L2 host identity (IP → MAC + OUI vendor), each as a
*separate* dashboard panel. But when an analyst drills into a *specific* suspicious host (the
`DetailFlyout`), that identity wasn't there — they had to cross-reference the panels. The single
most-useful attribution ("this C2 host resolved from `evil.example`, and the attacker device is a
`VMware` VM") belongs *on the host*.

## Approach

Pure UI — the data is already in `summary.resolved_ips` / `summary.arp_hosts` (no engine change):
- `Dashboard.tsx`: build `domainByIp` / `macByIp` lookup maps (memoized, like the existing
  `threatByHost`) and pass the selected host's `resolvedDomain` / `mac` to the flyout.
- `cockpit/DetailFlyout.tsx`: a compact **Identity** section (resolved-from domain · MAC with the
  `vendorForMac` OUI label), shown only when at least one is known.

## Scope

In: the inline Identity section in the host detail flyout. Out: enriching the threat-rail/watchlist
rows (the flyout is the detailed view), per-flow joins.

## Invariants

Pure UI; no engine change; no new deps. Hidden when neither domain nor MAC is known. Reuses the
curated `vendorForMac` OUI table (a vendor label only when confidently known).
