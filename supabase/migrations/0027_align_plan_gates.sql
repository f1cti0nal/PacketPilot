-- Align the hosted Free/Pro feature split with the marketed plan (see ui/src/seo/pages.json).
--
-- Intended split:
--   Pro : ai_assist, reputation, saved_rules   (AI analyst summary, reputation enrichment, saved rule-set library)
--   Free: pcap_export, multi_capture_diff       (PCAP carve/export + compare are core local-analysis features)
--
-- Before this migration the seed had it inverted (ai_assist/reputation ungated, pcap_export/
-- multi_capture_diff pro-gated), so free accounts received the two operator-funded Pro features
-- while being blocked from two free ones. `reputation`/`saved_rules` are ADDITIONALLY enforced
-- server-side (ai-proxy / reputation-proxy check plan) — the flag is the client-side half only.
insert into public.feature_flags (key, description, enabled, plan_gate) values
  ('ai_assist',          'AI analyst assistant',                    true, 'pro'),
  ('reputation',         'IP/domain/file reputation enrichment',    true, 'pro'),
  ('saved_rules',        'Saved Suricata/Snort rule-set library',   true, 'pro'),
  ('pcap_export',        'PCAP carving/export',                     true, null),
  ('multi_capture_diff', 'Compare two captures',                    true, null)
on conflict (key) do update set
  enabled     = excluded.enabled,
  plan_gate   = excluded.plan_gate,
  description  = excluded.description,
  updated_at  = now();
