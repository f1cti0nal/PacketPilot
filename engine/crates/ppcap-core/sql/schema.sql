-- PacketPilot Phase 0 case schema (DuckDB). schema_version = 1
-- Token: {CASE_DIR} (absolute forward-slash dir holding parquet/)
--
-- DuckDB is NOT linked into the engine. This DDL is emitted by `ppcap init-db`
-- (which substitutes {CASE_DIR}) and run by an external DuckDB CLI / DuckDB-Wasm
-- sidecar. Relational tables are native DuckDB; `flow` and `packet_index` are
-- views over the Snappy Parquet the engine writes.

CREATE TYPE severity_t  AS ENUM ('info','low','medium','high','critical');
CREATE TYPE category_t  AS ENUM (
  'web','dns','email','file_transfer','remote_access','voip','iot_ot',
  'tunnel_vpn','scan','c2','anomalous','unknown');     -- matches Category::as_str()
CREATE TYPE indicator_t AS ENUM ('ipv4','ipv6','domain','url','sha256','ja3','ja4','email_addr');

CREATE TABLE capture (
  id UBIGINT PRIMARY KEY, path VARCHAR NOT NULL, sha256 VARCHAR NOT NULL,
  bytes UBIGINT NOT NULL, first_ts TIMESTAMP NOT NULL, last_ts TIMESTAMP NOT NULL,
  pkt_count UBIGINT NOT NULL, status VARCHAR NOT NULL DEFAULT 'complete',
  ts_precision VARCHAR NOT NULL DEFAULT 'ns', created_at TIMESTAMP NOT NULL DEFAULT now());

-- flow VIEW over Parquet. SELECT list MUST equal flow_columns_in_order() (CI-guarded).
CREATE VIEW flow AS
SELECT flow_id, capture_id, src_ip, dst_ip, src_port, dst_port, proto, app_proto,
       bytes_c2s, bytes_s2c, pkts, start_ts, end_ts, tcp_flags_c2s, tcp_flags_s2c,
       ttl_min_c2s, category, app_proto_src, sni, severity, threat_score, ioc
FROM read_parquet('{CASE_DIR}/parquet/flow/*.parquet', union_by_name = true);

-- packet_index VIEW (Phase 0 may emit zero parts; view still resolves once a part exists).
-- Arrow contract: capture_id UInt64, flow_id UInt64, ts Timestamp(ns,UTC),
--                 file_offset UInt64, len UInt32, frame_no UInt64
CREATE VIEW packet_index AS
SELECT capture_id, flow_id, ts, file_offset, len, frame_no
FROM read_parquet('{CASE_DIR}/parquet/packet_index/*.parquet', union_by_name = true);

CREATE TABLE indicator (
  id UBIGINT PRIMARY KEY, value VARCHAR NOT NULL, type indicator_t NOT NULL,
  capture_id UBIGINT NOT NULL REFERENCES capture(id),
  first_seen TIMESTAMP NOT NULL, last_seen TIMESTAMP NOT NULL,
  UNIQUE (capture_id, type, value));

CREATE TABLE enrichment (
  indicator_id UBIGINT NOT NULL REFERENCES indicator(id), source VARCHAR NOT NULL,
  verdict VARCHAR, score DOUBLE, asn INTEGER, geo VARCHAR, tags VARCHAR[],
  fetched_at TIMESTAMP NOT NULL, raw JSON,
  PRIMARY KEY (indicator_id, source));

CREATE TABLE finding (
  id UBIGINT PRIMARY KEY, capture_id UBIGINT NOT NULL REFERENCES capture(id),
  category category_t NOT NULL, rule VARCHAR NOT NULL, severity severity_t NOT NULL,
  confidence DOUBLE NOT NULL, attack_technique VARCHAR, evidence JSON NOT NULL,
  flow_ids UBIGINT[] NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT now());

CREATE TABLE incident (
  id UBIGINT PRIMARY KEY, capture_id UBIGINT NOT NULL REFERENCES capture(id),
  host VARCHAR NOT NULL, severity severity_t NOT NULL,
  finding_ids UBIGINT[] NOT NULL,             -- element-FK enforced in engine, not DuckDB
  narrative VARCHAR NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT now());

CREATE TABLE artifact (
  id UBIGINT PRIMARY KEY, capture_id UBIGINT NOT NULL REFERENCES capture(id),
  flow_id UBIGINT NOT NULL, filename VARCHAR, sha256 VARCHAR NOT NULL, mime VARCHAR,
  bytes UBIGINT, path VARCHAR NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT now());
