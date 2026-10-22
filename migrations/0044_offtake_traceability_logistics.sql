-- =====================================================================
-- 0046 — Multi-Tenant Offtake Contracting, Traceability & Logistics
--
-- NON-BREAKING MODULAR EXPANSION. Every capability below is additive (new
-- tables / nullable columns only) and is GOVERNED by Feature Management & QA:
-- each feature is auto-registered into feature_flags at stage='sandbox'
-- (hidden from end users; visible to Super-Admin for QA). A Super-Admin promotes
-- it to 'testing' (whitelist) then 'live' (per-user or global) before end users
-- see it. The app gates every new surface behind these flags (featureOn()).
--
-- Mirrored across Equipment (host), Nia and Feed so the ecosystem stays aligned.
-- All DDL is idempotent (IF NOT EXISTS / ON CONFLICT) + applied by db-init.
-- =====================================================================

-- ---------------------------------------------------------------------------
-- 1. GOVERNANCE: auto-register the new features (sandbox by default).
-- ---------------------------------------------------------------------------
INSERT OR IGNORE INTO feature_flags (feature_key, label, description, stage, global_enabled) VALUES
  ('offtake_contracting',   'Offtake Contracting & Outgrower Engine', 'Spot (Buy) and forward (Contract) procurement of produce, outgrower matching and agent aggregation across crop & livestock value chains.', 'sandbox', 0),
  ('offtake_marketplace',   'Offtake Marketplace (Buy / Contract)', 'Produce storefront with dual Buy (spot) and Contract (forward) workflows for Offtaker / Produce Buyer accounts.', 'sandbox', 0),
  ('admin_matching_engine', 'Match Buyers & Outgrowers', 'Admin / Super-Admin suite to match offtake contracts to outgrowers externally (SMS/USSD), internally (block farm) or via agent aggregation.', 'sandbox', 0),
  ('agent_aggregation',     'Agent Field Aggregation & QR Bagging', 'First-mile aggregation work-orders: inspect, weigh, QR-tag crates/bags and confirm batch collection.', 'sandbox', 0),
  ('escrow_settlement',     'Offtake Escrow Settlement', 'Fully / partially pre-delivery and on-delivery escrow settlement through the Equipment Gateway escrow engine.', 'sandbox', 0),
  ('traceability_ledger',   'End-to-End Traceability & Provenance', 'Immutable crop & livestock provenance records with public QR lookup; auto-ingestion of input receipts (Nia) and veterinary logs (Feed).', 'sandbox', 0),
  ('logistics_telemetry',   'GPS & Cold-Chain Logistics Telemetry', 'Live driver GPS tracking, route/ETA rendering and BLE cold-chain temperature/humidity monitoring for in-transit freight.', 'sandbox', 0),
  ('master_user_registry',  'Cross-Marketplace Master User Registry', 'Unified identity & roles (Farmer, Input Provider/AgSME, Offtaker, Logistics Provider) shared across Equipment, Nia and Feed.', 'sandbox', 0),
  ('agsme_multicatalog',    'AgSME Multi-Catalog Provider', 'Input Providers (AgSME) publish products across Equipment, Nia and Feed from one unified product view.', 'sandbox', 0)
ON CONFLICT (feature_key) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 2. UNIFIED IDENTITY: master-registry role flags on users (nullable, additive).
--    Existing role column is preserved; these are ecosystem capability flags so a
--    single identity can be Farmer + Offtaker + Provider simultaneously.
-- ---------------------------------------------------------------------------
ALTER TABLE users ADD COLUMN is_offtaker INTEGER DEFAULT 0;          -- Produce Buyer (AgSME)
ALTER TABLE users ADD COLUMN is_input_provider INTEGER DEFAULT 0;    -- Input Provider (AgSME seller)
ALTER TABLE users ADD COLUMN is_logistics_provider INTEGER DEFAULT 0;-- Transporter
ALTER TABLE users ADD COLUMN agsme_profile TEXT;                     -- JSON: enterprise profile
ALTER TABLE users ADD COLUMN agent_scope TEXT;                       -- 'internal' | 'external' (agents)
ALTER TABLE users ADD COLUMN master_registry_id TEXT;               -- stable cross-app identity id

-- New delegable permissions for the operational role hierarchy.
INSERT OR IGNORE INTO permission_catalog (permission_key, label, description, category) VALUES
  ('manage_offtake',        'Offtake Contracting',          'Create and manage offtake (spot/forward) produce contracts.', 'offtake'),
  ('match_outgrowers',      'Match Buyers & Outgrowers',    'Run the admin matching engine (external SMS/USSD, internal block-farm, agent aggregation).', 'offtake'),
  ('aggregate_produce',     'Agent Produce Aggregation',    'Perform first-mile aggregation: weigh, inspect, QR-tag and confirm batches.', 'offtake'),
  ('manage_logistics',      'Logistics & Fleet',            'Register fleets/vehicles, assign drivers and configure cold-chain trackers.', 'logistics'),
  ('view_traceability',     'Traceability Audits',          'View immutable provenance records and traceability audit trails.', 'traceability');

-- Grant the new operational permissions to the full-access system roles so admins
-- can QA them immediately (end-user exposure is still governed by feature flags).
UPDATE role_templates
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb
       || '{"manage_offtake":true,"match_outgrowers":true,"aggregate_produce":true,"manage_logistics":true,"view_traceability":true}'::jsonb)::text
 WHERE role_key IN ('super_admin', 'admin');
UPDATE users
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb
       || '{"manage_offtake":true,"match_outgrowers":true,"aggregate_produce":true,"manage_logistics":true,"view_traceability":true}'::jsonb)::text
 WHERE role = 'super_admin';
-- Agents get aggregation by default (field work).
UPDATE role_templates
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb || '{"aggregate_produce":true}'::jsonb)::text
 WHERE role_key = 'agent';

-- ---------------------------------------------------------------------------
-- 3. OFFTAKE CONTRACTING & OUTGROWER MANAGEMENT
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS offtake_contracts (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  contract_ref        TEXT UNIQUE NOT NULL,
  offtaker_id         TEXT,                         -- buyer (user id)
  product_id          INTEGER,                      -- optional link to a produce listing
  produce_type        TEXT NOT NULL,                -- e.g. 'Maize', 'Avocado', 'Beef'
  value_chain         TEXT DEFAULT 'crop',          -- 'crop' | 'livestock'
  procurement_mode    TEXT NOT NULL DEFAULT 'forward', -- 'spot' | 'forward'
  target_volume       REAL NOT NULL,                -- net weight
  volume_unit         TEXT NOT NULL DEFAULT 'KG',   -- 'KG' | 'MT'
  variance_pct        REAL DEFAULT 5,               -- ±5% default
  delivery_start      TEXT,                         -- harvest/delivery window start
  delivery_end        TEXT,                         -- window end
  unit_price          REAL NOT NULL,                -- fixed price per KG
  currency            TEXT NOT NULL DEFAULT 'KES',  -- 'KES' | 'USD'
  currency_locked     INTEGER DEFAULT 1,
  quality_specs       TEXT,                         -- JSON: moisture%, defects, grading, organic, MRLs
  premium_penalty     TEXT,                         -- JSON: quality premium/penalty tiers
  payment_structure   TEXT NOT NULL DEFAULT 'on_delivery', -- 'pre_full' | 'pre_partial' | 'on_delivery'
  upfront_pct         REAL DEFAULT 0,               -- partial pre-delivery deposit %
  status              TEXT NOT NULL DEFAULT 'draft',-- draft|open|matching|aggregating|in_transit|delivered|settled|cancelled
  milestone           TEXT DEFAULT 'ORDERED',       -- ORDERED|PLANTED|GROWING|HARVESTED|AGGREGATED|IN_TRANSIT|DELIVERED
  escrow_state        TEXT DEFAULT 'none',          -- none|locked|partially_released|released
  escrow_amount       REAL DEFAULT 0,
  created_by          TEXT,
  created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_offtake_status ON offtake_contracts(status);
CREATE INDEX IF NOT EXISTS idx_offtake_offtaker ON offtake_contracts(offtaker_id);

-- Match records: one per outgrower / block-farm / agent assignment on a contract.
CREATE TABLE IF NOT EXISTS offtake_matches (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  contract_id    INTEGER NOT NULL,
  match_type     TEXT NOT NULL DEFAULT 'external',  -- 'external' | 'internal' | 'agent'
  outgrower_id   TEXT,                              -- matched farmer (customer/user id)
  agent_id       TEXT,                              -- assigned aggregation agent
  block_farm     TEXT,                              -- internal block-farm/cooperative id
  allocated_volume REAL DEFAULT 0,
  dispatch_channel TEXT,                            -- 'sms' | 'ussd' | 'internal'
  response       TEXT DEFAULT 'pending',            -- pending|accepted|declined
  responded_at   TIMESTAMP,
  created_by     TEXT,
  created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_offtake_match_contract ON offtake_matches(contract_id);

-- First-mile aggregation batches (agent weighs/inspects/QR-tags).
CREATE TABLE IF NOT EXISTS aggregation_batches (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  batch_ref      TEXT UNIQUE NOT NULL,              -- encoded into the QR tag
  contract_id    INTEGER,
  match_id       INTEGER,
  agent_id       TEXT,
  outgrower_id   TEXT,
  gross_weight   REAL DEFAULT 0,
  net_weight     REAL DEFAULT 0,
  unit           TEXT DEFAULT 'KG',
  quality_grade  TEXT,
  moisture_pct   REAL,
  defects_pct    REAL,
  qr_payload     TEXT,                              -- opaque QR value
  collected_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  created_by     TEXT
);
CREATE INDEX IF NOT EXISTS idx_agg_contract ON aggregation_batches(contract_id);

-- ---------------------------------------------------------------------------
-- 4. TRACEABILITY & PROVENANCE (immutable, append-only events).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS traceability_events (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  provenance_ref TEXT NOT NULL,                     -- the public QR key (batch/animal/contract)
  value_chain    TEXT NOT NULL DEFAULT 'crop',      -- 'crop' | 'livestock'
  stage          TEXT NOT NULL,                     -- e.g. SEED_PURCHASE, CHEMICAL_APP, HARVEST, VET_AUDIT, COLD_CHAIN...
  event_type     TEXT NOT NULL,
  source_app     TEXT,                              -- 'equipment' | 'nia' | 'feed'
  source_ref     TEXT,                              -- originating record (receipt id, vet log id, ping id)
  payload        TEXT,                              -- JSON snapshot (immutable)
  recorded_by    TEXT,
  recorded_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_trace_ref ON traceability_events(provenance_ref);

-- ---------------------------------------------------------------------------
-- 5. LOGISTICS: fleets/vehicles, shipments and telemetry pings.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS logistics_vehicles (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  provider_id    TEXT,                              -- logistics provider (user id)
  plate          TEXT,
  truck_type     TEXT,                              -- flatbed|refrigerated|box|...
  capacity_kg    REAL DEFAULT 0,
  has_cold_chain INTEGER DEFAULT 0,
  ble_sensor_id  TEXT,                              -- BLE cold-chain tracker id
  active         INTEGER DEFAULT 1,
  created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS logistics_shipments (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  shipment_ref   TEXT UNIQUE NOT NULL,
  contract_id    INTEGER,
  vehicle_id     INTEGER,
  driver_id      TEXT,
  driver_name    TEXT,
  origin_hub     TEXT,
  destination    TEXT,
  status         TEXT NOT NULL DEFAULT 'scheduled', -- scheduled|in_transit|delivered|cancelled
  eta_minutes    INTEGER,
  pod_signed_at  TIMESTAMP,                         -- Proof of Delivery sign-off
  last_lat       REAL,
  last_lng       REAL,
  last_speed_kmh REAL,
  last_temp_c    REAL,
  last_ping_at   TIMESTAMP,
  created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_ship_contract ON logistics_shipments(contract_id);
-- High-frequency driver telemetry (GPS + cold-chain). Append-only.
CREATE TABLE IF NOT EXISTS telemetry_pings (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  shipment_id    INTEGER NOT NULL,
  lat            REAL,
  lng            REAL,
  speed_kmh      REAL,
  heading        REAL,
  temp_c         REAL,                              -- BLE cold-chain
  humidity_pct   REAL,
  recorded_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_ping_shipment ON telemetry_pings(shipment_id);
