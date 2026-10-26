-- =====================================================================
-- 0048 — Produce Sourcing & Contracting Module (framework upgrade)
--
-- UPGRADES the existing offtake capability (0046) with the full Produce
-- Sourcing, Contracting & Supply-Chain layer from the PRD. STRICTLY ADDITIVE
-- and NON-BREAKING: new tables, nullable columns and new feature flags only —
-- the existing offtake_contracts / matches / aggregation / logistics /
-- traceability tables and their routes are preserved unchanged (zero
-- regression). Every NEW capability is GOVERNED by Feature Management & QA and
-- auto-registers at stage='sandbox' (hidden from end users; visible to
-- Super-Admin for QA) until promoted to testing (whitelist) then live.
--
-- Mirrored across Equipment (host), Nia and Feed.
-- All DDL idempotent (IF NOT EXISTS / duplicate-column tolerated by db-init).
-- =====================================================================

-- ---------------------------------------------------------------------------
-- 1. GOVERNANCE: auto-register the new modules as sandbox feature flags.
-- ---------------------------------------------------------------------------
INSERT OR IGNORE INTO feature_flags (feature_key, label, description, stage, global_enabled) VALUES
  ('buyer_portal',          'Produce Buyer Portal & Tenants',        'Multi-tenant Buyer Enterprise portal: company settings, intake sites, teams and contract templates.', 'sandbox', 0),
  ('coop_portal',           'Cooperative (COOP) Portal',             'Cooperative portal (duplicates agent capabilities) for cluster fulfilment, bid acceptance and delivery coordination.', 'sandbox', 0),
  ('contract_builder',      'Smart Contract Builder & Archetypes',   'Template-driven contracts with archetypes (fixed, multi-grade, index/area-linked, min-guaranteed) across 10+ price-basis types plus carry/insurance/brokerage costs.', 'sandbox', 0),
  ('time_slotting',         'Time Slotting (Inload/Outload)',        'Site access control, delivery slot scheduling, calendar booking and freight traffic flow for intake sites.', 'sandbox', 0),
  ('order_management',      'Orders (Freight / Call / Request / Pack)', 'Linked or standalone order management (Freight, Call-on-Grain, Request, Pack) with party & freight assignment.', 'sandbox', 0),
  ('movement_tracking',     'Movements (Commodity Movement Tracking)', 'Track every load farm-gate → site with live or post-delivery entry, weights, GPS and contract/order linkage.', 'sandbox', 0),
  ('freight_scheduling',    'Freight Scheduling (Truck & Mass)',     'Truck/fleet registry, drag-and-drop dispatch, per-truck tonnage and statutory mass compliance.', 'sandbox', 0),
  ('cor_compliance',        'Chain of Responsibility (CoR)',         'Statutory load-limit checks, overweight flagging and digital GTA/MLA declarations with audit.', 'sandbox', 0),
  ('stock_ledger',          'Stocks & Transfers (Inventory Ledger)', 'Real-time multi-site owned & third-party commodity stock ledger with regrade/reseason and automated fees.', 'sandbox', 0),
  ('container_packing',     'Container Packing (Export Ops)',        'Containerised pack orders, status/movement audit, export documentation and milestone invoicing.', 'sandbox', 0),
  ('cashboards_bidding',    'Cashboards & Live Bidding',             'Real-time price boards and bidding floor; accepting a live bid converts to an executed digital contract; targeted private bids.', 'sandbox', 0),
  ('closed_loop_settlement','Closed-Loop Settlement & Loan Offset',  'Automated RCTI generation and a split-settlement routing engine: net = gross − (input loan offset + platform fee + freight).', 'sandbox', 0)
ON CONFLICT (feature_key) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 2. RBAC: new roles & capability flags (additive — existing roles untouched).
--    Hierarchy: Buyer Enterprise Admin → Commercial Manager / Site Manager;
--    Logistics Provider → Dispatcher / Driver; plus Cooperative (COOP).
-- ---------------------------------------------------------------------------
INSERT OR IGNORE INTO role_templates (role_key, label, description, permissions, is_system) VALUES
  ('buyer_enterprise',  'Buyer Enterprise Admin', 'Produce Buyer tenant admin: company settings, intake sites, commercial & ops teams, contract templates.',
    '{"view":true,"manage_buyer_tenant":true,"manage_contracts_buyer":true,"manage_intake_sites":true,"manage_cashboards":true,"view_traceability":true}', 1),
  ('commercial_manager','Commercial Manager / Trader', 'Issues forward/spot contracts, manages cashboards & live bids, approves execution orders.',
    '{"view":true,"manage_contracts_buyer":true,"manage_cashboards":true,"manage_orders":true}', 1),
  ('site_manager',      'Site Manager / Weighmaster', 'Manages site hours & slot rules, approves intake bookings, logs weighbridge tickets & quality.',
    '{"view":true,"manage_intake_sites":true,"manage_slots":true,"log_weighbridge":true}', 1),
  ('logistics_provider','Logistics Provider (3PL)', 'Assigns fleets/drivers to orders, tracks load allocations, monitors mass compliance.',
    '{"view":true,"manage_logistics":true,"manage_freight":true,"manage_trucks":true}', 1),
  ('driver',            'Driver / Field Transporter', 'Views assigned loads, logs GPS timestamps, captures digital PoD signatures.',
    '{"view":true,"log_movements":true}', 1),
  ('coop',              'Cooperative (COOP)', 'Cooperative cluster: views off-take offers, accepts live bids (if authorised), books slots, tracks payouts & loan offsets.',
    '{"view":true,"add_farmer":true,"view_farmers":true,"aggregate_produce":true,"accept_bids":true,"book_slots":true}', 1)
ON CONFLICT (role_key) DO NOTHING;

-- New delegable permissions on the catalog (best-effort; category 'produce').
INSERT OR IGNORE INTO permission_catalog (permission_key, label, description, category) VALUES
  ('manage_buyer_tenant',   'Manage Buyer Tenant',    'Configure a Produce Buyer enterprise, its sites and teams.', 'produce'),
  ('manage_contracts_buyer','Manage Produce Contracts','Issue & manage forward/spot produce contracts and templates.', 'produce'),
  ('manage_intake_sites',   'Manage Intake Sites',    'Create & configure buyer intake sites and weighbridges.', 'produce'),
  ('manage_slots',          'Manage Delivery Slots',  'Create & manage time slots and booking rules.', 'produce'),
  ('log_weighbridge',       'Log Weighbridge Tickets','Capture weighbridge weights, moisture & quality at intake.', 'produce'),
  ('manage_orders',         'Manage Orders',          'Create & manage freight / call / request / pack orders.', 'produce'),
  ('manage_freight',        'Manage Freight',         'Assign freight, schedule trucks, track load allocations.', 'produce'),
  ('manage_trucks',         'Manage Trucks / Fleet',  'Register trucks, permits and trailer configurations.', 'produce'),
  ('log_movements',         'Log Commodity Movements','Log farm-gate → site movements, weights and GPS.', 'produce'),
  ('manage_cashboards',     'Manage Cashboards & Bids','Post live prices / bids and convert accepted bids to contracts.', 'produce'),
  ('accept_bids',           'Accept Live Bids',       'Accept cashboard bids on own / authorised behalf.', 'produce'),
  ('book_slots',            'Book Delivery Slots',    'Book intake delivery slots.', 'produce'),
  ('manage_settlement',     'Manage Settlement / RCTI','Generate RCTIs and run split-settlement with loan offset.', 'produce'),
  ('manage_cor',            'Manage CoR Compliance',  'Review CoR mass checks and sign digital declarations.', 'produce'),
  ('manage_stock_ledger',   'Manage Stock Ledger',    'View & adjust multi-site commodity stock ledgers.', 'produce');

-- Super-Admin & Admin hold all of the new produce permissions by default.
UPDATE role_templates
   SET permissions = (COALESCE(NULLIF(permissions,''),'{}')::jsonb || '{
     "manage_buyer_tenant":true,"manage_contracts_buyer":true,"manage_intake_sites":true,
     "manage_slots":true,"log_weighbridge":true,"manage_orders":true,"manage_freight":true,
     "manage_trucks":true,"log_movements":true,"manage_cashboards":true,"accept_bids":true,
     "book_slots":true,"manage_settlement":true,"manage_cor":true,"manage_stock_ledger":true
   }'::jsonb)::text
 WHERE role_key IN ('super_admin','admin');
UPDATE users
   SET permissions = (COALESCE(NULLIF(permissions,''),'{}')::jsonb || '{
     "manage_buyer_tenant":true,"manage_contracts_buyer":true,"manage_intake_sites":true,
     "manage_slots":true,"log_weighbridge":true,"manage_orders":true,"manage_freight":true,
     "manage_trucks":true,"log_movements":true,"manage_cashboards":true,"accept_bids":true,
     "book_slots":true,"manage_settlement":true,"manage_cor":true,"manage_stock_ledger":true
   }'::jsonb)::text
 WHERE role = 'super_admin';

-- ---------------------------------------------------------------------------
-- 3. EXISTING offtake_contracts — additive nullable columns for the new
--    contract framework (archetype, price basis, buyer tenant, cost add-ons).
-- ---------------------------------------------------------------------------
ALTER TABLE offtake_contracts ADD COLUMN buyer_tenant_id INTEGER;          -- Buyer Enterprise tenant
ALTER TABLE offtake_contracts ADD COLUMN contract_archetype TEXT DEFAULT 'fixed'; -- fixed|multi_grade|index_linked|area_linked|min_guaranteed
ALTER TABLE offtake_contracts ADD COLUMN price_basis TEXT DEFAULT 'fixed'; -- fixed|basis|pool|index|...(10+)
ALTER TABLE offtake_contracts ADD COLUMN carry_cost REAL DEFAULT 0;
ALTER TABLE offtake_contracts ADD COLUMN insurance_cost REAL DEFAULT 0;
ALTER TABLE offtake_contracts ADD COLUMN brokerage_cost REAL DEFAULT 0;
ALTER TABLE offtake_contracts ADD COLUMN platform_fee_pct REAL DEFAULT 0;  -- split-settlement platform fee
ALTER TABLE offtake_contracts ADD COLUMN intake_site_id INTEGER;           -- designated delivery site
ALTER TABLE offtake_contracts ADD COLUMN settlement_scope TEXT DEFAULT 'per_contract'; -- 'system'|'per_contract'

-- ---------------------------------------------------------------------------
-- 4. NEW TABLES (all additive).
-- ---------------------------------------------------------------------------
-- Buyer Enterprise tenants (multi-tenant buyer portal).
CREATE TABLE IF NOT EXISTS buyer_tenants (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_ref    TEXT UNIQUE NOT NULL,
  name          TEXT NOT NULL,
  admin_user_id TEXT,                     -- Buyer Enterprise Admin
  contact_phone TEXT,
  contact_email TEXT,
  logo_url      TEXT,
  settings      TEXT,                     -- JSON company settings / contract template defaults
  status        TEXT DEFAULT 'active',
  created_by    TEXT,
  created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Intake sites / weighbridges.
CREATE TABLE IF NOT EXISTS intake_sites (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  site_ref       TEXT UNIQUE NOT NULL,
  buyer_tenant_id INTEGER,
  name           TEXT NOT NULL,
  location       TEXT,
  latitude       REAL,
  longitude      REAL,
  open_hours     TEXT,                    -- JSON opening hours / break rules
  load_types     TEXT,                    -- JSON allowed load/commodity types
  requires_slot  INTEGER DEFAULT 1,       -- booking required before tipping
  status         TEXT DEFAULT 'active',
  created_by     TEXT,
  created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Delivery time slots.
CREATE TABLE IF NOT EXISTS delivery_slots (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  slot_ref       TEXT UNIQUE NOT NULL,
  intake_site_id INTEGER,
  contract_id    INTEGER,
  booked_by      TEXT,                    -- farmer / agent / coop / driver
  commodity      TEXT,
  grade          TEXT,
  load_type      TEXT DEFAULT 'inload',   -- inload|outload
  slot_start     TEXT,
  slot_end       TEXT,
  status         TEXT DEFAULT 'open',     -- open|booked|arrived|tipped|cancelled
  truck_rego     TEXT,
  notes          TEXT,
  created_by     TEXT,
  created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Orders (freight / call / request / pack).
CREATE TABLE IF NOT EXISTS freight_orders (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  order_ref     TEXT UNIQUE NOT NULL,
  order_type    TEXT NOT NULL DEFAULT 'freight', -- freight|call_on_grain|request|pack
  contract_id   INTEGER,                 -- optional link
  buyer_tenant_id INTEGER,
  seller_id     TEXT,
  buyer_id      TEXT,
  freight_provider_id TEXT,
  origin        TEXT,
  destination   TEXT,
  commodity     TEXT,
  tonnage       REAL DEFAULT 0,
  pickup_instructions TEXT,
  status        TEXT DEFAULT 'open',      -- open|assigned|in_transit|delivered|cancelled
  created_by    TEXT,
  created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Commodity movements (farm-gate → site loads).
CREATE TABLE IF NOT EXISTS commodity_movements (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  movement_ref  TEXT UNIQUE NOT NULL,
  movement_type TEXT DEFAULT 'contracted', -- contracted|standalone|order_linked
  contract_id   INTEGER,
  order_id      INTEGER,
  slot_id       INTEGER,
  commodity     TEXT,
  gross_weight  REAL DEFAULT 0,
  tare_weight   REAL DEFAULT 0,
  net_weight    REAL DEFAULT 0,
  moisture_pct  REAL,
  quality_grade TEXT,
  pickup_lat    REAL,
  pickup_lng    REAL,
  delivery_lat  REAL,
  delivery_lng  REAL,
  logged_at     TEXT,
  status        TEXT DEFAULT 'planned',   -- planned|in_transit|delivered
  created_by    TEXT,
  created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Freight trucks / fleet.
CREATE TABLE IF NOT EXISTS freight_trucks (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  truck_ref      TEXT UNIQUE NOT NULL,
  provider_id    TEXT,
  rego           TEXT,
  config         TEXT,                    -- trailer configuration
  max_mass_kg    REAL DEFAULT 0,          -- statutory mass limit
  permit_ref     TEXT,
  driver_id      TEXT,
  status         TEXT DEFAULT 'available',
  created_by     TEXT,
  created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Multi-site commodity stock ledger.
CREATE TABLE IF NOT EXISTS stock_ledger (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ledger_ref    TEXT UNIQUE NOT NULL,
  intake_site_id INTEGER,
  owner_id      TEXT,                     -- owning party (buyer / client / farmsky)
  commodity     TEXT,
  grade         TEXT,
  season        TEXT,
  quantity_kg   REAL DEFAULT 0,
  movement_kind TEXT DEFAULT 'inload',    -- inload|outload|regrade|reseason|fee
  reference     TEXT,
  created_by    TEXT,
  created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Cashboard live bids.
CREATE TABLE IF NOT EXISTS cashboard_bids (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  bid_ref        TEXT UNIQUE NOT NULL,
  buyer_tenant_id INTEGER,
  intake_site_id INTEGER,
  commodity      TEXT NOT NULL,
  grade          TEXT,
  price          REAL NOT NULL,
  price_max      REAL,                    -- for range bids
  currency       TEXT DEFAULT 'KES',
  bid_type       TEXT DEFAULT 'fixed',    -- fixed|range
  private_target TEXT,                    -- JSON: targeted farmer ids (private bids)
  valid_until    TEXT,
  status         TEXT DEFAULT 'live',     -- live|accepted|expired|withdrawn
  accepted_by    TEXT,
  contract_id    INTEGER,                 -- executed contract on acceptance
  created_by     TEXT,
  created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Closed-loop settlement records (RCTI + split routing).
CREATE TABLE IF NOT EXISTS settlement_records (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  settlement_ref TEXT UNIQUE NOT NULL,
  contract_id    INTEGER,
  movement_id    INTEGER,
  farmer_id      TEXT,
  gross_value    REAL DEFAULT 0,
  input_loan_offset REAL DEFAULT 0,
  platform_fee   REAL DEFAULT 0,
  freight_deduction REAL DEFAULT 0,
  net_payout     REAL DEFAULT 0,
  rcti_ref       TEXT,                    -- Recipient-Created Tax Invoice ref
  payout_target  TEXT,                    -- mobile / bank
  status         TEXT DEFAULT 'pending',  -- pending|rcti_issued|settled
  created_by     TEXT,
  created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Chain of Responsibility declarations.
CREATE TABLE IF NOT EXISTS cor_declarations (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  declaration_ref TEXT UNIQUE NOT NULL,
  movement_id   INTEGER,
  truck_id      INTEGER,
  mass_kg       REAL DEFAULT 0,
  mass_limit_kg REAL DEFAULT 0,
  overweight    INTEGER DEFAULT 0,
  template_kind TEXT,                     -- GTA|MLA
  driver_signed INTEGER DEFAULT 0,
  manager_signed INTEGER DEFAULT 0,
  created_by    TEXT,
  created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Container packing (export ops).
CREATE TABLE IF NOT EXISTS container_packs (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  pack_ref      TEXT UNIQUE NOT NULL,
  contract_id   INTEGER,
  container_no  TEXT,
  commodity     TEXT,
  net_weight    REAL DEFAULT 0,
  status        TEXT DEFAULT 'packing',  -- packing|packed|shipped|delivered
  export_docs   TEXT,                     -- JSON doc refs
  created_by    TEXT,
  created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
