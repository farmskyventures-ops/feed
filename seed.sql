-- =====================================================================
-- Farmsky demo seed data (passwords plain text for DEMO ONLY)
-- =====================================================================

INSERT OR IGNORE INTO users (id, full_name, phone, email, password, role, status, region) VALUES
  (1, 'System Administrator', '+2547500000', 'admin@farmsky.demo', '1224', 'super_admin', 'active', 'HQ - Nairobi'),
  (2, 'Field Agent - James Mwangi', '+2547400000', 'agent@farmsky.demo', '1225', 'agent', 'active', 'Nakuru'),
  (3, 'Fatuma Hassan (Farmer)', '+2547300000', 'user@farmsky.demo', '1226', 'customer', 'active', 'Nakuru'),
  (4, 'Customer Support - Aisha', '+2547200000', 'support@farmsky.demo', '1227', 'support', 'active', 'HQ - Nairobi');

INSERT OR IGNORE INTO agents (id, user_id, region, permissions, commission_rate) VALUES
  (1, 2, 'Nakuru', '{"lead_generation":true,"inventory_access":false,"customer_support":true,"loan_approval":false}', 0.025);

INSERT OR IGNORE INTO suppliers (id, name, contact) VALUES
  (1, 'AgriVet Supplies Ltd', '+254711000111'),
  (2, 'Pembe Feeds Kenya', '+254711000222'),
  (3, 'GreenSeed Distributors', '+254711000333');

INSERT OR IGNORE INTO products (id, sku, name, category, supplier_id, buying_price, cash_markup_pct, credit_markup_pct, cash_price, credit_price, quantity, unit, reorder_threshold) VALUES
  (1, 'FEED-DAIRY-50', 'Dairy Feed (50kg)', 'Feed', 2, 2500, 10, 20, 2750, 3000, 120, 'bag', 20),
  (2, 'FEED-CHICK-25', 'Chick Mash (25kg)', 'Feed', 2, 1800, 10, 22, 1980, 2196, 80, 'bag', 15),
  (3, 'FEED-FISH-20', 'Fish Feed (20kg)', 'Feed', 2, 3200, 10, 20, 3520, 3840, 40, 'bag', 10),
  (4, 'FERT-NPK-50', 'NPK Fertilizer (50kg)', 'Fertilizer', 3, 5000, 8, 20, 5400, 6000, 60, 'bag', 15),
  (5, 'SEED-MAIZE-2', 'Hybrid Maize Seed (2kg)', 'Seed', 3, 700, 10, 18, 770, 826, 200, 'pack', 30),
  (6, 'VAC-NEWCAS-100', 'Newcastle Vaccine (100 doses)', 'Vaccine', 1, 1200, 12, 25, 1344, 1500, 25, 'vial', 8),
  (7, 'MED-DEWORM-1L', 'Livestock Dewormer (1L)', 'Medicine', 1, 1500, 12, 24, 1680, 1860, 35, 'bottle', 10),
  (8, 'EQUIP-PUMP-1', 'Knapsack Sprayer (16L)', 'Equipment', 1, 3500, 10, 22, 3850, 4270, 18, 'unit', 5);

-- Test customer starts KYC pending so "Complete User Registration" flow is demonstrable
INSERT OR IGNORE INTO customers (id, user_id, agent_id, full_name, national_id, date_of_birth, gender, mobile, county, sub_county, ward, village, latitude, longitude, value_chain_type, value_chain, acreage, herd_size, farm_experience, kyc_status, risk_band, credit_score) VALUES
  (1, 3, 2, 'Fatuma Hassan', '29384756', '1988-04-12', 'Female', '+2547300000', 'Nakuru', 'Naivasha', 'Hells Gate', 'Mai Mahiu', -0.7167, 36.4333, 'livestock', 'Dairy', 5.0, 8, 6, 'pending', NULL, NULL);

INSERT OR IGNORE INTO customers (id, agent_id, full_name, national_id, gender, mobile, county, value_chain_type, value_chain, kyc_status, risk_band, credit_score) VALUES
  (2, 2, 'Peter Kamau', '31245678', 'Male', '+254790112233', 'Nakuru', 'crop', 'Maize', 'pending', 'medium', 610);

-- Sample completed cash sale + an active credit contract (kyc considered done historically)
INSERT OR IGNORE INTO murabaha_contracts (id, contract_ref, customer_id, agent_id, product_id, quantity, payment_type, supplier_cost, markup_pct, murabaha_price, term_months, monthly_payment, delivery_location, status, ownership_recorded, consent_given, amount_paid, outstanding) VALUES
  (1, 'MRB-2026-0001', 1, 2, 1, 2, 'cash', 5000, 10, 5500, 0, 0, 'Mai Mahiu', 'completed', 1, 1, 5500, 0),
  (2, 'MRB-2026-0002', 1, 2, 4, 2, 'financing', 10000, 20, 12000, 6, 2000, 'Mai Mahiu', 'active', 1, 1, 4000, 8000);

INSERT OR IGNORE INTO repayments (contract_id, installment_no, due_date, amount_due, amount_paid, status, paid_at) VALUES
  (2, 1, '2026-03-01', 2000, 2000, 'completed', '2026-03-01'),
  (2, 2, '2026-04-01', 2000, 2000, 'completed', '2026-04-01'),
  (2, 3, '2026-05-01', 2000, 0, 'late', NULL),
  (2, 4, '2026-06-01', 2000, 0, 'current', NULL),
  (2, 5, '2026-07-01', 2000, 0, 'current', NULL),
  (2, 6, '2026-08-01', 2000, 0, 'current', NULL);

INSERT OR IGNORE INTO invoices (invoice_ref, contract_id, customer_id, amount, status) VALUES
  ('INV-2026-0001', 1, 1, 5500, 'paid'),
  ('INV-2026-0002', 2, 1, 12000, 'partial');

INSERT OR IGNORE INTO transactions (txn_ref, contract_id, customer_id, amount, method, type, mpesa_receipt, status) VALUES
  ('TXN-0001', 1, 1, 5500, 'mpesa', 'cash_sale', 'SLE4XXXX1', 'success'),
  ('TXN-0002', 2, 1, 2000, 'mpesa', 'repayment', 'SLE4XXXX2', 'success'),
  ('TXN-0003', 2, 1, 2000, 'mpesa', 'repayment', 'SLE4XXXX3', 'success');
