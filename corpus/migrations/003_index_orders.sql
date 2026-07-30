-- Speeds up the per-user order listing.
-- deadbolt-expect DB-MIG-003:medium
CREATE INDEX idx_orders_user ON orders (user_id);
