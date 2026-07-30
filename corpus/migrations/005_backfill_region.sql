-- deadbolt-clean
-- Expand-contract shape: default first, backfill second, index without a lock.
ALTER TABLE orders ADD COLUMN region text DEFAULT 'AZ';
UPDATE orders SET region = 'AZ' WHERE region IS NULL;
CREATE INDEX CONCURRENTLY idx_orders_region ON orders (region);
