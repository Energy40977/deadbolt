-- Adds the settlement region.
-- deadbolt-expect DB-MIG-004:medium
ALTER TABLE orders ADD COLUMN region text NOT NULL;
