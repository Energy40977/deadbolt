-- Removes the superseded reference column.
-- deadbolt-expect DB-MIG-002:high
ALTER TABLE orders DROP COLUMN legacy_ref;
