-- Clears the staging order table before the reload.
-- deadbolt-expect DB-MIG-001:critical
DELETE FROM staging_orders;
