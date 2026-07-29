# Lens: migration — Taking The Service Down With A Schema Change

## Mandate

A migration rarely creates a security vulnerability — it creates **irreversible
unavailability**. Here the "attacker" is usually your own team.

Priority: **breaking older clients**.

## Critical Context

Mobile app versions on user devices **keep sending** requests that match the old
schema. A release that reached the store cannot be rolled back. A single-step
schema change is therefore irreversible breakage for those users.

## Phase 1 — Migration Inventory

```
Glob: "**/migrations/**", "**/alembic/versions/**", "**/*.sql", "**/db/migrate/**"
```

Read the most recent migrations (the last ones by date or number) — that is where
the risk is. **Separate** the `upgrade()` / `up()` block from the `downgrade()` /
`down()` block: deletions are normal inside a rollback block.

## Phase 2 — Attack Tree

### A. Expand-Contract Violation *(most severe)*

```
Grep: "drop_column|DROP COLUMN|drop_table|DROP TABLE|rename_column|RENAME COLUMN"
Grep: "alter_column.*type_|ALTER COLUMN.*TYPE"
```

The correct sequence has five steps and spans **two separate releases**:
1. add the new structure -> 2. write to both -> 3. backfill ->
4. switch reads -> 5. drop the old one **in a separate release**

Done in one step, older code — and older mobile clients — break.

**Check:** is that column still used in the application code?
```
Grep: "<dropped_column_name>"
```

### B. NOT NULL Without A Default

```
Grep: "ADD COLUMN.*NOT NULL|nullable\s*=\s*False|null: false"
```

If the table is not empty the migration aborts, the deployment is left
half-applied, and the code expects a column the schema does not have.

### C. Blocking DDL — A Scheduled Outage

```
Grep: "CREATE INDEX" -> when CONCURRENTLY is absent
Grep: "ALTER TABLE.*ADD CONSTRAINT|VALIDATE|SET NOT NULL"
```

In PostgreSQL, `CREATE INDEX` without CONCURRENTLY locks the table. On a table
with millions of rows that means minutes of complete downtime.

Also: if a long migration runs inside a transaction, the lock is held for its
entire duration.

### D. Unconditional Data Deletion

```
Grep: "TRUNCATE|DELETE FROM(?!.*WHERE)|UPDATE .* SET(?!.*WHERE)"
```

One run empties the whole table. Without a backup it is unrecoverable.

### E. No Rollback Step

If `downgrade()` is empty (`pass`, `...`, `NotImplementedError`), there is no way
back once the migration has been deployed.

## F. Code-Migration Ordering Mismatch *(easy to miss)*

The application code **already** reads the new column, but during deployment the
migration may not have been applied yet (a rolling deploy, several pods).

```
Grep: "<new_column_name>" -> in model, serializer and query files
```

Scenario: `a new pod starts -> queries the old schema -> 500 error`

### G. Size Of The Backfill

```
Grep: "op.execute|UPDATE .* SET .* FROM|INSERT INTO .* SELECT"
```

Does the migration contain an `UPDATE` that walks the whole table? How many rows?
Is it batched?

### H. Forgotten Index

Is there an index for a new foreign key or a frequently filtered column? Without
one, the query strangles the database as the table grows — a delayed denial of
service.

## Phase 3 — Verification

- [ ] The finding is inside the `upgrade()` block, not the rollback block
- [ ] The affected column or table is used in application code
- [ ] It is not compensated for by a later migration

## False-Positive Traps

| Trap | Check |
|---|---|
| The deletion is inside `downgrade()` | Establish the block boundary |
| The table is new and empty | Look at the creation migration |
| The column is used nowhere | Confirm with Grep |
| SQLite and MySQL behave differently | Establish which database is used |
