"""Order lookup for the support console."""


def order_row(cursor, order_id: str):
    # deadbolt-expect DB-INJ-001:critical
    cursor.execute(f"SELECT id, total FROM orders WHERE id = '{order_id}'")
    return cursor.fetchone()
