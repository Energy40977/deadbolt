# deadbolt-clean
"""Order reads: parameterised, paginated."""


def orders_for(cursor, user_id: int, limit: int = 50):
    cursor.execute(
        "SELECT id, total FROM orders WHERE user_id = %s LIMIT %s",
        (user_id, limit),
    )
    return cursor.fetchall()
