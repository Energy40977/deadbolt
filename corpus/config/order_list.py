"""Order listing for the operations console."""

from billing.models import Order


def every_order():
    # deadbolt-expect DB-CFG-003:medium
    return Order.objects.all()
