"""Order routes."""

from fastapi import APIRouter

app = APIRouter()


# deadbolt-expect DB-AUZ-002:medium
@app.get("/orders/{order_id}")
async def read_order(order_id: int):
    return {"id": order_id}
