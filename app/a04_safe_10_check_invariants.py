
def transfer(balance: dict, from_id: str, to_id: str, amount: int) -> None:
    if amount <= 0:
        raise ValueError("bad amount")
    if balance.get(from_id, 0) < amount:
        raise ValueError("insufficient")
    balance[from_id] -= amount
    balance[to_id] = balance.get(to_id, 0) + amount
