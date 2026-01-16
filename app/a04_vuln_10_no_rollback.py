# DURINN_GT id=a04_10_no_rollback track=sast set=core owasp=A04

def transfer(balance: dict, from_id: str, to_id: str, amount: int) -> None:
    # BUG: no rollback / invariants
    balance[from_id] -= amount
    balance[to_id] += amount
