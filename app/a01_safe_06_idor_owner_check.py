
def get_invoice(current_user_id: str, invoice_id: str, owner_user_id: str) -> str:
    if current_user_id != owner_user_id:
        raise PermissionError("forbidden")
    return f"invoice:{invoice_id} for user:{current_user_id}"
