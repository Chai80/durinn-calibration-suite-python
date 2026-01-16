# DURINN_GT id=a01_06_idor_no_owner_check track=sast set=core owasp=A01

def get_invoice(current_user_id: str, invoice_id: str) -> str:
    # BUG: no ownership check
    return f"invoice:{invoice_id} for user:{current_user_id}"
