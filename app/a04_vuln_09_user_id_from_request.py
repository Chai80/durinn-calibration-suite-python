# DURINN_GT id=a04_09_user_id_from_request track=sast set=core owasp=A04

def delete_account(request_json: dict) -> str:
    # BUG: trust client-provided user id
    user_id = request_json.get("user_id")
    return f"deleted:{user_id}"
