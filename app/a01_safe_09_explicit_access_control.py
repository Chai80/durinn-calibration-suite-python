
def delete_user(current_user, target_user_id: str) -> None:
    if not getattr(current_user, "is_admin", False):
        raise PermissionError("forbidden")
    _ = target_user_id
