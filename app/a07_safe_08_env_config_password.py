import os

CONFIG = {
    "db_user": "app",
    "db_password": os.environ.get("DB_PASSWORD", ""),
}
