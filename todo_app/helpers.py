from datetime import datetime, timedelta


def default_expiry():
    return datetime.utcnow() + timedelta(minutes=5)