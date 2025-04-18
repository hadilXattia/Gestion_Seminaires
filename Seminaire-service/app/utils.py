from datetime import datetime

def parse_iso_datetime(date_str):
    """
    Parse an ISO 8601 datetime string to a Python datetime object.
    """
    try:
        return datetime.fromisoformat(date_str)
    except ValueError:
        raise ValueError("Invalid ISO 8601 datetime format.")
