from urllib.parse import urlparse

def validate_authorized_target(target: str, authorized_target: str) -> bool:
    """Validate that the authorized target matches the scan target."""
    if not authorized_target:
        return False
    return urlparse(authorized_target).netloc == urlparse(target).netloc
