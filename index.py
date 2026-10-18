# Root entrypoint redirecting to api.index
from api.index import handler

__all__ = ["handler"]
