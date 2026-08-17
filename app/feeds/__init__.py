"""Clients for the upstream vulnerability feeds Weedout depends on."""

from app.feeds.kev import KevClient, KevFeedError
from app.feeds.osv import OSVClient, OSVError

__all__ = ["KevClient", "KevFeedError", "OSVClient", "OSVError"]
