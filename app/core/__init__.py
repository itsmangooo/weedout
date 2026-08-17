"""Pure domain logic for Weedout.

Nothing in this package may import SQLAlchemy, FastAPI, or application settings.
Manifest parsing, version-range evaluation and CVE match triage are all plain
functions over plain dataclasses so they can be tested without a database or an
HTTP client. The web and persistence layers adapt to these types, not vice versa.
"""
