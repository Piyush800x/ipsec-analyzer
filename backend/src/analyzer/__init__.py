"""AI-powered IPsec VPN protocol analyzer and security assessment framework.

Module map (LLD §5-§9):

- ``core``     -- enums, the Pydantic contract, settings, error types
- ``ingest``   -- M2, PCAP reading and flow assembly
- ``track_a``  -- M3, deterministic IKE parsing
- ``track_b``  -- M4, statistical inference over encrypted ESP
- ``assess``   -- M5, rule evaluation, scoring, threat matrix
- ``report``   -- M6, PDF rendering
- ``db``       -- SQLAlchemy models and session factory
- ``api``      -- FastAPI application
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
