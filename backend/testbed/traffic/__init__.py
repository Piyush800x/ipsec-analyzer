"""Labelled traffic generators, one module per class (PRD section 9.2).

Implementation-plan step 2.6. ``base`` holds the shared plumbing and the table
of what shape each class commits to; every sibling module implements exactly one
of them and exposes ``async def generate(left, right, duration_s)``.

``base.registry`` maps every ``TrafficClass`` to its generator and is the only
place the mapping exists.
"""

from __future__ import annotations

from testbed.traffic.base import generate_traffic, registry

__all__ = ["generate_traffic", "registry"]
