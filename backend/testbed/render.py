"""Render a ``SessionConfig`` into a swanctl.conf for one peer.

Implementation-plan step 2.2.

Both sides come from the same ``SessionConfig``, which is what stops the two
ends of a tunnel disagreeing about what they are negotiating. The only thing
that differs between them is the point of view: which address is local, which
traffic selector is ours, which identity we present.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final, Literal

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from testbed.config import IkeFlavour, SessionConfig

TEMPLATE_DIR: Final = Path(__file__).parent / "templates"
TEMPLATE_NAME: Final = "swanctl.conf.j2"

CONNECTION_NAME: Final = "testbed"
CHILD_NAME: Final = "net"
"""The connection and child names the orchestrator initiates by.

Fixed rather than derived from the session name: ``swanctl --initiate --child``
takes the child name, and step 2.4 has to know it without carrying the config
around. Changing either of these means changing tunnel.py in the same commit.
"""

Side = Literal["left", "right"]

_ENV: Final = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    # StrictUndefined turns a renamed or missing variable into a render-time
    # error. The default silently substitutes an empty string, which here would
    # emit `proposals = ` -- a syntactically valid config that negotiates
    # nothing, and a tunnel that fails for no visible reason.
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
    keep_trailing_newline=True,
    # swanctl.conf is not markup. HTML-escaping it would turn every `&` and
    # quote in a proposal string or PSK into an entity and produce a config
    # strongSwan rejects.
    autoescape=False,
)


def peer_identity(side: Side) -> str:
    """The IKE identity a peer presents.

    FQDN-shaped because that is what real deployments use, and because an
    address-shaped ID would be indistinguishable from the ID_IPV4_ADDR that
    strongSwan derives by default -- making it impossible to tell from a capture
    whether an identity was configured or inferred.
    """
    return f"{side}.testbed.local"


def render_swanctl_conf(cfg: SessionConfig, side: Side) -> str:
    """Render the swanctl.conf for ``side`` of ``cfg``."""
    other: Side = "right" if side == "left" else "left"
    addressing = cfg.addressing

    return _ENV.get_template(TEMPLATE_NAME).render(
        conn_name=CONNECTION_NAME,
        child_name=CHILD_NAME,
        ike_version=cfg.ike_version.value,
        aggressive=cfg.ike is IkeFlavour.IKEV1_AGGRESSIVE,
        local_addr=addressing.left if side == "left" else addressing.right,
        remote_addr=addressing.left if other == "left" else addressing.right,
        local_id=peer_identity(side),
        remote_id=peer_identity(other),
        ike_proposal=cfg.ike_proposal,
        esp_proposal=cfg.esp_proposal,
        local_ts=cfg.local_ts(side),
        remote_ts=cfg.remote_ts(side),
        mode=cfg.mode.value,
        lifetime_s=cfg.lifetime_s,
        psk=cfg.psk,
    )
