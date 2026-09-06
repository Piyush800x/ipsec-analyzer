"""Builders for synthetic tshark ``-T json`` ISAKMP packets, used by the Track
A tests.

No tshark binary was available where Phase 4 was implemented, so these
fixtures encode this project's best-effort understanding of tshark's ISAKMP
JSON shape rather than a real capture's actual output -- see
``track_a/ike_parser.py``'s module docstring. They exist to test the parsing
*logic* in ``ike_parser.py`` against a self-consistent, documented input
shape; they cannot by themselves prove that shape matches a real tshark.
"""

from __future__ import annotations

from typing import Any


def packet(
    *,
    frame_number: int,
    ts: float,
    src: str,
    dst: str,
    isakmp: dict[str, Any],
) -> dict[str, Any]:
    return {
        "_source": {
            "layers": {
                "frame": {"frame.number": str(frame_number), "frame.time_epoch": repr(ts)},
                "ip": {"ip.src": src, "ip.dst": dst},
                "isakmp": isakmp,
            }
        }
    }


def isakmp_header(
    *,
    version: str,
    exchange_type: int,
    message_id: int = 0,
    init_spi: str,
    resp_spi: str = "0000000000000000",
    sa: dict[str, Any] | None = None,
    notify: dict[str, Any] | list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    header: dict[str, Any] = {
        "isakmp.version": version,
        "isakmp.exchangetype": str(exchange_type),
        "isakmp.messageid": f"{message_id:08x}",
        "isakmp.init_spi": init_spi,
        "isakmp.resp_spi": resp_spi,
    }
    if sa is not None:
        header["isakmp.sa"] = sa
    if notify is not None:
        header["isakmp.notify"] = notify
    return header


def sa_payload(proposals: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "isakmp.sa.proposals": {
            "isakmp.sa.proposal": proposals if len(proposals) != 1 else proposals[0]
        }
    }


def proposal(*, number: int, protocol_id: int, transforms: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "isakmp.prop.number": str(number),
        "isakmp.prop.protoid": str(protocol_id),
        "isakmp.tf": transforms if len(transforms) != 1 else transforms[0],
    }


def transform(
    *, transform_type: int, transform_id: int, attrs: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    t: dict[str, Any] = {"isakmp.tf.type": str(transform_type), "isakmp.tf.id": str(transform_id)}
    if attrs:
        t["isakmp.tf.attr"] = attrs if len(attrs) != 1 else attrs[0]
    return t


def attr(attr_type: int, value: int) -> dict[str, Any]:
    return {"isakmp.tf.attr.type": str(attr_type), "isakmp.tf.attr.value": str(value)}


def notify(msgtype: int) -> dict[str, Any]:
    return {"isakmp.notify.msgtype": str(msgtype)}
