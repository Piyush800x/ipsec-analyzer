"""Builders for synthetic tshark ``-T json --no-duplicate-keys`` ISAKMP packets.

**Rebuilt from real output.** Phase 4 wrote these from a best-effort reading of
Wireshark's display-filter names, without a tshark binary to check against, and
almost every structural guess in them was wrong -- so the Track A tests passed
against a JSON shape tshark never produces, while Track A observed nothing at
all on a real capture. See ``track_a/ike_parser.py``'s module docstring for the
list of what differed.

Every key and every rendering below now mirrors what tshark 4.4.18 emitted for
the two reference tunnels of step 8.1's pilot batch:

* Payloads are *two* aligned repeated keys, ``isakmp.typepayload`` (the type
  number) and ``isakmp.typepayload_tree`` (the contents), nested recursively --
  not the ``isakmp.sa.proposals``/``isakmp.tf`` containers assumed before.
* SPIs and transform-attribute values are colon-separated octets, not decimal.
* ``isakmp.version`` is the packed byte (``0x20``), with the nibbles split into
  ``isakmp.version_tree``.
* IKEv1 and IKEv2 get *different* key names for the same concepts:
  ``isakmp.ike.attr`` vs ``isakmp.ike2.attr``, ``isakmp.trans.id`` vs a
  per-type ``isakmp.tf.id.encr``/``.prf``/``.integ``/``.dh``/``.esn``.

The builders therefore take a neutral description of a message and render it in
the dialect matching the IKE version passed to ``isakmp_header``. Keeping the
version-dependent rendering in one place is what lets a test say "an IKEv1
aggressive-mode proposal offering 3DES" without restating tshark's spelling of
it, and stops a fixture drifting into a shape only the parser believes in.

These fixtures still cannot prove the *next* tshark renders things this way.
That is what the version pin and ``tests/test_tshark_version.py`` are for.
"""

from __future__ import annotations

from typing import Any

PAYLOAD_TYPE_KEY = "isakmp.typepayload"
PAYLOAD_TREE_KEY = "isakmp.typepayload_tree"

_SA_PAYLOAD_TYPE = {1: 1, 2: 33}
_NOTIFY_PAYLOAD_TYPE = {1: 11, 2: 41}
_PROPOSAL_PAYLOAD_TYPE = 2
_TRANSFORM_PAYLOAD_TYPE = 3

_IKEV2_TRANSFORM_ID_KEY = {
    1: "isakmp.tf.id.encr",
    2: "isakmp.tf.id.prf",
    3: "isakmp.tf.id.integ",
    4: "isakmp.tf.id.dh",
    5: "isakmp.tf.id.esn",
}
"""tshark names an IKEv2 transform ID after the transform type it belongs to."""


def _octets(value: str) -> str:
    """A hex string as tshark renders it: colon-separated octet pairs."""
    padded = value if len(value) % 2 == 0 else "0" + value
    return ":".join(padded[i : i + 2] for i in range(0, len(padded), 2))


def _attr_value(value: int) -> str:
    """An attribute value as octets, in the width the encoding would use.

    Two bytes is the TV form every algorithm identifier uses; anything larger
    (a lifetime in seconds, typically) needs the four-byte TLV form. Rendering
    the natural width rather than always four bytes keeps a fixture honest
    about which encoding it is standing in for.
    """
    width = 2 if value < 0x10000 else 4
    return _octets(value.to_bytes(width, "big").hex())


def _chain(payloads: list[tuple[int, dict[str, Any]]]) -> dict[str, Any]:
    """Render ``(type, contents)`` pairs as tshark's repeated payload keys.

    A lone payload is emitted as a bare value rather than a one-element list,
    which is what tshark does and what the parser has to tolerate.
    """
    if not payloads:
        return {}
    types = [str(payload_type) for payload_type, _ in payloads]
    trees = [tree for _, tree in payloads]
    return {
        PAYLOAD_TYPE_KEY: types if len(types) > 1 else types[0],
        PAYLOAD_TREE_KEY: trees if len(trees) > 1 else trees[0],
    }


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
    """One ISAKMP message. *version* is ``"1.0"`` or ``"2.0"``.

    This is where the neutral payload descriptions built below are rendered
    into one IKE version's spelling, because the version is the one thing that
    decides it and this is the only builder that knows it.
    """
    major = int(version.split(".", 1)[0])
    header: dict[str, Any] = {
        "isakmp.ispi": _octets(init_spi),
        "isakmp.rspi": _octets(resp_spi),
        "isakmp.version": f"0x{major << 4:02x}",
        "isakmp.version_tree": {"isakmp.mjver": f"0x{major:02x}", "isakmp.mnver": "0x00"},
        "isakmp.exchangetype": str(exchange_type),
        "isakmp.messageid": f"0x{message_id:08x}",
    }

    payloads: list[tuple[int, dict[str, Any]]] = []
    if sa is not None:
        payloads.append((_SA_PAYLOAD_TYPE[major], _render_sa(sa, major)))
    notifies = notify if isinstance(notify, list) else ([] if notify is None else [notify])
    payloads.extend((_NOTIFY_PAYLOAD_TYPE[major], n) for n in notifies)

    header.update(_chain(payloads))
    return header


# ===========================================================================
# Neutral payload descriptions, rendered by ``isakmp_header`` above
# ===========================================================================


def sa_payload(proposals: list[dict[str, Any]]) -> dict[str, Any]:
    return {"proposals": proposals}


def proposal(*, number: int, protocol_id: int, transforms: list[dict[str, Any]]) -> dict[str, Any]:
    return {"number": number, "protocol_id": protocol_id, "transforms": transforms}


def transform(
    *, transform_type: int, transform_id: int, attrs: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    return {"type": transform_type, "id": transform_id, "attrs": attrs or []}


def attr(attr_type: int, value: int) -> dict[str, Any]:
    return {"type": attr_type, "value": value}


def notify(msgtype: int) -> dict[str, Any]:
    return {"isakmp.notify.msgtype": str(msgtype)}


def _render_sa(sa: dict[str, Any], major: int) -> dict[str, Any]:
    tree: dict[str, Any] = {"isakmp.sa.doi": "1"} if major == 1 else {}
    tree.update(
        _chain(
            [(_PROPOSAL_PAYLOAD_TYPE, _render_proposal(p, major)) for p in sa.get("proposals", [])]
        )
    )
    return tree


def _render_proposal(spec: dict[str, Any], major: int) -> dict[str, Any]:
    transforms = spec.get("transforms", [])
    tree: dict[str, Any] = {
        "isakmp.prop.number": str(spec["number"]),
        "isakmp.prop.protoid": str(spec["protocol_id"]),
        "isakmp.spisize": "0",
        "isakmp.prop.transforms": str(len(transforms)),
    }
    tree.update(
        _chain(
            [
                (_TRANSFORM_PAYLOAD_TYPE, _render_transform(t, index + 1, major))
                for index, t in enumerate(transforms)
            ]
        )
    )
    return tree


def _render_transform(spec: dict[str, Any], number: int, major: int) -> dict[str, Any]:
    attrs = spec.get("attrs", [])
    if major == 2:
        id_key = _IKEV2_TRANSFORM_ID_KEY.get(spec["type"], "isakmp.tf.id")
        tree: dict[str, Any] = {"isakmp.tf.type": str(spec["type"]), id_key: str(spec["id"])}
        container = "isakmp.ike2.attr"
    else:
        # IKEv1 carries a transform *number* and an ID, and no type: the
        # algorithms are all attributes. ``spec["type"]`` is ignored here on
        # purpose -- it has no rendering in IKEv1 and inventing one would put a
        # key in the fixture that tshark never emits.
        tree = {"isakmp.trans.number": str(number), "isakmp.trans.id": str(spec["id"])}
        container = "isakmp.ike.attr"

    if attrs:
        rendered = [
            {
                f"{container}.format": "1",
                f"{container}.type": str(a["type"]),
                f"{container}.value": _attr_value(a["value"]),
            }
            for a in attrs
        ]
        tree[container] = rendered if len(rendered) > 1 else rendered[0]
    return tree
