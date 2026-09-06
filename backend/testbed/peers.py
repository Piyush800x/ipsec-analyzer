"""Container lifecycle for a pair of IPsec peers.

Implementation-plan step 2.3, LLD section 10.2.

``peer_pair`` is the only thing in the testbed that creates Docker resources,
and it is responsible for destroying every one of them. That responsibility is
the whole point of the module: a batch run (step 2.10) invokes this hundreds of
times, and a context manager that leaks one network per failed session will
exhaust the address pool of the daemon long before the batch finishes, with a
symptom -- "all predefined address pools have been fully subnetted" -- that says
nothing about the cause.

Every resource is labelled, so ``prune_orphans`` can clean up after a process
that was killed outright and never ran its ``finally``.
"""

from __future__ import annotations

import asyncio
import io
import logging
import tarfile
import uuid
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, Literal

import docker
from docker.errors import DockerException, NotFound

from testbed.config import IPV4, IpVersion, SessionConfig

if TYPE_CHECKING:
    from docker.models.containers import Container
    from docker.models.networks import Network

log = logging.getLogger(__name__)

PEER_IMAGE: Final = "ipsec-testbed-peer:0.1.0"

TESTBED_LABEL: Final = "ipsec-analyzer.testbed"
SESSION_LABEL: Final = "ipsec-analyzer.session"
"""Labels stamped on every container and network this module creates.

They exist so that orphans are identifiable. Matching on a name prefix would
also work until somebody runs two batches at once, or names a container by hand.
"""

Side = Literal["left", "right"]
SIDES: Final[tuple[Side, Side]] = ("left", "right")


class TestbedError(RuntimeError):
    """A testbed operation failed in a way that invalidates the session."""

    # The name begins with "Test", so pytest tries to collect this as a test
    # class and warns that it cannot because it takes constructor arguments.
    __test__ = False


class PeerCommandError(TestbedError):
    """A command inside a peer container exited non-zero."""

    def __init__(self, peer: str, cmd: Sequence[str], exit_code: int, output: str) -> None:
        self.peer = peer
        self.cmd = list(cmd)
        self.exit_code = exit_code
        self.output = output
        super().__init__(f"[{peer}] {' '.join(cmd)} exited {exit_code}\n{output.strip()}")


@dataclass(frozen=True)
class PeerHandle:
    """One running peer container, and the addresses it answers on."""

    side: Side
    container: Container
    addr: str
    """Outer address: what a capture on the bridge sees."""

    traffic_addr: str
    """Where traffic generators should send. Differs from ``addr`` in tunnel
    mode, where it is the protected address behind this peer."""

    @property
    def name(self) -> str:
        return str(self.container.name)

    async def exec(
        self,
        cmd: Sequence[str],
        *,
        check: bool = True,
        detach: bool = False,
        timeout_s: float | None = None,
    ) -> tuple[int, str]:
        """Run a command in the container.

        Returns ``(exit_code, combined_output)``. Raises ``PeerCommandError``
        when ``check`` and the command failed, because a silently ignored
        failure here becomes a mislabelled capture later.
        """

        def _run() -> tuple[int, str]:
            result = self.container.exec_run(list(cmd), detach=detach, demux=False)
            if detach:
                return 0, ""
            output = result.output.decode("utf-8", errors="replace") if result.output else ""
            return int(result.exit_code or 0), output

        try:
            code, output = await asyncio.wait_for(asyncio.to_thread(_run), timeout=timeout_s)
        except TimeoutError as exc:
            raise TestbedError(
                f"[{self.name}] {' '.join(cmd)} did not finish within {timeout_s}s"
            ) from exc

        if check and code != 0:
            raise PeerCommandError(self.name, cmd, code, output)
        return code, output

    async def write_file(self, path: str, content: str) -> None:
        """Write ``content`` to ``path`` inside the container.

        Sent as a tar stream rather than piped through a shell. swanctl.conf
        contains braces, quotes and newlines, and every shell-quoting scheme
        that survives those is one someone will eventually get wrong.
        """
        data = content.encode("utf-8")
        directory, _, filename = path.rpartition("/")

        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as tar:
            info = tarfile.TarInfo(name=filename)
            info.size = len(data)
            info.mode = 0o600
            tar.addfile(info, io.BytesIO(data))
        archive.seek(0)

        def _put() -> None:
            if not self.container.put_archive(directory or "/", archive.getvalue()):
                raise TestbedError(f"[{self.name}] failed to write {path}")

        await asyncio.to_thread(_put)

    async def logs(self, *, tail: int = 200) -> str:
        def _logs() -> str:
            raw: bytes = self.container.logs(tail=tail, stdout=True, stderr=True)
            return raw.decode("utf-8", errors="replace")

        return await asyncio.to_thread(_logs)


def _client() -> docker.DockerClient:
    try:
        return docker.from_env()
    except DockerException as exc:
        raise TestbedError(
            "cannot reach the Docker daemon. The testbed needs a running daemon "
            "with kernel XFRM available; see testbed/README.md."
        ) from exc


async def preflight() -> None:
    """Check that this host can actually run kernel IPsec.

    Called before a batch rather than discovered halfway through one. The
    failure this catches -- XFRM modules absent from the running kernel -- shows
    up otherwise as every tunnel timing out in negotiation, which looks like a
    configuration bug and costs a day.
    """
    client = _client()

    def _probe() -> tuple[int, str]:
        container = client.containers.run(
            PEER_IMAGE,
            command=["ip", "xfrm", "state"],
            cap_add=["NET_ADMIN"],
            network_mode="none",
            labels={TESTBED_LABEL: "1", SESSION_LABEL: "preflight"},
            detach=True,
        )
        try:
            status = container.wait(timeout=30)
            output = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
            return int(status.get("StatusCode", 1)), output
        finally:
            container.remove(force=True)

    code, output = await asyncio.to_thread(_probe)
    if code != 0:
        raise TestbedError(
            "kernel XFRM is not usable from a container on this host, so no "
            "tunnel can be established:\n"
            f"{output.strip()}\n\n"
            "On most hosts the fix is to load the modules once:\n"
            "  sudo modprobe esp4 esp6 ah4 ah6 xfrm_user af_key\n"
            "Under Docker Desktop, run that inside the VM:\n"
            "  docker run --rm --privileged --pid=host alpine nsenter -t 1 -m -u -n -i "
            "modprobe esp4 esp6 ah4 ah6 xfrm_user af_key\n\n"
            "Do not work around this by enabling kernel-libipsec -- LLD 10.3 "
            "explains why a userspace ESP dataset is worse than no dataset."
        )


def _network_ipam(cfg: SessionConfig) -> docker.types.IPAMConfig:
    """Address pools for the session network.

    IPv4 is always configured, even for an IPv6 session: the peers need a
    working v4 stack for the container runtime itself, and a dual-stack bridge
    is what a real gateway sits on anyway.
    """
    pools = [docker.types.IPAMPool(subnet=cfg.addressing.subnet)]
    if cfg.ip is IpVersion.V6:
        # The v4 pool is offset by the same index as the v6 one. It is never
        # used for traffic, but the daemon still refuses to create two networks
        # claiming the same v4 subnet -- so a shared v4 pool would make v6
        # sessions collide across shards even though their v6 subnets differ.
        pools = [
            docker.types.IPAMPool(subnet=IPV4.offset(cfg.address_index).subnet),
            docker.types.IPAMPool(subnet=cfg.addressing.subnet),
        ]
    return docker.types.IPAMConfig(pool_configs=pools)


def _endpoint_addresses(cfg: SessionConfig, side: Side) -> dict[str, str]:
    """Static addresses to give one peer on the session network.

    An IPv6 session still gets a v4 address: the bridge carries a v4 pool
    regardless, and Docker rejects an endpoint that claims an address from only
    one of a dual-stack network's pools.
    """
    # Offset by the session's address index, like the pool it must fall inside.
    # Docker rejects an endpoint whose static address is outside the network's
    # subnet, with "invalid endpoint settings" -- which is what a shard on a
    # different subnet gets if this reaches for the unshifted constant.
    v4 = IPV4.offset(cfg.address_index)
    addresses = {"ipv4_address": v4.left if side == "left" else v4.right}
    if cfg.ip is IpVersion.V6:
        addresses["ipv6_address"] = cfg.addressing.left if side == "left" else cfg.addressing.right
    return addresses


def _peer_environment(cfg: SessionConfig, side: Side) -> dict[str, str]:
    """Entrypoint environment: protected addressing for tunnel mode.

    Transport mode gets none of this. Its traffic selectors are the outer
    addresses, so a dummy interface would be an unused decoration -- and an
    unused interface is one more thing to explain when a capture looks wrong.
    """
    if cfg.is_transport:
        return {}

    addressing = cfg.addressing
    other: Side = "right" if side == "left" else "left"
    protected = addressing.left_protected if side == "left" else addressing.right_protected
    peer_subnet = (
        addressing.left_protected_subnet if other == "left" else addressing.right_protected_subnet
    )
    peer_addr = addressing.left if other == "left" else addressing.right

    if cfg.ip is IpVersion.V6:
        return {
            "PROTECTED_ADDR6": protected,
            "PEER_ADDR6": peer_addr,
            "PEER_PROTECTED_SUBNET6": peer_subnet,
        }
    return {
        "PROTECTED_ADDR": protected,
        "PEER_ADDR": peer_addr,
        "PEER_PROTECTED_SUBNET": peer_subnet,
    }


_SYSCTLS: Final[dict[str, str]] = {
    # Tunnel mode forwards between the protected subnet and the tunnel.
    "net.ipv4.ip_forward": "1",
    "net.ipv6.conf.all.forwarding": "1",
    # Reverse-path filtering drops decrypted tunnel-mode packets, whose inner
    # source address does not route back out the interface they arrived on.
    # Set here as well as in the entrypoint because Docker mounts /proc/sys
    # read-only for unprivileged containers, so the entrypoint cannot always do
    # it -- and a tunnel that establishes and then passes nothing is the single
    # most confusing failure mode in this whole subsystem.
    "net.ipv4.conf.all.rp_filter": "0",
    "net.ipv4.conf.default.rp_filter": "0",
}


@asynccontextmanager
async def peer_pair(
    cfg: SessionConfig,
    *,
    image: str = PEER_IMAGE,
    session_token: str | None = None,
) -> AsyncIterator[tuple[PeerHandle, PeerHandle]]:
    """Create a network and two peers, yield handles, and destroy everything.

    Teardown runs whether the body succeeded, raised, or was cancelled, and it
    never raises on its own: a cleanup failure must not mask the exception that
    caused it. Failures are logged and the resources are left labelled for
    ``prune_orphans``.
    """
    client = _client()
    token = session_token or uuid.uuid4().hex[:10]
    labels = {TESTBED_LABEL: "1", SESSION_LABEL: token}
    network_name = f"ipsec-tb-{token}"

    network: Network | None = None
    containers: list[Container] = []

    try:
        network = await asyncio.to_thread(
            client.networks.create,
            network_name,
            driver="bridge",
            enable_ipv6=cfg.ip is IpVersion.V6,
            ipam=_network_ipam(cfg),
            labels=labels,
        )

        handles: list[PeerHandle] = []
        for side in SIDES:
            addr = cfg.addressing.left if side == "left" else cfg.addressing.right

            def _create(side: Side = side) -> Container:
                # The addresses are fixed at creation rather than assigned by
                # Docker, because the rendered swanctl.conf names them literally
                # in local_addrs, remote_addrs and the traffic selectors. They
                # have to be decided before the container exists, not read back
                # from it afterwards.
                return client.containers.create(
                    image,
                    # charon in the foreground, so Docker owns its lifetime and a
                    # daemon that dies stops the container instead of leaving a
                    # hollow one the orchestrator would happily configure. The
                    # config arrives afterwards via `swanctl --load-all`.
                    command=["charon"],
                    name=f"ipsec-tb-{token}-{side}",
                    hostname=side,
                    cap_add=["NET_ADMIN"],
                    sysctls=dict(_SYSCTLS),
                    environment=_peer_environment(cfg, side),
                    labels=labels,
                    network=network_name,
                    networking_config={
                        network_name: client.api.create_endpoint_config(
                            **_endpoint_addresses(cfg, side)
                        )
                    },
                    detach=True,
                )

            container = await asyncio.to_thread(_create)
            containers.append(container)
            await asyncio.to_thread(container.start)

            handles.append(
                PeerHandle(
                    side=side,
                    container=container,
                    addr=addr,
                    traffic_addr=cfg.traffic_endpoint(side),
                )
            )

        left, right = handles
        log.info("peer pair %s up: %s / %s", token, left.name, right.name)
        yield left, right

    finally:
        for container in containers:
            try:
                await asyncio.to_thread(container.remove, force=True, v=True)
            except NotFound:
                pass
            except DockerException:
                log.exception("failed to remove container %s", getattr(container, "name", "?"))
        if network is not None:
            try:
                await asyncio.to_thread(network.remove)
            except NotFound:
                pass
            except DockerException:
                log.exception("failed to remove network %s", network_name)


async def prune_orphans(session: str | None = None) -> tuple[int, int]:
    """Remove testbed containers and networks left behind.

    A killed process never runs its ``finally``. Returns the counts removed, so
    a caller can report that it had cleaning up to do rather than doing it
    silently.

    *session* restricts the sweep to one session's resources, and passing it is
    **required whenever another batch might be running.** Unrestricted, this
    force-removes every container carrying ``TESTBED_LABEL`` -- including the
    live peers of a concurrent shard (``--shard I/N``), whose session would
    then fail, prune in turn, and take down the next one. Three shards sharing
    a Docker daemon would cascade each other to a standstill on the first
    unrelated failure.

    The unrestricted form stays available and is still what a batch wants
    *before* it starts, where anything labelled really is an orphan.
    """
    client = _client()

    def _prune() -> tuple[int, int]:
        filters: dict[str, Any] = {"label": TESTBED_LABEL}
        if session is not None:
            filters["label"] = [f"{TESTBED_LABEL}=1", f"{SESSION_LABEL}={session}"]
        removed_containers = 0
        for container in client.containers.list(all=True, filters=filters):
            try:
                container.remove(force=True, v=True)
                removed_containers += 1
            except NotFound:
                pass

        removed_networks = 0
        for network in client.networks.list(filters=filters):
            try:
                network.remove()
                removed_networks += 1
            except NotFound:
                pass
        return removed_containers, removed_networks

    return await asyncio.to_thread(_prune)
