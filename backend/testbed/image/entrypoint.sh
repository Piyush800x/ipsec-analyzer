#!/bin/sh
# Peer container entrypoint — implementation-plan step 2.1.
#
# Prepares the network namespace, then hands over to charon in the foreground so
# that Docker owns the process lifetime and a crashed daemon stops the container
# instead of leaving a hollow one the orchestrator would happily configure.
set -eu

log() { printf '[entrypoint] %s\n' "$*" >&2; }

# XFRM state is network-namespace scoped, which is the whole reason two
# containers on one bridge can hold independent SAs (LLD §10.2). These sysctls
# are per-namespace too, so they must be set here rather than on the host.
set_sysctl() {
    if [ -w "/proc/sys/$1" ]; then
        echo "$2" > "/proc/sys/$1"
    else
        log "WARNING: cannot write /proc/sys/$1 — is --cap-add=NET_ADMIN missing?"
    fi
}

set_sysctl net/ipv4/ip_forward 1
set_sysctl net/ipv6/conf/all/forwarding 1

# Reverse-path filtering drops decrypted tunnel-mode packets, whose inner source
# address does not route back out the interface they arrived on. This is the
# single most common reason a tunnel establishes and then passes no traffic.
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
    [ -e "$f" ] && echo 0 > "$f" 2>/dev/null || true
done

# Tunnel mode needs a protected subnet behind each peer, otherwise the inner and
# outer addresses coincide and the capture is indistinguishable from transport
# mode. A dummy interface gives us one without a second container per side.
if [ -n "${PROTECTED_ADDR:-}" ]; then
    log "protected address ${PROTECTED_ADDR} on dummy0"
    ip link add dummy0 type dummy 2>/dev/null || true
    ip link set dummy0 up
    ip addr add "${PROTECTED_ADDR}" dev dummy0 2>/dev/null || true
fi
if [ -n "${PROTECTED_ADDR6:-}" ]; then
    log "protected address ${PROTECTED_ADDR6} on dummy0"
    ip link add dummy0 type dummy 2>/dev/null || true
    ip link set dummy0 up
    ip addr add "${PROTECTED_ADDR6}" dev dummy0 2>/dev/null || true
fi

# Route the peer's protected subnet down the tunnel. With policy-based IPsec the
# XFRM policy does the encapsulation, but the kernel still needs a route that
# selects a source address in our own protected subnet.
if [ -n "${PEER_PROTECTED_SUBNET:-}" ] && [ -n "${PEER_ADDR:-}" ]; then
    ip route replace "${PEER_PROTECTED_SUBNET}" via "${PEER_ADDR}" 2>/dev/null \
        || log "WARNING: could not install route to ${PEER_PROTECTED_SUBNET}"
fi
if [ -n "${PEER_PROTECTED_SUBNET6:-}" ] && [ -n "${PEER_ADDR6:-}" ]; then
    ip -6 route replace "${PEER_PROTECTED_SUBNET6}" via "${PEER_ADDR6}" 2>/dev/null \
        || log "WARNING: could not install route to ${PEER_PROTECTED_SUBNET6}"
fi

case "${1:-charon}" in
    charon)
        # charon-systemd reads swanctl.conf rather than the legacy ipsec.conf,
        # and runs perfectly well without systemd — it only calls sd_notify,
        # which is a no-op when NOTIFY_SOCKET is unset.
        log "starting charon-systemd"
        exec /usr/sbin/charon-systemd
        ;;
    idle)
        log "idling"
        exec sleep infinity
        ;;
    *)
        exec "$@"
        ;;
esac
