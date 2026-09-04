# syntax=docker/dockerfile:1

# Backend image. Carries the pinned tshark that Track A shells out to.
#
# LLD §6.1: we do not hand-roll ISAKMP dissection, we parse Wireshark's JSON.
# Wireshark's JSON field names change across releases and a version drift breaks
# the parser silently -- wrong output, no error. So the version is pinned here,
# recorded in pyproject.toml under [tool.ipsec-analyzer.external-tools], and
# asserted by tests/test_tshark_version.py. All three must agree.
#
# Bumping: when Debian rotates the package out of the archive this build fails
# with an unmet-dependency error naming the version that replaced it. That
# failure is the point -- bump TSHARK_DEB_VERSION and TSHARK_VERSION here,
# update pyproject.toml, then re-run the Track A golden-PCAP tests before
# merging. Do not relax the pin to make the build pass.

ARG PYTHON_VERSION=3.11
FROM python:${PYTHON_VERSION}-slim-trixie AS base

# Debian 13 (trixie) with trixie-security applied ships wireshark
# 4.4.18-0+deb13u1 -> tshark 4.4.18. wireshark-common is pinned alongside
# tshark: they are lockstep-versioned, and pinning only tshark lets apt pull a
# newer common package and fail the dependency solve.
ARG TSHARK_DEB_VERSION=4.4.18-0+deb13u1
ARG TSHARK_VERSION=4.4.18

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive \
    TSHARK_VERSION=${TSHARK_VERSION}

# wireshark-common asks, via debconf, whether non-root users may capture. We
# only ever read PCAP files from disk -- NFR-5 forbids this tool from putting a
# packet on the wire at all -- so answer no and skip the dumpcap setuid step.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" \
      | debconf-set-selections \
 && apt-get update \
 && apt-get install --no-install-recommends -y \
      "wireshark-common=${TSHARK_DEB_VERSION}" \
      "tshark=${TSHARK_DEB_VERSION}" \
 && rm -rf /var/lib/apt/lists/*

# Fail the build, not the demo, if the installed binary is not what we pinned.
RUN installed="$(tshark --version | head -n 1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)" \
 && echo "tshark reports ${installed}, pin is ${TSHARK_VERSION}" \
 && [ "${installed}" = "${TSHARK_VERSION}" ]

COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /uvx /usr/local/bin/

WORKDIR /app

# Dependency layer first so source edits do not re-resolve the environment.
COPY pyproject.toml uv.lock .python-version README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev

COPY src ./src
COPY alembic ./alembic
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:${PATH}"

# Captures are read-only inputs, processed locally (NFR-6). Nothing needs root.
RUN useradd --create-home --uid 10001 analyzer \
 && mkdir -p /data/captures \
 && chown -R analyzer:analyzer /app /data
USER analyzer

# The API entrypoint arrives in Phase 6 (step 6.1). Until then this image exists
# to carry the pinned toolchain, so it drops you in a shell rather than
# pretending to serve something.
CMD ["bash"]
