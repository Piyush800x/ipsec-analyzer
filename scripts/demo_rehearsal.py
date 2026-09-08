#!/usr/bin/env python3
"""Rehearse the PRD section 16 demo against a running stack. Step 11.6.

    python scripts/demo_rehearsal.py --runs 3

Step 11.6's **Done when** is "three consecutive clean runs", timed against a
two-minute target, and a rehearsal that is watched rather than measured cannot
demonstrate that. This drives the exact sequence PRD section 16 specifies,
through the same HTTP API the dashboard uses, and times each step:

1. Load Tunnel A's capture. Score, critical findings, threat matrix.
2. The traffic classifier's reading of the inner traffic, with its confidence
   -- the metadata-exposure point, which is the one thing PRD section 16 says
   the demo must state explicitly.
3. Load Tunnel B. The contrasting score and the near-empty findings list.
4. Tunnel A's executive report.

**It asserts rather than merely reporting.** A rehearsal whose only output is a
number tells you the stack was fast; it does not tell you the demo *works*.
Each step checks the thing that step is on stage to show -- that tunnel A
scores worse than tunnel B, that its findings are not empty and B's are
shorter, that the classifier actually returned a class, that the report is a
PDF -- so a run that is quick and wrong fails instead of passing.

Point it at the offline stack (step 11.4), which is what the demo runs on:

    docker compose -f docker-compose.offline.yml up -d
    python scripts/demo_rehearsal.py

``--base-url`` is the prefix the resource paths hang off, and it differs by
where you point it: the frontend's proxy route rewrites ``/api/<path>`` to the
backend's ``/api/v1/<path>``, so through the stack it is ``/api`` and against a
directly-started backend it is ``/api/v1``.

Nothing here imports the backend. It is deliberately an outside-in check over
HTTP, because that is what happens on the day.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

REPO_ROOT: Final = Path(__file__).resolve().parent.parent
DEMO_DIR: Final = REPO_ROOT / "dataset" / "demo"

TUNNEL_A: Final = "demo-tunnel-a"
TUNNEL_B: Final = "demo-tunnel-b"

TARGET_S: Final = 120.0
"""PRD section 16: "Target runtime: two minutes, no slides."."""

POLL_INTERVAL_S: Final = 0.5
ANALYSIS_TIMEOUT_S: Final = 180.0


class RehearsalError(RuntimeError):
    """A step of the demo did not do what the demo says it does."""


# ---------------------------------------------------------------------------
# A very small HTTP client
# ---------------------------------------------------------------------------
#
# urllib rather than httpx or requests so this script runs from a bare Python
# with nothing installed. A rehearsal tool that needs its own environment set
# up is one more thing to go wrong on the morning of the demo.


def _request(
    method: str,
    url: str,
    *,
    body: bytes | None = None,
    content_type: str | None = None,
    timeout: float = 60.0,
) -> tuple[int, bytes, str]:
    request = urllib.request.Request(url, data=body, method=method)  # noqa: S310 # a localhost URL the operator passed in
    if content_type:
        request.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 # as above
            return response.status, response.read(), response.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), exc.headers.get("Content-Type", "")
    except urllib.error.URLError as exc:
        msg = f"{method} {url} could not connect: {exc.reason}"
        raise RehearsalError(msg) from exc


def _json_request(method: str, url: str, **kwargs: Any) -> Any:
    status, payload, _ = _request(method, url, **kwargs)
    if status >= 400:
        msg = f"{method} {url} returned {status}: {payload[:400].decode('utf-8', 'replace')}"
        raise RehearsalError(msg)
    return json.loads(payload) if payload else None


def _multipart(path: Path) -> tuple[bytes, str]:
    """A minimal multipart/form-data body for one file field named ``file``."""
    boundary = f"----rehearsal{uuid.uuid4().hex}"
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{path.name}"\r\n'
        f"Content-Type: application/vnd.tcpdump.pcap\r\n\r\n"
    ).encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    return head + path.read_bytes() + tail, f"multipart/form-data; boundary={boundary}"


# ---------------------------------------------------------------------------
# The demo
# ---------------------------------------------------------------------------


@dataclass
class Step:
    name: str
    seconds: float
    detail: str = ""


@dataclass
class Run:
    index: int
    steps: list[Step] = field(default_factory=list)
    total_s: float = 0.0
    error: str | None = None

    @property
    def clean(self) -> bool:
        return self.error is None


class Rehearsal:
    def __init__(self, base_url: str, demo_dir: Path) -> None:
        self.base = base_url.rstrip("/")
        self.demo_dir = demo_dir

    # -- the pieces the sequence is built from -----------------------------

    def analyse(self, name: str) -> dict[str, Any]:
        """Upload one demo capture, run it, and return its assessment."""
        pcap = self.demo_dir / name / "capture.pcap"
        if not pcap.is_file():
            msg = (
                f"{pcap} is missing. Generate the demo captures first:\n"
                f"  cd backend && uv run python -m testbed.demo_captures ../dataset/demo"
            )
            raise RehearsalError(msg)

        body, content_type = _multipart(pcap)
        capture = _json_request(
            "POST", f"{self.base}/captures", body=body, content_type=content_type, timeout=300
        )
        accepted = _json_request("POST", f"{self.base}/captures/{capture['id']}/analyze")

        run_id = accepted["runId"]
        deadline = time.monotonic() + ANALYSIS_TIMEOUT_S
        while time.monotonic() < deadline:
            run = _json_request("GET", f"{self.base}/runs/{run_id}")
            if run["status"] == "failed":
                msg = f"{name}: analysis failed: {run.get('error')}"
                raise RehearsalError(msg)
            if run["status"] == "succeeded" and run.get("assessmentId"):
                return _json_request("GET", f"{self.base}/assessments/{run['assessmentId']}")
            time.sleep(POLL_INTERVAL_S)
        msg = f"{name}: analysis did not finish within {ANALYSIS_TIMEOUT_S:.0f}s"
        raise RehearsalError(msg)

    @staticmethod
    def _traffic_class(assessment: dict[str, Any]) -> tuple[list[str], float | None, int | None]:
        """ML-1's reading of the inner traffic, which is the demo's step 2.

        Read off ``metadata_exposure`` rather than the SA: PRD section 4.1
        makes the classifier's own confidence the leakage measurement, so the
        number the demo says out loud is this one and not a per-SA attribute.
        Note the document is served as stored, in snake_case -- only the
        Pydantic response models are camelCased at the boundary.
        """
        exposure = assessment.get("metadata_exposure") or {}
        return (
            list(exposure.get("identified_classes") or []),
            exposure.get("mean_classifier_confidence"),
            exposure.get("score"),
        )

    # -- the sequence ------------------------------------------------------

    def run_once(self, index: int) -> Run:
        run = Run(index=index)
        started = time.monotonic()

        def step(name: str) -> float:
            mark = time.monotonic()
            run.steps.append(Step(name, 0.0))
            return mark

        try:
            # 1. Tunnel A: the score, the findings, the threat matrix.
            mark = step("1. load tunnel A (weak)")
            weak = self.analyse(TUNNEL_A)
            weak_score = weak["score"]["total"]
            weak_findings = weak.get("findings") or []
            critical = [f for f in weak_findings if f.get("severity") == "critical"]
            if not weak_findings:
                msg = "tunnel A produced no findings: the demo has nothing to show"
                raise RehearsalError(msg)
            if not weak.get("threat_matrix"):
                msg = "tunnel A produced no threat matrix (PRD section 16 step 1)"
                raise RehearsalError(msg)
            run.steps[-1] = Step(
                run.steps[-1].name,
                time.monotonic() - mark,
                f"score {weak_score}, {len(weak_findings)} findings ({len(critical)} critical)",
            )

            # 2. The metadata-exposure point.
            mark = step("2. traffic classifier on tunnel A")
            classes, confidence, exposure_score = self._traffic_class(weak)
            if not classes:
                msg = (
                    "the traffic classifier identified no inner traffic class for "
                    "tunnel A, so the demo's metadata-exposure point (PRD section "
                    "16 step 2) has nothing to show. On the offline stack this is "
                    "usually MODEL_DIR: check that the backend image carries "
                    "/app/models, that libgomp1 is installed so LightGBM can "
                    "import, and that JobRunner is passing Settings.model_dir "
                    "through. See MT-26"
                )
                raise RehearsalError(msg)
            run.steps[-1] = Step(
                run.steps[-1].name,
                time.monotonic() - mark,
                f"{'/'.join(classes)} at confidence "
                f"{confidence if confidence is not None else 'n/a'}, "
                f"exposure {exposure_score}",
            )

            # 3. Tunnel B: the contrast.
            mark = step("3. load tunnel B (hardened)")
            hardened = self.analyse(TUNNEL_B)
            hardened_score = hardened["score"]["total"]
            hardened_findings = hardened.get("findings") or []
            if hardened_score <= weak_score:
                msg = (
                    f"the hardened tunnel did not score better than the weak one "
                    f"({hardened_score} vs {weak_score}): the demo's whole "
                    f"argument is this contrast"
                )
                raise RehearsalError(msg)
            if len(hardened_findings) >= len(weak_findings):
                msg = (
                    f"the hardened tunnel's findings list is not shorter "
                    f"({len(hardened_findings)} vs {len(weak_findings)})"
                )
                raise RehearsalError(msg)
            run.steps[-1] = Step(
                run.steps[-1].name,
                time.monotonic() - mark,
                f"score {hardened_score} (+{hardened_score - weak_score}), "
                f"{len(hardened_findings)} findings",
            )

            # 3b. The comparison view's data (step 7.12), which the demo opens.
            mark = step("3b. comparison A vs B")
            # `assessment_id`, not `id`: GET /assessments/{id} serves the
            # stored document as-is, and the document is snake_case. Only the
            # Pydantic response models are camelCased at the API boundary.
            comparison = _json_request(
                "GET",
                f"{self.base}/assessments/compare"
                f"?a={weak['assessment_id']}&b={hardened['assessment_id']}",
            )
            if not comparison["findingsOnlyInA"]:
                msg = "the comparison shows nothing present in A and absent in B"
                raise RehearsalError(msg)
            run.steps[-1] = Step(
                run.steps[-1].name,
                time.monotonic() - mark,
                f"delta {comparison['scoreDelta']}, "
                f"{len(comparison['findingsOnlyInA'])} findings only in A",
            )

            # 4. The executive report for tunnel A.
            mark = step("4. executive report for tunnel A")
            status_code, payload, content_type = _request(
                "GET",
                f"{self.base}/assessments/{weak['assessment_id']}/report?format=executive",
                timeout=120,
            )
            if status_code != 200:
                msg = f"the executive report returned {status_code}"
                raise RehearsalError(msg)
            if not payload.startswith(b"%PDF"):
                msg = f"the executive report is not a PDF (content-type {content_type!r})"
                raise RehearsalError(msg)
            run.steps[-1] = Step(
                run.steps[-1].name,
                time.monotonic() - mark,
                f"{len(payload) / 1024:.0f} KB PDF",
            )

        except RehearsalError as exc:
            run.error = str(exc)

        run.total_s = time.monotonic() - started
        return run


def _print_run(run: Run) -> None:
    verdict = "clean" if run.clean else "FAILED"
    print(f"\n--- run {run.index}: {run.total_s:6.1f}s  {verdict}")
    for step in run.steps:
        print(f"      {step.seconds:6.1f}s  {step.name:<34} {step.detail}")
    if run.error:
        print(f"      error: {run.error}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--base-url",
        default="http://localhost:3000/api",
        help="the prefix the resource paths hang off. The frontend's proxy "
        "route rewrites /api/<path> to the backend's /api/v1/<path>, so "
        "through the offline stack that prefix is /api with no version in "
        "it; against a backend started directly it is /api/v1.",
    )
    parser.add_argument("--runs", type=int, default=3, help="consecutive runs required")
    parser.add_argument("--demo-dir", type=Path, default=DEMO_DIR)
    args = parser.parse_args(argv)

    print(f"rehearsing against {args.base_url}, {args.runs} runs, target {TARGET_S:.0f}s")

    runs = [Rehearsal(args.base_url, args.demo_dir).run_once(i) for i in range(1, args.runs + 1)]
    for run in runs:
        _print_run(run)

    clean = [r for r in runs if r.clean]
    print(f"\n{len(clean)}/{len(runs)} clean")
    if clean:
        times = [r.total_s for r in clean]
        print(
            f"clean-run time: min {min(times):.1f}s  "
            f"median {statistics.median(times):.1f}s  max {max(times):.1f}s  "
            f"(target {TARGET_S:.0f}s)"
        )
        within = [t for t in times if t <= TARGET_S]
        print(f"{len(within)}/{len(times)} clean runs inside the two-minute target")

    if len(clean) != len(runs):
        print("\nstep 11.6 is NOT satisfied: a run was not clean.", file=sys.stderr)
        return 1
    print("\nstep 11.6: three consecutive clean runs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
