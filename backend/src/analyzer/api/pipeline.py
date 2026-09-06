"""Pipeline orchestration: ingest -> Track A -> Track B -> assess -> persist.

Step 6.5, with Track B wired in at step 9.11. Track B's deterministic analyses
run for real; its model-backed ones report UNAVAILABLE with their reason,
because the dataset they would train on (Phase 8) needs Docker and does not
exist. The stage runs either way, so the stage list, the progress fractions and
the SSE event sequence are already what the finished pipeline will emit.

Persistence writes the assessment document *and* its denormalised ``findings``
and ``security_associations`` rows in one transaction (LLD section 4.3): the
document is the immutable artefact, the rows exist so the dashboard can filter
and sort without JSON path queries.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from analyzer.assess.engine import AssessmentEngine
from analyzer.core.enums import RunStage
from analyzer.core.ids import new_id
from analyzer.core.schema import Assessment as AssessmentDocument
from analyzer.core.schema import SecurityAssociation
from analyzer.db import models
from analyzer.ingest.flow import SAPair, assemble_flows
from analyzer.ingest.quality import compute_quality
from analyzer.ingest.reader import read_packets
from analyzer.track_a.correlate import assemble_security_association, correlate_negotiation
from analyzer.track_a.ike_parser import (
    ExchangeSizes,
    TrackAError,
    build_negotiations,
    exchange_sizes,
    parse_isakmp_json,
    run_tshark,
)
from analyzer.track_b.service import InferenceService

log = logging.getLogger(__name__)

ProgressCallback = Callable[[RunStage, float, str], None]

STAGE_PROGRESS: dict[RunStage, float] = {
    RunStage.INGEST: 0.25,
    RunStage.TRACK_A: 0.55,
    RunStage.TRACK_B: 0.75,
    RunStage.ASSESS: 0.90,
    RunStage.REPORT: 1.0,
}
"""Fraction complete *after* each stage finishes. Fixed rather than measured:
NFR-1 budgets 60 seconds end to end, and a progress bar that is honest about
its own imprecision beats one that stalls at 90% while a model loads."""


@dataclass(frozen=True, slots=True)
class PipelineResult:
    assessment: AssessmentDocument
    assessment_row_id: object


def _noop(stage: RunStage, progress: float, message: str) -> None:
    del stage, progress, message


def _pfs_sizes(sizes: list[ExchangeSizes], pair: SAPair) -> dict[str, tuple[int, ...]]:
    """The exchange sizes belonging to this SA's endpoints, for step 9.4.

    Matched on the outer addresses, the same correlation Track A uses (LLD
    section 6.2) and for the same reason: a Child SA's own SPI is negotiated
    inside an encrypted exchange, so there is no identifier shared between the
    ESP flow and the IKE exchanges that rekeyed it. A capture of two tunnels
    between different endpoint pairs keeps their series apart; one capture of
    two tunnels between the *same* pair would merge them, which is a real
    limitation and the reason PFS stays INFERRED rather than OBSERVED.

    Empty tuples when nothing matches, which ``infer_pfs`` reports as
    UNAVAILABLE with the reason rather than as an absence of PFS.
    """
    key = pair.forward.key
    for entry in sizes:
        if entry.matches(key.src, key.dst):
            return {"create_child_sizes": entry.create_child, "baseline_sizes": entry.baseline}
    return {"create_child_sizes": (), "baseline_sizes": ()}


def analyse_capture(
    pcap_path: Path,
    engine: AssessmentEngine,
    *,
    capture_id: object,
    engine_version: str,
    tshark_bin: str = "tshark",
    model_dir: Path | None = None,
    generated_at: datetime | None = None,
    on_progress: ProgressCallback | None = None,
) -> AssessmentDocument:
    """Run the analysis stages over one capture. CPU-bound and synchronous.

    Kept free of database and HTTP concerns so step 6.6 can hand it to a
    ``ProcessPoolExecutor`` without dragging a session across a process
    boundary.
    """
    progress = on_progress or _noop

    # --- ingest (Phase 3) ---------------------------------------------------
    result = read_packets(pcap_path)
    sa_pairs = assemble_flows(result.packets)
    quality = compute_quality(result, sa_pairs)
    progress(
        RunStage.INGEST, STAGE_PROGRESS[RunStage.INGEST], f"read {len(result.packets)} packets"
    )

    # --- Track A (Phase 4) --------------------------------------------------
    security_associations: list[SecurityAssociation] = []
    sizes: list[ExchangeSizes] = []
    try:
        messages = parse_isakmp_json(run_tshark(pcap_path, tshark_bin=tshark_bin))
        negotiations = build_negotiations(messages)
        # Step 9.4's input, off the same parsed messages: the CREATE_CHILD_SA
        # and INFORMATIONAL sizes PFS inference measures its delta between.
        sizes = exchange_sizes(messages)
    except TrackAError as exc:
        # A capture with no IKE, or no tshark on this host, is a degraded
        # analysis rather than a failed one: every IKE-derived attribute
        # becomes UNAVAILABLE with a reason and Track B still has work to do.
        log.warning("Track A unavailable for %s: %s", pcap_path, exc)
        negotiations = []
    for pair in sa_pairs:
        security_associations.append(
            assemble_security_association(pair, correlate_negotiation(pair.forward, negotiations))
        )
    progress(
        RunStage.TRACK_A,
        STAGE_PROGRESS[RunStage.TRACK_A],
        f"parsed {len(negotiations)} IKE negotiations",
    )

    # --- Track B (Phase 9) --------------------------------------------------
    # The deterministic analyses (cipher-family sieve, sequence and rekey
    # behaviour, PFS) always run. The model-backed ones -- traffic class and
    # operating mode -- run when `model_dir` holds trained artefacts and report
    # UNAVAILABLE with their reason when it does not. Both are supported states:
    # a deployment shipped the code without the artefacts still produces a
    # complete assessment, honest about what it could not determine.
    service = InferenceService(model_dir)
    security_associations = [
        service.apply(
            sa,
            service.analyse(
                pair,
                quality,
                dh_group=sa.dh_group.value,
                **_pfs_sizes(sizes, pair),
            ),
        )
        for sa, pair in zip(security_associations, sa_pairs, strict=True)
    ]
    progress(
        RunStage.TRACK_B,
        STAGE_PROGRESS[RunStage.TRACK_B],
        f"inference over {len(sa_pairs)} SA pairs",
    )

    # --- assess (Phase 5) ---------------------------------------------------
    document = engine.evaluate(
        security_associations,
        quality,
        assessment_id=new_id(),
        capture_id=capture_id,  # type: ignore[arg-type] # a UUIDv7 from the caller's row
        generated_at=generated_at or datetime.now(tz=UTC),
        engine_version=engine_version,
    )
    progress(
        RunStage.ASSESS,
        STAGE_PROGRESS[RunStage.ASSESS],
        f"{len(document.findings)} findings, score {document.score.total}",
    )
    return document


def analyse_capture_json(
    pcap_path: Path,
    engine: AssessmentEngine,
    *,
    capture_id: object,
    engine_version: str,
    tshark_bin: str = "tshark",
    model_dir: Path | None = None,
) -> str:
    """``analyse_capture``, returning JSON rather than the model.

    This exists for the ``ProcessPoolExecutor`` path and is not a convenience.
    ``Attribute[T]`` is a *parametrised* generic Pydantic model, and a
    parametrised generic has no importable module-level name -- so
    ``Attribute[IkeVersion]`` cannot be pickled, and an ``Assessment`` full of
    them cannot cross a process boundary at all. JSON can, it is the form the
    document is stored in anyway, and the parent re-validates it back into the
    model on arrival.
    """
    document = analyse_capture(
        pcap_path,
        engine,
        capture_id=capture_id,
        engine_version=engine_version,
        tshark_bin=tshark_bin,
        model_dir=model_dir,
    )
    return document.model_dump_json()


async def persist_assessment(
    session: AsyncSession, document: AssessmentDocument, *, run_id: object
) -> models.Assessment:
    """Write the document and its queryable rows in one transaction."""
    row = models.Assessment(
        id=document.assessment_id,
        run_id=run_id,
        capture_id=document.capture_id,
        schema_version=document.schema_version,
        score_total=document.score.total,
        rating=document.score.rating,
        exposure_score=document.metadata_exposure.score,
        document=document.model_dump(mode="json"),
        created_at=document.generated_at,
    )
    session.add(row)

    for finding in document.findings:
        session.add(
            models.Finding(
                id=new_id(),
                assessment_id=row.id,
                finding_key=finding.id,
                severity=finding.severity,
                category=finding.category,
                penalty=finding.penalty,
                sa_spi=finding.sa_spi,
                detail=finding.model_dump(mode="json"),
            )
        )

    for sa in document.security_associations:
        session.add(
            models.SecurityAssociationRow(
                id=new_id(),
                assessment_id=row.id,
                spi_initiator=sa.spi_initiator,
                src_addr=str(sa.src),
                dst_addr=str(sa.dst),
                packet_count=sa.packet_count,
                byte_count=sa.byte_count,
                detail=sa.model_dump(mode="json"),
            )
        )

    await session.flush()
    return row
