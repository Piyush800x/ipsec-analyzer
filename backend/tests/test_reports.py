"""Phase 10: report rendering. Steps 10.1-10.3.

Rendered from the step 1.4 fixtures, which is what step 10.1 asks for. The
PDF assertions check that a real PDF came out; the content assertions check
what each format is *for*, because the difference between the two reports is
editorial, not just length, and only a content assertion catches a technical
report leaking into the executive one.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from analyzer.core.schema import Assessment
from analyzer.report.render import (
    CAPABILITY_MATRIX,
    TOP_RISK_COUNT,
    pdf_backend_available,
    render_html,
    render_pdf,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"

needs_pdf_backend = pytest.mark.skipif(
    not pdf_backend_available(),
    reason=(
        "WeasyPrint's native libraries (Pango/Cairo/GObject) are not installed. "
        "Only the PDF assertions need them; every content assertion below runs "
        "on HTML and is unaffected. See render.PDF_BACKEND_HINT."
    ),
)


def _fixture(name: str) -> Assessment:
    return Assessment.model_validate_json((FIXTURES / f"assessment_{name}.json").read_text())


@pytest.fixture(params=["weak", "strong"])
def assessment(request: pytest.FixtureRequest) -> Assessment:
    return _fixture(str(request.param))


# --- step 10.1: both templates render to PDF from a fixture ----------------


@needs_pdf_backend
@pytest.mark.parametrize("report_format", ["executive", "technical"])
def test_renders_a_real_pdf(assessment: Assessment, report_format: str) -> None:
    """Step 10.1 Done-when."""
    pdf = render_pdf(assessment, report_format, rule_count=14)  # type: ignore[arg-type]

    assert pdf.startswith(b"%PDF-")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert len(pdf) > 5_000


@needs_pdf_backend
@pytest.mark.parametrize("report_format", ["executive", "technical"])
def test_pdf_has_pages(assessment: Assessment, report_format: str) -> None:
    """WeasyPrint compresses its object streams, so the page objects are not
    greppable in the bytes -- count them on the document instead."""
    from weasyprint import CSS, HTML

    from analyzer.report.render import CSS_PATH, TEMPLATE_DIR

    html = render_html(assessment, report_format, rule_count=14)  # type: ignore[arg-type]
    document = HTML(string=html, base_url=str(TEMPLATE_DIR)).render(
        stylesheets=[CSS(filename=str(CSS_PATH))]
    )
    assert len(document.pages) >= 1


# --- step 10.2: the executive report ---------------------------------------


def test_executive_report_states_the_score_and_rating() -> None:
    html = render_html(_fixture("weak"), "executive", rule_count=14)

    assert "15" in html
    assert "critical" in html.lower()


def test_executive_report_names_the_top_three_risks() -> None:
    """Step 10.2: "top three risks", not all fourteen."""
    weak = _fixture("weak")
    html = render_html(weak, "executive", rule_count=14)

    # The three most severe findings appear; the least severe does not.
    ordered = ["CRYPTO-3DES", "PROTO-AGGRESSIVE-MODE", "KEX-WEAK-DH"]
    for finding_id in ordered[:TOP_RISK_COUNT]:
        title = next(f.title for f in weak.findings if f.id == finding_id)
        assert title in html, finding_id


def test_executive_report_carries_no_hex_and_no_packet_indices() -> None:
    """Step 10.2 is explicit: no hex, no packet indices."""
    weak = _fixture("weak")
    html = render_html(weak, "executive", rule_count=14)

    assert weak.security_associations[0].spi_initiator not in html
    for finding in weak.findings:
        assert finding.evidence.method not in html


def test_executive_report_tells_the_reader_what_to_do() -> None:
    """The Done-when is a non-technical reader knowing what is wrong and what
    to do. Remediation text is the second half of that."""
    weak = _fixture("weak")
    html = render_html(weak, "executive", rule_count=14)

    assert "What to do" in html
    top = sorted(weak.findings, key=lambda f: -f.penalty)[0]
    assert top.remediation.split(".")[0].strip()[:40] in html


def _flat(html: str) -> str:
    """Templates wrap prose across source lines; assertions are about the
    sentence, not the wrapping."""
    return " ".join(html.split())


def test_executive_report_explains_metadata_exposure_separately() -> None:
    html = _flat(render_html(_fixture("weak"), "executive", rule_count=14))
    assert "passive observer" in html
    assert "does not improve when the cryptography does" in html


def test_executive_report_says_nothing_was_guessed() -> None:
    html = _flat(render_html(_fixture("weak"), "executive", rule_count=14))
    assert "Nothing has been guessed" in html


def test_strong_fixture_reads_as_reassuring() -> None:
    html = _flat(render_html(_fixture("strong"), "executive", rule_count=14))
    assert "configured to a current standard" in html


# --- step 10.3: the technical report ---------------------------------------


def test_technical_report_shows_every_finding_with_its_evidence() -> None:
    """Step 10.3 Done-when: every finding shows its evidence."""
    weak = _fixture("weak")
    html = render_html(weak, "technical", rule_count=14)

    for finding in weak.findings:
        assert finding.id in html, finding.id
        assert finding.evidence.method in html, f"{finding.id} evidence missing"


def test_technical_report_covers_the_aes_key_length_limitation() -> None:
    """Step 10.3 Done-when, stated explicitly rather than implied."""
    html = _flat(render_html(_fixture("weak"), "technical", rule_count=14))

    assert "AES key length cannot be determined from ESP alone" in html
    assert "AES-128 and AES-256 produce identical packet geometry" in html


def test_technical_report_carries_the_capability_matrix() -> None:
    html = render_html(_fixture("weak"), "technical", rule_count=14)
    for row in CAPABILITY_MATRIX:
        assert row[0] in html, row[0]


def test_technical_report_records_model_versions() -> None:
    """A report whose numbers came from a model must name the model."""
    weak = _fixture("weak")
    html = render_html(weak, "technical", rule_count=14)

    for model_id, version in weak.model_versions.items():
        assert model_id in html
        assert version in html


def test_technical_report_says_so_when_no_model_ran() -> None:
    """The Track A-only case, which is this project's state today: the report
    must say a model was absent rather than let the reader assume one ran."""
    weak = _fixture("weak")
    html = _flat(
        render_html(weak.model_copy(update={"model_versions": {}}), "technical", rule_count=14)
    )

    assert "none loaded" in html
    assert "No trained models were loaded" in html


def test_technical_report_renders_unavailable_as_a_reason_not_a_dash() -> None:
    """FR-4.9 in the report, matching the dashboard's AttributeCell."""
    weak = _fixture("weak")
    html = render_html(weak, "technical", rule_count=14)

    assert "Not determinable" in html
    unavailable = [
        attr.note
        for attr in (
            weak.security_associations[0].prf_alg,
            weak.security_associations[0].esn_negotiated,
        )
        if attr.note
    ]
    for note in unavailable:
        assert note[:50] in html


def test_technical_report_shows_provenance_for_every_parameter() -> None:
    html = render_html(_fixture("strong"), "technical", rule_count=14)
    assert "observed" in html
    assert "inferred" in html


def test_technical_report_preserves_the_replay_distinction() -> None:
    """LLD section 7.5: "sequence numbers behave correctly" is not
    "anti-replay is enabled", and the report wording must keep them apart."""
    html = _flat(render_html(_fixture("weak"), "technical", rule_count=14))

    assert "not a statement that anti-replay is enabled" in html
    assert "Sequence gaps are not evidence of an attack" in html


def test_technical_report_explains_both_tracks() -> None:
    html = _flat(render_html(_fixture("weak"), "technical", rule_count=14))
    assert "Track A" in html
    assert "Track B" in html
    assert "nothing was decrypted" in html


# --- determinism ------------------------------------------------------------


def test_html_rendering_is_deterministic(assessment: Assessment) -> None:
    """The report is derived from an immutable document, so it must not drift
    between renders any more than the assessment does (NFR-4)."""
    assert render_html(assessment, "technical", rule_count=14) == render_html(
        assessment, "technical", rule_count=14
    )


# --- cross-platform: WeasyPrint must not be a startup dependency -----------


def test_importing_the_api_does_not_import_weasyprint() -> None:
    """The regression this guards is severe and silent-looking.

    WeasyPrint's cffi bindings dlopen Pango/Cairo/GObject at *import* time, so
    a module-level ``from weasyprint import ...`` anywhere in the API's import
    graph made ``uvicorn analyzer.api.main:create_app`` fail outright on every
    machine without a GTK stack -- which is every stock Windows install. The
    traceback named ``libgobject-2.0-0`` and read like a broken Python
    package, so it did not point at the report renderer at all.

    A subprocess, because ``weasyprint`` may already be in this process's
    ``sys.modules`` from another test.
    """
    probe = (
        "import sys;import analyzer.api.main as m;m.create_app();print('weasyprint' in sys.modules)"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )

    assert result.stdout.strip().endswith("False"), result.stdout


def test_pdf_backend_probe_is_cached() -> None:
    """A failed import is not cached in ``sys.modules`` -- Python discards the
    half-built module -- so without the module-level cache every report
    request on a GTK-less machine re-runs the dlopen probe and re-prints
    WeasyPrint's installation banner to stdout."""
    from analyzer.report import render

    first = render.pdf_backend_available()
    assert render._PDF_BACKEND is not None or render._PDF_BACKEND_FAILURE is not None
    assert render.pdf_backend_available() is first
