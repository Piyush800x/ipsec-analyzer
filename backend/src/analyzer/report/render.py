"""Report rendering. Steps 10.1-10.3.

Jinja2 to HTML, then WeasyPrint to PDF where its native libraries are
installed and xhtml2pdf everywhere else (see ``render_pdf``). Both formats
render from an ``Assessment``
and nothing else -- no database, no network, no filesystem beyond the template
directory -- so a report is reproducible from its stored document alone, which
is what makes the immutable-artefact story in LLD section 4.3 worth anything.

The executive and technical reports are not the same content at two lengths.
The executive one leads every finding with its consequence and contains no hex
and no packet indices (step 10.2); the technical one carries the evidence,
the provenance of every parameter, and the limitations (step 10.3).
"""

from __future__ import annotations

import io
import logging
import re
import threading
from functools import cache
from pathlib import Path
from typing import Any, Final, Literal
from uuid import UUID

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from analyzer.core.enums import CATEGORY_CAPS, Provenance, Severity
from analyzer.core.schema import Assessment, Attribute, Finding, SecurityAssociation

log = logging.getLogger(__name__)

TEMPLATE_DIR: Final = Path(__file__).parent / "templates"
CSS_PATH: Final = TEMPLATE_DIR / "base.css"
PORTABLE_CSS_PATH: Final = TEMPLATE_DIR / "portable.css"

ReportFormat = Literal["executive", "technical"]


PdfEngine = Literal["weasyprint", "xhtml2pdf"]


class PdfRenderError(RuntimeError):
    """The PDF engine ran and reported that it could not produce a document."""


PORTABLE_ENGINE_NOTICE: Final = (
    "WeasyPrint's native libraries (Pango, Cairo, GObject) are not installed, so PDF reports "
    "are rendered with the portable xhtml2pdf engine. The content is identical; the "
    "typesetting is plainer. For WeasyPrint's layout: on Windows install the GTK3 runtime "
    "from https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases "
    "and open a new shell; on Debian/Ubuntu install libpango-1.0-0, libpangoft2-1.0-0 and "
    "libcairo2; on macOS run `brew install pango`."
)
"""Logged once, the first time a PDF falls back. An operator-facing note, not
an error: nothing the user asked for is missing."""

TOP_RISK_COUNT: Final = 3
"""Step 10.2: "top three risks". Three is a number an executive summary can
carry; a list of fourteen is a technical report wearing the wrong title."""

_SEVERITY_ORDER: Final[dict[Severity, int]] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 4,
}

PARAMETER_LABELS: Final[tuple[tuple[str, str], ...]] = (
    ("ike_version", "IKE version"),
    ("ike_exchange_mode", "Exchange mode"),
    ("encryption_alg", "Encryption algorithm"),
    ("encryption_keylen", "Key length (bits)"),
    ("integrity_alg", "Integrity algorithm"),
    ("prf_alg", "Pseudo-random function"),
    ("dh_group", "Diffie-Hellman group"),
    ("operating_mode", "Operating mode"),
    ("pfs_enabled", "Perfect Forward Secrecy"),
    ("auth_method", "Authentication method"),
    ("negotiated_lifetime_s", "Negotiated lifetime (s)"),
    ("observed_rekey_s", "Observed rekey interval (s)"),
    ("esn_negotiated", "Extended Sequence Numbers"),
    ("replay_sane", "Sequence numbers behave correctly"),
    ("nat_traversal", "NAT traversal"),
    ("downgrade_available", "Weaker proposal offered"),
)

CAPABILITY_MATRIX: Final[tuple[tuple[str, str, str], ...]] = (
    (
        "IKE version and exchange mode",
        "Track A — cleartext IKE header",
        "Certain when IKE was captured",
    ),
    ("Proposed and selected transforms", "Track A — SA payload", "Certain when IKE was captured"),
    ("Diffie-Hellman group", "Track A — SA payload", "Certain when IKE was captured"),
    ("SA lifetime", "Track A — IKEv1 attributes only", "IKEv2 does not negotiate one at all"),
    (
        "Authentication method",
        "Track A — IKEv1 attribute 3",
        "IKEv2 AUTH is encrypted; not determinable",
    ),
    (
        "Child SA cipher",
        "Inferred from the IKE SA's family",
        "The Child SA proposal is encrypted for both IKE versions",
    ),
    (
        "Cipher family from ESP alone",
        "Track B — packet-length congruence",
        "Needs ≥200 packets and ≥8 distinct lengths",
    ),
    ("AES key length from ESP alone", "—", "Not determinable by any means; see Limitations"),
    ("Operating mode", "Track B — encapsulation overhead", "Never observed, always inferred"),
    ("Inner traffic type", "Track B — flow statistics", "Calibrated confidence per prediction"),
    (
        "Sequence-number behaviour",
        "Track B — per-SPI analysis",
        "Measured; gaps are not attack evidence",
    ),
    ("Anti-replay window size", "—", "Never transmitted; not determinable"),
)
"""PRD section 7's capability matrix. The rows that say "not determinable" are
the point of including it: a reviewer's first question is what this method
cannot do, and answering it in the report beats being asked."""


def _render_value(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if hasattr(value, "value"):
        return str(value.value)
    return str(value)


def _parameter_rows(sa: SecurityAssociation) -> list[tuple[str, Attribute[Any]]]:
    return [(label, getattr(sa, field)) for field, label in PARAMETER_LABELS]


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "xml", "html.j2"]),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _quality_caveats(assessment: Assessment) -> list[str]:
    quality = assessment.capture_quality
    caveats = []
    if quality.truncated:
        caveats.append("The capture was truncated, so packet-geometry analysis could not run.")
    if not quality.has_ike:
        caveats.append(
            "No key-exchange negotiation was captured, so the cryptographic "
            "settings could not be read directly and were estimated where possible."
        )
    elif not quality.ike_complete:
        caveats.append(
            "The capture joined the key exchange mid-stream, so part of the "
            "negotiation was not observed."
        )
    if not quality.sufficient_for_lattice and quality.esp_sa_count:
        caveats.append(
            "The encrypted traffic carried too few distinct packet sizes to "
            "identify the cipher family from geometry alone."
        )
    return caveats


def top_risks(assessment: Assessment) -> list[Finding]:
    """The findings the executive report leads with: most severe first, then
    heaviest penalty, then rule key so ties render in a stable order."""
    findings = sorted(
        assessment.findings, key=lambda f: (_SEVERITY_ORDER[f.severity], -f.penalty, f.id)
    )
    return findings[:TOP_RISK_COUNT]


def _context(assessment: Assessment, rule_count: int) -> dict[str, Any]:
    unavailable = sum(
        1
        for sa in assessment.security_associations
        for _, attribute in _parameter_rows(sa)
        if attribute.provenance is Provenance.UNAVAILABLE
    )
    return {
        "a": assessment,
        "q": assessment.capture_quality,
        "generated_at": assessment.generated_at.strftime("%Y-%m-%d %H:%M UTC"),
        "top_risks": top_risks(assessment),
        "rule_count": rule_count,
        "unavailable_count": unavailable,
        "quality_caveats": _quality_caveats(assessment),
        "category_caps": CATEGORY_CAPS,
        "capability_matrix": CAPABILITY_MATRIX,
        "parameter_rows": _parameter_rows,
        "render_value": _render_value,
    }


def report_filename(report_format: ReportFormat, assessment_id: UUID) -> str:
    """The PDF's file name. Shared by the download endpoint and the emailed
    attachment, so the file an analyst receives is the file they would have
    downloaded, under the same name."""
    return f"ipsec-{report_format}-{assessment_id}.pdf"


def render_html(assessment: Assessment, report_format: ReportFormat, *, rule_count: int = 0) -> str:
    template = _environment().get_template(f"{report_format}.html.j2")
    return template.render(**_context(assessment, rule_count))


_RENDER_LOCK: Final = threading.Lock()
"""One PDF render at a time, process-wide. Downloads render on the event-loop
thread and emailed reports on a worker thread, so two can overlap, and neither
engine promises thread safety: WeasyPrint for the Pango/Cairo state beneath it,
xhtml2pdf for reportlab's module-level font registry. A render takes around a
second; serialising them costs nothing a user would notice."""

_WEASYPRINT: tuple[Any, Any] | None = None
_WEASYPRINT_FAILURE: Exception | None = None
"""Both outcomes of the probe are cached, deliberately.

``functools.cache`` would only memoise the success: it re-raises through to
the caller without storing the exception, so every request on a machine
without GTK would re-run the dlopen probe and re-print WeasyPrint's
multi-line installation banner to stdout. A *failed* import is not cached in
``sys.modules`` either -- Python drops the half-built module -- so the probe
genuinely does repeat unless something here remembers that it failed."""


def _weasyprint() -> tuple[Any, Any] | None:
    """WeasyPrint's ``(CSS, HTML)``, or ``None`` when it cannot load here.

    Imported on demand, never at module scope. WeasyPrint binds to Pango,
    Cairo and GObject through cffi at *import* time, so a missing GTK stack
    raises ``OSError`` from the import statement itself; at module scope that
    took down the entire API on every machine without those libraries, stock
    Windows above all. ``OSError`` is caught alongside ``ImportError`` because
    that is the shape it takes: the package imports cleanly, its bindings then
    fail to dlopen the shared library.
    """
    global _WEASYPRINT, _WEASYPRINT_FAILURE

    if _WEASYPRINT is not None or _WEASYPRINT_FAILURE is not None:
        return _WEASYPRINT

    try:
        from weasyprint import CSS, HTML
    except (ImportError, OSError) as exc:
        _WEASYPRINT_FAILURE = exc
        log.warning("%s (%s)", PORTABLE_ENGINE_NOTICE, exc)
        return None

    _WEASYPRINT = (CSS, HTML)
    return _WEASYPRINT


def pdf_engine() -> PdfEngine:
    """Which engine ``render_pdf`` uses on this machine."""
    return "weasyprint" if _weasyprint() is not None else "xhtml2pdf"


def render_pdf(
    assessment: Assessment, report_format: ReportFormat, *, rule_count: int = 0
) -> bytes:
    """Render to PDF bytes. Steps 10.1-10.3.

    WeasyPrint when its native libraries load, xhtml2pdf otherwise. There is
    no machine this cannot run on: WeasyPrint's libraries are a system install
    that stock Windows never has, and a report feature that works only after
    an operator installs GTK is one that silently does not work for most
    people who try it. Both engines render the same HTML from the same
    template, so the content is identical and only the typesetting differs.
    """
    html = render_html(assessment, report_format, rule_count=rule_count)
    weasyprint = _weasyprint()
    with _RENDER_LOCK:
        if weasyprint is None:
            return _render_portable(html)
        css, html_cls = weasyprint
        document = html_cls(string=html, base_url=str(TEMPLATE_DIR)).render(
            stylesheets=[css(filename=str(CSS_PATH))]
        )
        pdf: bytes = document.write_pdf()
    return pdf


# --- the portable engine ----------------------------------------------------

_VERA_FACES: Final = (
    ("Vera.ttf", "normal", "normal"),
    ("VeraBd.ttf", "bold", "normal"),
    ("VeraIt.ttf", "normal", "italic"),
    ("VeraBI.ttf", "bold", "italic"),
)
"""Bitstream Vera, from inside the reportlab wheel. DejaVu Sans, which the
WeasyPrint stylesheet names, is Vera extended, so the two engines' output is
typographically close. Shipping inside a wheel is the point: a system font
would put back the per-OS dependency this engine exists to remove."""

_PORTABLE_SUBSTITUTIONS: Final = {"→": "-&gt;"}
"""Characters the reports use that Vera has no glyph for. Without this they
print as blank boxes. The list was taken by scanning every non-ASCII
character in the templates, the policy and the report code against Vera's
character map; only the arrow is missing."""

_H1: Final = re.compile(r"<h1>(.*?)</h1>", re.DOTALL)


@cache
def _portable_stylesheet() -> str:
    import reportlab

    fonts = Path(reportlab.__file__).parent / "fonts"
    faces = "".join(
        f'@font-face {{ font-family: Vera; src: url("{(fonts / name).as_posix()}"); '
        f"font-weight: {weight}; font-style: {style}; }}\n"
        for name, weight, style in _VERA_FACES
    )
    return faces + PORTABLE_CSS_PATH.read_text(encoding="utf-8")


def _render_portable(html: str) -> bytes:
    """xhtml2pdf over the same HTML, with its own stylesheet and page furniture.

    The running header and footer are frames that xhtml2pdf fills from
    elements in the document, so they are added to the markup here rather
    than in the templates, which WeasyPrint also reads.
    """
    from xhtml2pdf import pisa

    for char, replacement in _PORTABLE_SUBSTITUTIONS.items():
        html = html.replace(char, replacement)
    title = match.group(1).strip() if (match := _H1.search(html)) else ""
    furniture = (
        f'<div id="pdf-header">{title}</div>'
        '<div id="pdf-footer">IPsec VPN Protocol Analyzer &#160;&#160; '
        "Page <pdf:pagenumber> of <pdf:pagecount></div>"
    )
    html = html.replace("</head>", f"<style>{_portable_stylesheet()}</style></head>", 1)
    html = html.replace("<body>", f"<body>{furniture}", 1)

    buffer = io.BytesIO()
    status = pisa.CreatePDF(html, dest=buffer, encoding="utf-8")
    if status.err:
        msg = f"xhtml2pdf reported {status.err} error(s) rendering the report"
        raise PdfRenderError(msg)
    return buffer.getvalue()
