"""Report rendering. Steps 10.1-10.3.

Jinja2 to HTML, WeasyPrint to PDF. Both formats render from an ``Assessment``
and nothing else -- no database, no network, no filesystem beyond the template
directory -- so a report is reproducible from its stored document alone, which
is what makes the immutable-artefact story in LLD section 4.3 worth anything.

The executive and technical reports are not the same content at two lengths.
The executive one leads every finding with its consequence and contains no hex
and no packet indices (step 10.2); the technical one carries the evidence,
the provenance of every parameter, and the limitations (step 10.3).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final, Literal

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from weasyprint import CSS, HTML

from analyzer.core.enums import CATEGORY_CAPS, Provenance, Severity
from analyzer.core.schema import Assessment, Attribute, SecurityAssociation

TEMPLATE_DIR: Final = Path(__file__).parent / "templates"
CSS_PATH: Final = TEMPLATE_DIR / "base.css"

ReportFormat = Literal["executive", "technical"]

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


def _context(assessment: Assessment, rule_count: int) -> dict[str, Any]:
    findings = sorted(
        assessment.findings, key=lambda f: (_SEVERITY_ORDER[f.severity], -f.penalty, f.id)
    )
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
        "top_risks": findings[:TOP_RISK_COUNT],
        "rule_count": rule_count,
        "unavailable_count": unavailable,
        "quality_caveats": _quality_caveats(assessment),
        "category_caps": CATEGORY_CAPS,
        "capability_matrix": CAPABILITY_MATRIX,
        "parameter_rows": _parameter_rows,
        "render_value": _render_value,
    }


def render_html(assessment: Assessment, report_format: ReportFormat, *, rule_count: int = 0) -> str:
    template = _environment().get_template(f"{report_format}.html.j2")
    return template.render(**_context(assessment, rule_count))


def render_pdf(
    assessment: Assessment, report_format: ReportFormat, *, rule_count: int = 0
) -> bytes:
    """Render to PDF bytes. Steps 10.1-10.3."""
    html = render_html(assessment, report_format, rule_count=rule_count)
    document = HTML(string=html, base_url=str(TEMPLATE_DIR)).render(
        stylesheets=[CSS(filename=str(CSS_PATH))]
    )
    pdf: bytes = document.write_pdf()
    return pdf
