"""Report download endpoints. Step 10.4.

``GET /assessments/{id}/report?format=executive|technical`` streaming
``application/pdf``. Rendering happens from the stored document alone, so a
report is byte-reproducible from an assessment years later without the
capture, the models, or the policy file that produced it.
"""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Query, Request, Response

from analyzer.api.deps import SessionDep
from analyzer.api.errors import NotFoundError
from analyzer.core.schema import Assessment as AssessmentDocument
from analyzer.db import models
from analyzer.report.render import render_html, render_pdf

router = APIRouter(prefix="/assessments", tags=["reports"])


@router.get("/{assessment_id}/report")
async def get_report(
    request: Request,
    session: SessionDep,
    assessment_id: UUID,
    # The query parameter is `format` because LLD section 9 specifies that
    # wire name; the Python parameter is renamed to avoid shadowing the
    # builtin, and the alias keeps the two independent.
    report_format: Annotated[
        Literal["executive", "technical"], Query(alias="format")
    ] = "executive",
    inline: Annotated[bool, Query(description="Render HTML instead of PDF")] = False,
) -> Response:
    row = await session.get(models.Assessment, assessment_id)
    if row is None:
        raise NotFoundError("assessment", assessment_id)

    document = AssessmentDocument.model_validate(row.document)
    rule_count = len(request.app.state.assessment_engine.policy.rules)

    if inline:
        # Useful when iterating on a template: the PDF renderer is the slow
        # part and the HTML is what actually changed.
        return Response(
            render_html(document, report_format, rule_count=rule_count), media_type="text/html"
        )

    pdf = render_pdf(document, report_format, rule_count=rule_count)
    filename = f"ipsec-{report_format}-{assessment_id}.pdf"
    return Response(
        pdf,
        media_type="application/pdf",
        headers={"content-disposition": f'attachment; filename="{filename}"'},
    )
