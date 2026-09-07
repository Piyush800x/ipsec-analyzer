"""FastAPI app factory and router mounting (LLD 9). Step 6.1.

Everything mutable lives on ``app.state`` and is built by ``create_app``, so a
test can stand the whole API up against a throwaway SQLite file and an
in-process job runner without patching a single module global.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import sqlalchemy as sa
from fastapi import APIRouter, FastAPI
from sqlalchemy.ext.asyncio import AsyncEngine

from analyzer import __version__
from analyzer.api.deps import SessionDep
from analyzer.api.errors import install_error_handlers
from analyzer.api.jobs import JobRunner
from analyzer.api.routes import assessments, captures, reports, runs
from analyzer.api.schemas import HealthResponse
from analyzer.assess.engine import AssessmentEngine
from analyzer.assess.policy import load_policy
from analyzer.core.config import Settings, get_settings
from analyzer.db.session import check_connection, create_db_engine, create_session_factory

log = logging.getLogger(__name__)

API_PREFIX = "/api/v1"

health_router = APIRouter(tags=["health"])


@health_router.get("/health", response_model=HealthResponse)
async def health(session: SessionDep) -> HealthResponse:
    """Liveness plus database reachability.

    Reports ``degraded`` with a 200 rather than failing the request: a
    dashboard needs to be able to say "the database is unreachable" to a human,
    and a 503 here reads to a load balancer as "take this instance out", which
    is the wrong response to a database that is merely cold (Neon scales to
    zero).
    """
    try:
        await session.execute(sa.text("SELECT 1"))
        database = "up"
    except Exception:
        log.warning("health check could not reach the database", exc_info=True)
        database = "down"
    return HealthResponse(
        status="ok" if database == "up" else "degraded",
        database=database,
        version=__version__,
    )


def create_app(
    *,
    settings: Settings | None = None,
    db_engine: AsyncEngine | None = None,
    use_process_pool: bool = True,
) -> FastAPI:
    resolved = settings or get_settings()
    engine = db_engine or create_db_engine(resolved.database_url)
    session_factory = create_session_factory(engine)
    assessment_engine = AssessmentEngine(load_policy(resolved.policy_path))

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.job_runner = JobRunner(
            session_factory,
            assessment_engine,
            max_concurrent=resolved.max_concurrent_analyses,
            engine_version=__version__,
            model_dir=resolved.model_dir,
            use_process_pool=use_process_pool,
        )
        reachable = await check_connection(engine)
        if not reachable:
            # Not fatal: Neon scales to zero and the first query wakes it. The
            # health endpoint reports the truth either way.
            log.warning("database was not reachable at startup")
        try:
            yield
        finally:
            await app.state.job_runner.aclose()
            if db_engine is None:
                await engine.dispose()

    app = FastAPI(
        title="IPsec VPN Protocol Analyzer",
        version=__version__,
        summary="Determines the security posture of an IPsec deployment from captured traffic",
        lifespan=lifespan,
    )

    app.state.settings = resolved
    app.state.db_engine = engine
    app.state.session_factory = session_factory
    app.state.assessment_engine = assessment_engine
    app.state.engine_version = __version__

    install_error_handlers(app)

    api = APIRouter(prefix=API_PREFIX)
    api.include_router(health_router)
    api.include_router(captures.router)
    api.include_router(runs.router)
    api.include_router(assessments.router)
    api.include_router(reports.router)
    app.include_router(api)

    return app
