"""Shared FastAPI dependencies: the engine, sessions, settings and storage.

The engine and session factory live on ``app.state`` rather than in module
globals so tests can build an app against a throwaway SQLite file without
monkeypatching anything.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from analyzer.assess.engine import AssessmentEngine
from analyzer.core.config import Settings


def get_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_engine_state(request: Request) -> AssessmentEngine:
    engine: AssessmentEngine = request.app.state.assessment_engine
    return engine


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    factory: async_sessionmaker[AsyncSession] = request.app.state.session_factory
    async with factory() as session:
        try:
            yield session
            # A handler may have committed and closed early -- `start_analysis`
            # does, so its background job is not blocked behind this request's
            # write lock. Committing a session that is no longer in a
            # transaction raises, so check rather than assume.
            if session.in_transaction():
                await session.commit()
        except Exception:
            if session.in_transaction():
                await session.rollback()
            raise


def get_storage_dir(request: Request) -> Path:
    settings: Settings = request.app.state.settings
    path = Path(settings.storage_path)
    path.mkdir(parents=True, exist_ok=True)
    return path


SessionDep = Annotated[AsyncSession, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
StorageDep = Annotated[Path, Depends(get_storage_dir)]
EngineDep = Annotated[AssessmentEngine, Depends(get_engine_state)]
