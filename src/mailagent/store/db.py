from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from mailagent.config import get_settings

engine = create_async_engine(get_settings().database_url)
session_factory = async_sessionmaker(engine, expire_on_commit=False)


async def get_session():
    async with session_factory() as session:
        yield session


__all__ = ["AsyncSession", "engine", "get_session", "session_factory"]
