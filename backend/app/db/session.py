import os
from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "")


def _normalize_db_url(url: str) -> str:
    """
    Normalize the database URL for asyncpg.
    - Convert postgresql:// to postgresql+asyncpg://
    - Convert postgres:// to postgresql+asyncpg://
    """
    if not url:
        return url

    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+asyncpg://", 1)

    return url


ASYNC_DATABASE_URL = _normalize_db_url(DATABASE_URL)

# Only create async engine if using PostgreSQL (asyncpg driver)
# SQLite doesn't have async driver support
if ASYNC_DATABASE_URL.startswith("postgresql+asyncpg://"):
    async_engine = create_async_engine(
        ASYNC_DATABASE_URL,
        echo=False,
        pool_pre_ping=True,
    )

    async_session_maker = async_sessionmaker(
        async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
else:
    async_engine = None
    async_session_maker = None


class Base(DeclarativeBase):
    pass


async def get_async_session() -> AsyncSession:
    if async_session_maker is None:
        raise RuntimeError("Async database session not available (not using PostgreSQL)")
    async with async_session_maker() as session:
        yield session


async def async_init_db() -> None:
    if async_engine is None:
        return
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    if async_engine is None:
        return
    await async_engine.dispose()