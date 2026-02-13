"""Auto-create database tables on first run."""

import asyncio
from .db import DatabaseManager


async def run_migrations() -> None:
    """Initialize the database and create all tables."""
    db = DatabaseManager()
    await db.init_db()
    await db.close()


if __name__ == "__main__":
    asyncio.run(run_migrations())
