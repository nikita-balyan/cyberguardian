#!/usr/bin/env python
"""
Database initialization script for CyberGuardian.
Creates all tables in the Supabase PostgreSQL database.
"""
import asyncio
import sys
from pathlib import Path

# Add the backend directory to the Python path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))

from app.db.session import async_engine, Base, async_init_db


async def main() -> None:
    """Initialize the database by creating all tables."""
    print("Initializing database connection to Supabase...")
    
    try:
        await async_init_db()
        print("✅ Database tables created successfully!")
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        sys.exit(1)
    finally:
        await async_engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())