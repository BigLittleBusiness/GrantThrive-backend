# src/utils/database.py
"""
Database utility functions for session management.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Example connection string, replace with your actual database URI
DATABASE_URI = "sqlite:///example.db"
engine = create_engine(DATABASE_URI)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db_session():
    """
    Returns a new SQLAlchemy session.
    """
    return SessionLocal()
