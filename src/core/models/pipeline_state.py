"""Pipeline state ORM models for database persistence."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """SQLAlchemy declarative base for pipeline state models."""
