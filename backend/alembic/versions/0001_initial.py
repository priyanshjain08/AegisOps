"""Initial schema (created from the SQLAlchemy models at this revision).

NOTE: this baseline uses metadata.create_all. It was NOT generated or run against a live
PostgreSQL in the authoring environment. Generate subsequent revisions with
`alembic revision --autogenerate -m "..."` and review them.

Revision ID: 0001
Revises:
"""
from alembic import op
from app.core.db import Base
import app.models  # noqa

revision = "0001"
down_revision = None

def upgrade():
    Base.metadata.create_all(bind=op.get_bind())

def downgrade():
    Base.metadata.drop_all(bind=op.get_bind())
