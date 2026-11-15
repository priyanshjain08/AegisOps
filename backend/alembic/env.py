from alembic import context
from app.core.config import settings
from app.core.db import Base, engine
import app.models  # noqa: register tables

def run():
    with engine.connect() as conn:
        context.configure(connection=conn, target_metadata=Base.metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()
run()
