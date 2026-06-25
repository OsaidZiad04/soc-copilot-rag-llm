from logging.config import fileConfig
import os
import sys

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context


BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../"))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from models.db_schemes.minirag.schemes.minirag_base import SQLAlchemyBase
from models.db_schemes.minirag.schemes.project import Project  # noqa: F401
from models.db_schemes.minirag.schemes.asset import Asset  # noqa: F401
from models.db_schemes.minirag.schemes.datachunk import DataChunk  # noqa: F401
from models.db_schemes.minirag.schemes.threat_analysis import ThreatAnalysis  # noqa: F401


config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = SQLAlchemyBase.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
