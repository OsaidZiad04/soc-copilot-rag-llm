"""add threat analyses table

Revision ID: 002_threat_analyses
Revises: fee4cd54bd38
Create Date: 2026-03-27 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = '002_threat_analyses'
down_revision: Union[str, None] = 'fee4cd54bd38'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    op.create_table(
        'threat_analyses',
        sa.Column('analysis_id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('analysis_uuid', sa.UUID(), nullable=False),
        sa.Column('input_text', sa.Text(), nullable=False),
        sa.Column('input_type', sa.String(length=50), server_default='alert', nullable=True),
        sa.Column('title', sa.String(length=500), nullable=True),
        sa.Column('threat_type', sa.String(length=200), nullable=True),
        sa.Column('risk_level', sa.String(length=20), server_default='info', nullable=True),
        sa.Column('risk_score', sa.Float(), server_default='0.0', nullable=True),
        sa.Column('confidence', sa.Float(), server_default='0.0', nullable=True),
        sa.Column('analysis_result', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('mitre_techniques', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('iocs', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('detection_rules', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('investigation_id', sa.UUID(), nullable=True),
        sa.Column('analyst_feedback', sa.String(length=20), nullable=True),
        sa.Column('analyst_notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('analysis_id'),
        sa.UniqueConstraint('analysis_uuid')
    )

    op.create_index('ix_analysis_risk_level', 'threat_analyses', ['risk_level'], unique=False)
    op.create_index('ix_analysis_input_type', 'threat_analyses', ['input_type'], unique=False)
    op.create_index('ix_analysis_created_at', 'threat_analyses', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_analysis_created_at', table_name='threat_analyses')
    op.drop_index('ix_analysis_input_type', table_name='threat_analyses')
    op.drop_index('ix_analysis_risk_level', table_name='threat_analyses')
    op.drop_table('threat_analyses')
