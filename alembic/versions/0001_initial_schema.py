"""initial_schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-09-02

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'scan_runs',
        sa.Column('run_id', sa.String(length=128), primary_key=True),
        sa.Column('target_name', sa.String(length=255), nullable=False),
        sa.Column('mode', sa.String(length=64), nullable=False),
        sa.Column('start_time', sa.DateTime(), nullable=False),
        sa.Column('end_time', sa.DateTime(), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('total_urls', sa.Integer(), default=0),
        sa.Column('total_endpoints', sa.Integer(), default=0),
        sa.Column('total_findings', sa.Integer(), default=0),
        sa.Column('validated_findings', sa.Integer(), default=0),
        sa.Column('false_positives', sa.Integer(), default=0),
    )

    op.create_table(
        'findings',
        sa.Column('finding_id', sa.String(length=128), primary_key=True),
        sa.Column('run_id', sa.String(length=128), sa.ForeignKey('scan_runs.run_id'), nullable=False),
        sa.Column('target_host', sa.String(length=255), nullable=False),
        sa.Column('target_endpoint', sa.Text(), nullable=False),
        sa.Column('finding_category', sa.String(length=128), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('confidence', sa.Float(), default=0.0),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )

    op.create_table(
        'jobs',
        sa.Column('job_id', sa.String(length=128), primary_key=True),
        sa.Column('target_url', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('progress', sa.Integer(), default=0),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('jobs')
    op.drop_table('findings')
    op.drop_table('scan_runs')
