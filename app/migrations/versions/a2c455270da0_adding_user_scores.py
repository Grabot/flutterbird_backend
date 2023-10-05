"""adding user scores

Revision ID: a2c455270da0
Revises: 74605c6ddf01
Create Date: 2023-09-28 20:36:26.932584

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a2c455270da0"
down_revision: Union[str, None] = "74605c6ddf01"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column("User", sa.Column("best_score", sa.Integer(), nullable=False))
    op.add_column("User", sa.Column("total_flutters", sa.Integer(), nullable=False))
    op.add_column("User", sa.Column("total_pipes_cleared", sa.Integer(), nullable=False))
    op.add_column("User", sa.Column("total_games", sa.Integer(), nullable=False))
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column("User", "total_games")
    op.drop_column("User", "total_pipes_cleared")
    op.drop_column("User", "total_flutters")
    op.drop_column("User", "best_score")
    # ### end Alembic commands ###