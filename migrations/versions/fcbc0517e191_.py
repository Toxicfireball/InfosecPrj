"""empty message

Revision ID: fcbc0517e191
Revises: 
Create Date: 2022-12-14 22:24:00.685357

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'fcbc0517e191'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('Post', sa.Column('data', sa.LargeBinary(), nullable=False))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('Post', 'data')
    # ### end Alembic commands ###