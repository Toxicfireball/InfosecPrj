"""empty message

Revision ID: bba335635d82
Revises: 
Create Date: 2022-08-08 14:52:31.723513

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'bba335635d82'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('pfpfilename', sa.String(length=85), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user', 'pfpfilename')
    # ### end Alembic commands ###
