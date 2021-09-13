"""Added Password Field
exit
exit()


Revision ID: 188f7f49535b
Revises: f7a69a08fb39
Create Date: 2021-08-29 22:26:00.980568

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '188f7f49535b'
down_revision = 'f7a69a08fb39'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('password_hash', sa.String(length=120), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'password_hash')
    # ### end Alembic commands ###