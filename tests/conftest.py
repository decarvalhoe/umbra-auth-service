import pytest

from src import db
from src.main import create_app


@pytest.fixture()
def app():
    app = create_app({
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "TESTING": True,
    })

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()
