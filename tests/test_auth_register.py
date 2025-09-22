from __future__ import annotations

from http import HTTPStatus

from src import db
from src.models import RefreshToken, User


def test_register_success(app):
    client = app.test_client()

    response = client.post(
        "/auth/register",
        json={"email": "NewUser@example.com", "password": "StrongPass123"},
    )

    assert response.status_code == HTTPStatus.CREATED
    payload = response.get_json()
    assert payload["success"] is True
    assert payload["data"]["user"]["email"] == "newuser@example.com"
    assert payload["data"]["user"]["id"] is not None
    assert payload["data"]["access_token"]
    assert payload["data"]["refresh_token"]

    with app.app_context():
        user = db.session.execute(
            db.select(User).filter_by(email="newuser@example.com")
        ).scalar_one()
        assert user.check_password("StrongPass123")
        assert len(user.refresh_tokens) == 1
        stored_token = user.refresh_tokens[0]
        assert stored_token.token == payload["data"]["refresh_token"]
        assert not stored_token.revoked


def test_register_duplicate_email(app):
    client = app.test_client()

    first_response = client.post(
        "/auth/register",
        json={"email": "duplicate@example.com", "password": "StrongPass123"},
    )
    assert first_response.status_code == HTTPStatus.CREATED

    response = client.post(
        "/auth/register",
        json={"email": "duplicate@example.com", "password": "AnotherPass123"},
    )
    assert response.status_code == HTTPStatus.CONFLICT
    payload = response.get_json()
    assert payload["success"] is False
    assert "email" in payload["errors"]

    with app.app_context():
        users = db.session.execute(db.select(User)).scalars().all()
        assert len(users) == 1
        assert users[0].check_password("StrongPass123")


def test_register_invalid_email(app):
    client = app.test_client()

    response = client.post(
        "/auth/register", json={"email": "invalid-email", "password": "StrongPass123"}
    )
    assert response.status_code == HTTPStatus.BAD_REQUEST
    payload = response.get_json()
    assert payload["success"] is False
    assert "email" in payload["errors"]


def test_register_invalid_password(app):
    client = app.test_client()

    response = client.post(
        "/auth/register", json={"email": "valid@example.com", "password": "short"}
    )
    assert response.status_code == HTTPStatus.BAD_REQUEST
    payload = response.get_json()
    assert payload["success"] is False
    assert "password" in payload["errors"]

    with app.app_context():
        assert db.session.execute(db.select(User)).scalar_one_or_none() is None
        assert db.session.execute(db.select(RefreshToken)).scalar_one_or_none() is None
