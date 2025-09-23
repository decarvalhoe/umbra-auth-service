from __future__ import annotations

from http import HTTPStatus

from src import db
from src.models import User


def _create_user(app, email: str = "existing@example.com", password: str = "StrongPass123") -> None:
    with app.app_context():
        user = User(email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()


def test_login_success(app):
    _create_user(app, email="login@example.com", password="StrongPass123")
    client = app.test_client()

    response = client.post(
        "/auth/login",
        json={"email": "LOGIN@example.com", "password": "StrongPass123"},
    )

    assert response.status_code == HTTPStatus.OK
    payload = response.get_json()
    assert payload["success"] is True
    assert payload["data"]["user"]["email"] == "login@example.com"
    assert payload["data"]["user"]["id"] is not None
    assert payload["data"]["access_token"]
    assert payload["data"]["refresh_token"]
    assert payload["message"] == "Connexion réussie."

    with app.app_context():
        user = db.session.execute(
            db.select(User).filter_by(email="login@example.com")
        ).scalar_one()
        assert len(user.refresh_tokens) == 1
        stored_token = user.refresh_tokens[0]
        assert stored_token.token == payload["data"]["refresh_token"]
        assert not stored_token.revoked


def test_login_invalid_credentials(app):
    _create_user(app, email="login@example.com", password="StrongPass123")
    client = app.test_client()

    response = client.post(
        "/auth/login",
        json={"email": "login@example.com", "password": "WrongPass123"},
    )

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    payload = response.get_json()
    assert payload["success"] is False
    assert payload["message"] == "Identifiants invalides."
    assert "credentials" in payload["errors"]

    with app.app_context():
        user = db.session.execute(
            db.select(User).filter_by(email="login@example.com")
        ).scalar_one()
        assert not user.refresh_tokens


def test_login_invalid_email_format(app):
    client = app.test_client()

    response = client.post(
        "/auth/login",
        json={"email": "invalid-email", "password": "StrongPass123"},
    )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    payload = response.get_json()
    assert payload["success"] is False
    assert "email" in payload["errors"]
    assert payload["message"] == "Données invalides."


def test_login_missing_password(app):
    client = app.test_client()

    response = client.post(
        "/auth/login",
        json={"email": "user@example.com"},
    )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    payload = response.get_json()
    assert payload["success"] is False
    assert "password" in payload["errors"]
    assert payload["message"] == "Données invalides."

