from __future__ import annotations

from datetime import datetime, timedelta, timezone
from http import HTTPStatus

from flask_jwt_extended import create_refresh_token

from src import db
from src.models import RefreshToken, User


def _create_user_with_refresh_token(
    app,
    *,
    email: str = "refresh@example.com",
    expires_delta: timedelta = timedelta(days=7),
    revoked: bool = False,
    expired: bool = False,
) -> str:
    with app.app_context():
        user = User(email=email)
        user.set_password("StrongPass123")
        db.session.add(user)
        db.session.commit()

        refresh_token = create_refresh_token(identity=user.id)

        now = datetime.now(timezone.utc)
        expires_at = now + expires_delta
        if expired:
            expires_at = now - timedelta(seconds=1)

        token_entry = RefreshToken(
            user=user,
            token=refresh_token,
            revoked=revoked,
            expires_at=expires_at,
        )
        db.session.add(token_entry)
        db.session.commit()

        return refresh_token


def test_refresh_success(app):
    refresh_token = _create_user_with_refresh_token(app)
    client = app.test_client()

    response = client.post("/auth/refresh", json={"refresh_token": refresh_token})

    assert response.status_code == HTTPStatus.OK
    payload = response.get_json()
    assert payload["success"] is True
    assert payload["data"]["user"]["email"] == "refresh@example.com"
    assert payload["data"]["user"]["id"] is not None
    assert payload["data"]["access_token"]
    assert payload["message"] == "Token renouvelé avec succès."

    with app.app_context():
        user = db.session.execute(
            db.select(User).filter_by(email="refresh@example.com")
        ).scalar_one()
        assert len(user.refresh_tokens) == 1
        stored_token = user.refresh_tokens[0]
        assert stored_token.token == refresh_token
        assert not stored_token.revoked


def test_refresh_missing_token(app):
    client = app.test_client()

    response = client.post("/auth/refresh", json={})

    assert response.status_code == HTTPStatus.BAD_REQUEST
    payload = response.get_json()
    assert payload["success"] is False
    assert payload["errors"]["refresh_token"] == "Refresh token requis."
    assert payload["message"] == "Données invalides."


def test_refresh_invalid_token(app):
    client = app.test_client()

    response = client.post("/auth/refresh", json={"refresh_token": "invalid"})

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    payload = response.get_json()
    assert payload["success"] is False
    assert payload["errors"]["refresh_token"] == "Refresh token invalide ou expiré."
    assert payload["message"] == "Token de rafraîchissement invalide."


def test_refresh_revoked_token(app):
    refresh_token = _create_user_with_refresh_token(app, revoked=True)
    client = app.test_client()

    response = client.post("/auth/refresh", json={"refresh_token": refresh_token})

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    payload = response.get_json()
    assert payload["success"] is False
    assert payload["errors"]["refresh_token"] == "Refresh token invalide ou expiré."
    assert payload["message"] == "Token de rafraîchissement invalide."


def test_refresh_expired_token(app):
    refresh_token = _create_user_with_refresh_token(app, expired=True)
    client = app.test_client()

    response = client.post("/auth/refresh", json={"refresh_token": refresh_token})

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    payload = response.get_json()
    assert payload["success"] is False
    assert payload["errors"]["refresh_token"] == "Refresh token invalide ou expiré."
    assert payload["message"] == "Token de rafraîchissement invalide."
