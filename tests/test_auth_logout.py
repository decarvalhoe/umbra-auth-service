from http import HTTPStatus

from src import db
from src.models import RefreshToken


def _register_user(client):
    response = client.post(
        "/auth/register",
        json={"email": "logout@example.com", "password": "StrongPass123"},
    )
    return response.get_json()


def test_logout_revokes_refresh_token(app):
    client = app.test_client()
    registration_payload = _register_user(client)
    refresh_token = registration_payload["data"]["refresh_token"]

    response = client.post(
        "/auth/logout", json={"refresh_token": refresh_token}
    )

    assert response.status_code == HTTPStatus.OK
    payload = response.get_json()
    assert payload["success"] is True
    assert payload["data"]["revoked"] is True
    assert payload["message"] == "Déconnexion effectuée."

    with app.app_context():
        token_entry = db.session.execute(
            db.select(RefreshToken).filter_by(token=refresh_token)
        ).scalar_one()
        assert token_entry.revoked is True


def test_logout_requires_refresh_token(app):
    client = app.test_client()

    response = client.post("/auth/logout", json={})

    assert response.status_code == HTTPStatus.BAD_REQUEST
    payload = response.get_json()
    assert payload["success"] is False
    assert payload["errors"]["refresh_token"] == "Refresh token requis."
    assert payload["message"] == "Données invalides."


def test_logout_is_idempotent_for_unknown_token(app):
    client = app.test_client()

    response = client.post(
        "/auth/logout", json={"refresh_token": "unknown-token"}
    )

    assert response.status_code == HTTPStatus.OK
    payload = response.get_json()
    assert payload["success"] is True
    assert payload["data"]["revoked"] is True
    assert payload["message"] == "Déconnexion effectuée."
