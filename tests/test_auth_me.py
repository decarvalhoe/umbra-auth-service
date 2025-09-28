from http import HTTPStatus

from src import db
from src.models import User


def _register_user(client):
    response = client.post(
        "/auth/register",
        json={"email": "me@example.com", "password": "StrongPass123"},
    )
    return response.get_json()


def test_me_returns_current_user_profile(app):
    client = app.test_client()
    registration_payload = _register_user(client)
    access_token = registration_payload["data"]["access_token"]

    response = client.get(
        "/auth/me", headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == HTTPStatus.OK
    payload = response.get_json()
    assert payload["success"] is True
    assert payload["data"]["user"]["email"] == "me@example.com"
    assert payload["message"] == "Profil utilisateur récupéré."


def test_me_returns_not_found_when_user_missing(app):
    client = app.test_client()
    registration_payload = _register_user(client)
    access_token = registration_payload["data"]["access_token"]
    user_id = registration_payload["data"]["user"]["id"]

    with app.app_context():
        user = db.session.get(User, user_id)
        db.session.delete(user)
        db.session.commit()

    response = client.get(
        "/auth/me", headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == HTTPStatus.NOT_FOUND
    payload = response.get_json()
    assert payload["success"] is False
    assert payload["errors"]["user"] == "Utilisateur introuvable."
    assert payload["message"] == "Utilisateur introuvable."


def test_me_requires_authorization_header(app):
    client = app.test_client()

    response = client.get("/auth/me")

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    payload = response.get_json()
    assert payload["msg"] == "Missing Authorization Header"
