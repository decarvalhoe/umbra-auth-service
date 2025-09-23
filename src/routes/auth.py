from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import create_access_token, create_refresh_token
from sqlalchemy.exc import IntegrityError

from src import db
from src.models import RefreshToken, User

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


auth_bp = Blueprint("auth", __name__)


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _validate_input(data: dict[str, object]) -> tuple[dict[str, str], str | None, str | None]:
    email = data.get("email")
    password = data.get("password")

    errors: dict[str, str] = {}
    normalized_email: str | None = None
    normalized_password: str | None = None

    if not isinstance(email, str) or not email.strip():
        errors["email"] = "Email requis."
    else:
        normalized_email = _normalize_email(email)
        if not EMAIL_REGEX.fullmatch(normalized_email):
            errors["email"] = "Email invalide."

    if not isinstance(password, str) or not password:
        errors["password"] = "Mot de passe requis."
    elif len(password) < 8:
        errors["password"] = "Le mot de passe doit contenir au moins 8 caractères."
    else:
        normalized_password = password

    return errors, normalized_email, normalized_password


def _resolve_refresh_token_expiry(now: datetime) -> datetime:
    expires = current_app.config.get("JWT_REFRESH_TOKEN_EXPIRES")

    if isinstance(expires, timedelta):
        expires_delta = expires
    elif isinstance(expires, int):
        expires_delta = timedelta(seconds=expires)
    elif expires in {None, True}:
        expires_delta = timedelta(days=30)
    elif expires is False:
        expires_delta = timedelta(days=3650)
    else:
        raise TypeError("Invalid JWT_REFRESH_TOKEN_EXPIRES configuration")

    return now + expires_delta


@auth_bp.post("/auth/register")
def register():
    payload = request.get_json(silent=True) or {}
    errors, email, password = _validate_input(payload)

    if errors:
        return (
            jsonify({"success": False, "errors": errors, "message": "Données invalides."}),
            400,
        )

    assert email is not None and password is not None  # For type checkers

    existing_user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none()
    if existing_user is not None:
        return (
            jsonify(
                {
                    "success": False,
                    "errors": {"email": "Un utilisateur avec cet email existe déjà."},
                    "message": "Conflit de données.",
                }
            ),
            409,
        )

    user = User(email=email)
    user.set_password(password)

    db.session.add(user)

    try:
        db.session.flush()
    except IntegrityError:
        db.session.rollback()
        return (
            jsonify(
                {
                    "success": False,
                    "errors": {"email": "Un utilisateur avec cet email existe déjà."},
                    "message": "Conflit de données.",
                }
            ),
            409,
        )

    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)

    now = datetime.now(timezone.utc)
    refresh_token_entry = RefreshToken(
        user=user,
        token=refresh_token,
        expires_at=_resolve_refresh_token_expiry(now),
    )
    db.session.add(refresh_token_entry)

    db.session.commit()

    return (
        jsonify(
            {
                "success": True,
                "data": {
                    "user": {"id": user.id, "email": user.email},
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                },
                "message": "Utilisateur créé avec succès.",
            }
        ),
        201,
    )


@auth_bp.post("/auth/login")
def login():
    payload = request.get_json(silent=True) or {}
    errors, email, password = _validate_input(payload)

    if errors:
        return (
            jsonify({"success": False, "errors": errors, "message": "Données invalides."}),
            400,
        )

    assert email is not None and password is not None  # For type checkers

    user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none()

    if user is None or not user.check_password(password):
        return (
            jsonify(
                {
                    "success": False,
                    "errors": {
                        "credentials": "Email ou mot de passe invalide.",
                    },
                    "message": "Identifiants invalides.",
                }
            ),
            401,
        )

    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)

    now = datetime.now(timezone.utc)
    refresh_token_entry = RefreshToken(
        user=user,
        token=refresh_token,
        expires_at=_resolve_refresh_token_expiry(now),
    )
    db.session.add(refresh_token_entry)
    db.session.commit()

    return (
        jsonify(
            {
                "success": True,
                "data": {
                    "user": {"id": user.id, "email": user.email},
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                },
                "message": "Connexion réussie.",
            }
        ),
        200,
    )
