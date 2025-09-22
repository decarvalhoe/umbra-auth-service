from datetime import datetime, timedelta, timezone

from src import db
from src.models import RefreshToken, User


def test_user_password_hashing(app):
    with app.app_context():
        user = User(email="test@example.com")
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()

        assert user.password_hash != "password123"
        assert user.check_password("password123")
        assert not user.check_password("wrong-password")


def test_refresh_token_relationship(app):
    with app.app_context():
        user = User(email="owner@example.com")
        user.set_password("strong-password")
        db.session.add(user)
        db.session.commit()

        refresh_token = RefreshToken(
            user=user,
            token="refresh-token",
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )
        db.session.add(refresh_token)
        db.session.commit()

        assert refresh_token.user == user
        assert refresh_token in user.refresh_tokens
        assert not refresh_token.revoked
        assert not refresh_token.is_expired(datetime.now(timezone.utc))
