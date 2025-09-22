from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Mapped
from werkzeug.security import check_password_hash, generate_password_hash

from src import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True), server_default=db.func.now(), nullable=False
    )

    refresh_tokens: Mapped[list["RefreshToken"]] = db.relationship(
        "RefreshToken",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def set_password(self, password: str) -> None:
        """Hash and store the user's password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verify that the provided password matches the stored hash."""
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)


class RefreshToken(db.Model):
    __tablename__ = "refresh_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)
    revoked = db.Column(db.Boolean, default=False, nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True), server_default=db.func.now(), nullable=False
    )

    user: Mapped[User] = db.relationship("User", back_populates="refresh_tokens", lazy="joined")

    def is_expired(self, reference_time: datetime | None = None) -> bool:
        """Return True if the refresh token is expired at the given time."""
        reference_time = reference_time or datetime.now(timezone.utc)

        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if reference_time.tzinfo is None:
            reference_time = reference_time.replace(tzinfo=timezone.utc)

        return expires_at <= reference_time
