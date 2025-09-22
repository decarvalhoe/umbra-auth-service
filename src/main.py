import os
from datetime import timedelta
from typing import Any, Mapping

from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager

from src import db


def create_app(config: Mapping[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URI", "sqlite:///umbra-auth.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config.setdefault("JWT_SECRET_KEY", os.getenv("JWT_SECRET_KEY", "change-me"))
    app.config.setdefault("JWT_ACCESS_TOKEN_EXPIRES", timedelta(minutes=15))
    app.config.setdefault("JWT_REFRESH_TOKEN_EXPIRES", timedelta(days=7))

    if config:
        app.config.update(config)

    CORS(app)
    db.init_app(app)
    JWTManager(app)

    # Ensure models are registered with SQLAlchemy metadata
    from src import models  # noqa: F401
    from src.routes.auth import auth_bp

    app.register_blueprint(auth_bp)

    @app.get("/health")
    def health():
        return jsonify({
            "success": True,
            "data": {"status": "healthy", "service": "umbra-auth-service"},
            "message": "Service en bonne santé"
        }), 200

    return app


if __name__ == "__main__":
    app = create_app()
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
