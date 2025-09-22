import os
from typing import Any, Mapping

from flask import Flask, jsonify
from flask_cors import CORS

from src import db


def create_app(config: Mapping[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URI", "sqlite:///umbra-auth.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    if config:
        app.config.update(config)

    CORS(app)
    db.init_app(app)

    # Ensure models are registered with SQLAlchemy metadata
    from src import models  # noqa: F401

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
