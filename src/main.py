import os
from flask import Flask, jsonify
from flask_cors import CORS

def create_app() -> Flask:
    app = Flask(__name__)
    CORS(app)

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
