#!/usr/bin/env python3
from __future__ import annotations

import logging
import os
from flask import Flask

from api import create_api
from detector import ThreatDetector


def create_app() -> Flask:
    app = Flask(__name__)

    # Security limits
    app.config["MAX_CONTENT_LENGTH"] = int(
        os.getenv("MAX_CONTENT_LENGTH", str(64 * 1024))
    )

    # Logging
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

    # Core services
    detector = ThreatDetector()
    api_bp = create_api(detector)
    app.register_blueprint(api_bp)
    return app


# WSGI entrypoint for Gunicorn
app = create_app()
