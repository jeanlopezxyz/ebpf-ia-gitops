ML Detector
===========

Lightweight Flask service that performs rule-based and ML-based anomaly detection (MiniBatchKMeans, LOF, One-Class SVM) and exposes Prometheus metrics.

Run locally
- Install: `python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt`
- Start: `gunicorn -b 0.0.0.0:5000 app:app --workers 2 --threads 4`
- Health: `curl :5000/health`
- Detect: `curl -H 'Content-Type: application/json' -d '{"packets_per_second":120}' :5000/detect`

Environment
- MODEL_PATH: path to persist models (default `/tmp/models`).
- TRAINING_ENABLED: enable background training thread (`true`/`false`, default `true`).
- BASELINE_ENABLED: seed baseline training on boot (`true`/`false`, default `true`).
- PROMETHEUS_MULTIPROC_DIR: path for Prometheus multiprocess metrics (default `/tmp/prometheus`).
- MAX_CONTENT_LENGTH: max request size in bytes (default `65536`).

Endpoints
- `/health`: service status.
- `/metrics`: Prometheus metrics (text/plain).
- `/detect` (POST JSON): threat inference.
- `/train` (POST): on-demand training.
- `/stats`: model stats.

