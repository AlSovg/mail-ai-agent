from fastapi.testclient import TestClient

from mailagent.api import app


def test_health():
    r = TestClient(app).get("/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_access_log_drops_query():
    import logging

    import mailagent.api  # noqa: F401  регистрирует фильтр

    rec = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, '%s - "%s %s HTTP/%s" %d',
                            ("1.2.3.4:0", "GET", "/oauth/callback?code=SECRET&state=S", "1.1", 200), None)
    assert all(f.filter(rec) for f in logging.getLogger("uvicorn.access").filters)
    assert "SECRET" not in rec.getMessage() and "/oauth/callback" in rec.getMessage()
