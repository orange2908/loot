"""The HTTP surface the web UI depends on."""
import pytest

fastapi_testclient = pytest.importorskip("fastapi.testclient")
from fastapi.testclient import TestClient   # noqa: E402

from ctfbrain.api import app                # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_health(client):
    body = client.get("/api/health").json()
    assert body["ok"] is True
    assert body["documents"] >= 0


def test_home_serves_the_spa(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "CTF" in res.text and '<div id="app">' in res.text


def test_static_assets_are_served(client):
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/style.css").status_code == 200
    css = client.get("/pygments.css")
    assert css.status_code == 200 and "text/css" in css.headers["content-type"]


def test_search_endpoint_shape(client):
    body = client.get("/api/search", params={"q": "rsa", "limit": 5}).json()
    assert set(body) >= {"query", "total", "results"}
    for hit in body["results"]:
        assert set(hit) >= {"slug", "title", "category", "type", "tags", "score"}


def test_search_accepts_filters(client):
    body = client.get("/api/search", params={"q": "", "category": "pwn", "limit": 3}).json()
    assert all(r["category"] == "pwn" for r in body["results"])


def test_doc_endpoint_renders_html(client):
    hits = client.get("/api/search", params={"q": "", "limit": 1}).json()["results"]
    if not hits:
        pytest.skip("index is empty")
    doc = client.get(f"/api/doc/{hits[0]['slug']}").json()
    assert "html" in doc and "toc" in doc and "related" in doc
    assert doc["slug"] == hits[0]["slug"]


def test_missing_doc_is_404(client):
    assert client.get("/api/doc/definitely:not:here").status_code == 404


def test_tags_and_stats(client):
    assert isinstance(client.get("/api/tags").json()["tags"], list)
    stats = client.get("/api/stats").json()
    assert len(stats["categories"]) == 13
    assert "documents" in stats


def test_deep_link_serves_the_spa(client):
    res = client.get("/doc/whatever:slug")
    assert res.status_code == 200 and '<div id="app">' in res.text
