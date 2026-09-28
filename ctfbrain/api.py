"""FastAPI application serving the CTF-Brain web UI and JSON API."""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__
from .config import CATEGORIES, CATEGORY_META, DOC_TYPES, INDEX_DB
from .index import load_meta
from .render import pygments_css, render
from .search import Brain

WEB_DIR = Path(__file__).parent / "web"
STATIC_DIR = WEB_DIR / "static"
INDEX_HTML = WEB_DIR / "templates" / "index.html"

_brain: Brain | None = None


def brain() -> Brain:
    global _brain
    if _brain is None:
        if not INDEX_DB.exists():
            from .index import build
            build(verbose=False)
        _brain = Brain()
    return _brain


@asynccontextmanager
async def lifespan(app: FastAPI):
    brain()  # fail fast at startup rather than on the first request
    yield
    if _brain is not None:
        _brain.close()


app = FastAPI(title="CTF-Brain", version=__version__, lifespan=lifespan,
              docs_url="/api/docs", redoc_url=None)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ------------------------------------------------------------------- pages
def _page() -> HTMLResponse:
    if not INDEX_HTML.exists():
        return HTMLResponse("<h1>CTF-Brain</h1><p>UI template missing.</p>", 500)
    return HTMLResponse(INDEX_HTML.read_text(encoding="utf-8"))


@app.get("/", response_class=HTMLResponse)
def home() -> HTMLResponse:
    return _page()


@app.get("/doc/{slug:path}", response_class=HTMLResponse)
def doc_page(slug: str) -> HTMLResponse:
    return _page()


@app.get("/search", response_class=HTMLResponse)
def search_page() -> HTMLResponse:
    return _page()


@app.get("/pygments.css")
def css() -> Response:
    return Response(pygments_css(), media_type="text/css",
                    headers={"Cache-Control": "public, max-age=3600"})


@app.get("/favicon.ico")
def favicon():
    path = STATIC_DIR / "favicon.svg"
    if path.exists():
        return FileResponse(path, media_type="image/svg+xml")
    raise HTTPException(404)


# --------------------------------------------------------------------- api
@app.get("/api/search")
def api_search(
    q: str = Query("", description="query; supports cat: type: tag: diff: ctf: filters"),
    category: str | None = None,
    type: str | None = None,          # noqa: A002 - matches the query-string name
    tag: list[str] | None = Query(None),
    difficulty: str | None = None,
    limit: int = Query(25, ge=1, le=200),
    offset: int = Query(0, ge=0),
    synonyms: bool = True,
):
    hits, total = brain().search(
        q, category=category, doctype=type, tags=tag or [],
        difficulty=difficulty, limit=limit, offset=offset, synonyms=synonyms)
    return {
        "query": q, "total": total, "limit": limit, "offset": offset,
        "results": [h.to_dict() for h in hits],
    }


@app.get("/api/facets")
def api_facets(q: str = ""):
    return brain().facets(q)


@app.get("/api/doc/{slug:path}")
def api_doc(slug: str):
    doc = brain().get(slug)
    if doc is None:
        raise HTTPException(404, f"no document {slug!r}")
    body_html, toc = render(doc["body"])
    doc = dict(doc)
    doc.pop("body", None)
    doc.pop("code", None)
    doc["html"] = body_html
    doc["toc"] = toc
    doc["related"] = brain().related(slug, limit=10)
    doc["category_meta"] = dict(zip(
        ("label", "color", "description"),
        CATEGORY_META.get(doc["category"], (doc["category"], "#888", ""))))
    return doc


@app.get("/api/raw/{slug:path}", response_class=PlainTextResponse)
def api_raw(slug: str) -> str:
    doc = brain().get(slug)
    if doc is None:
        raise HTTPException(404, f"no document {slug!r}")
    path = Path(doc["path"])
    if not path.exists():
        raise HTTPException(410, "source file no longer on disk; re-run `ctfbrain index`")
    return path.read_text(encoding="utf-8")


@app.get("/api/tags")
def api_tags(category: str | None = None, limit: int = Query(400, ge=1, le=5000)):
    return {"tags": brain().tags(category=category, limit=limit)}


@app.get("/api/related/{slug:path}")
def api_related(slug: str, limit: int = 10):
    return {"related": brain().related(slug, limit=limit)}


@app.get("/api/stats")
def api_stats():
    data = brain().stats()
    data["build"] = load_meta()
    data["version"] = __version__
    data["categories"] = [
        {"key": c, "label": CATEGORY_META[c][0], "color": CATEGORY_META[c][1],
         "description": CATEGORY_META[c][2], "count": data["by_category"].get(c, 0)}
        for c in CATEGORIES
    ]
    data["types"] = DOC_TYPES
    return data


@app.get("/api/random")
def api_random(category: str | None = None, type: str | None = None):  # noqa: A002
    doc = brain().random(category=category, doctype=type)
    if doc is None:
        raise HTTPException(404, "index is empty")
    return {"slug": doc["slug"], "title": doc["title"], "category": doc["category"]}


@app.get("/api/health")
def api_health():
    meta = load_meta()
    return {"ok": True, "version": __version__,
            "documents": meta.get("documents", 0),
            "built_at": meta.get("built_at")}
