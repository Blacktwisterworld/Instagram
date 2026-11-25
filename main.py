import os
import time
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.concurrency import run_in_threadpool

import database

API_KEY = os.environ.get("API_KEY", "").strip()

app = FastAPI(title="Remote SQLite API", version="1.0.0")
templates = Jinja2Templates(directory="templates")


def _check_key(provided: str):
    if not API_KEY:
        raise HTTPException(status_code=503, detail="Server API_KEY not configured")
    if provided != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


# ---------- Health (keep-alive ke liye) ----------
@app.get("/health")
def health():
    return {"status": "ok", "time": time.time()}


# ---------- Admin page ----------
@app.get("/", response_class=HTMLResponse)
async def admin_page(request: Request):
    return templates.TemplateResponse("admin.html", {"request": request})


# ---------- Old /search (admin page isse use karta hai) ----------
@app.get("/search")
async def search_endpoint(
    q: str = Query(..., min_length=1),
    field: str = Query("any"),
    limit: int = Query(10, ge=1, le=100),
    apikey: str = Query(""),
):
    _check_key(apikey)
    t0 = time.time()
    try:
        rows = await run_in_threadpool(database.search, q, field, limit)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}")
    return {
        "query": q,
        "field": field,
        "count": len(rows),
        "elapsed_ms": round((time.time() - t0) * 1000, 1),
        "results": rows,
    }


# ---------- NAYA ENDPOINT: /<number>&<apikey> ----------
# MUST be last route (catch-all)
@app.get("/{combined}")
async def lookup_by_number(combined: str):
    if "&" not in combined:
        raise HTTPException(
            status_code=400,
            detail="Invalid format. Use: /<number>&<apikey>",
        )

    number, provided_key = combined.split("&", 1)
    number = number.strip()
    provided_key = provided_key.strip()

    if not number:
        raise HTTPException(status_code=400, detail="Number is empty")
    if not provided_key:
        raise HTTPException(status_code=400, detail="API key is empty")

    _check_key(provided_key)

    try:
        rows = await run_in_threadpool(database.search, number, "phone", 10)
        if not rows:
            rows = await run_in_threadpool(database.search, number, "id", 10)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}")

    if not rows:
        return {
            "success": False,
            "count": 0,
            "message": "Not found",
            "data": [],
        }

    return {
        "success": True,
        "count": len(rows),
        "data": rows,
    }
