import time
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.concurrency import run_in_threadpool

import database

app = FastAPI(title="Remote SQLite API", version="1.0.0")
templates = Jinja2Templates(directory="templates")


@app.get("/health")
def health():
    return {"status": "ok", "time": time.time()}


@app.get("/search")
async def search(
    q: str = Query(..., min_length=1, description="Search value"),
    field: str = Query("any", description="id|username|email|phone|name|any"),
    limit: int = Query(10, ge=1, le=100),
):
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


@app.get("/", response_class=HTMLResponse)
async def admin_page(request: Request):
    return templates.TemplateResponse("admin.html", {"request": request})


@app.get("/admin", response_class=HTMLResponse)
async def admin_page_alt(request: Request):
    return templates.TemplateResponse("admin.html", {"request": request})
