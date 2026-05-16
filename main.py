import faulthandler
import logging
import os
from typing import Callable
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.webhook import router as webhook_router
from app.api.admin import router as admin_router
from app.core.config import settings
import uvicorn

faulthandler.enable()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("app.log", encoding="utf-8")
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="南昌大学智慧课程平台 - 零幻觉企业微信课后伴学助教专属代理。",
    version="1.1.0"
)

static_dir = os.path.join(os.path.dirname(__file__), "app", "static")

ALLOWED_IPS = frozenset(["127.0.0.1", "localhost"])
ALLOWED_IP_PREFIXES = ("172.", "192.168.8.")
EXCLUDED_IP = "192.168.8.88"
WHITELISTED_PATHS = frozenset([
    f"{settings.API_V1_STR}/wecom", "/health", "/", "/index", "/admin", "/exam"
])

def is_allowed_ip(client_ip: str) -> bool:
    if not client_ip:
        return False
    if client_ip in ALLOWED_IPS:
        return True
    if client_ip.startswith(ALLOWED_IP_PREFIXES):
        if client_ip.startswith("192.168.8.") and client_ip != EXCLUDED_IP:
            return True
    return False

def is_whitelisted_path(path: str) -> bool:
    if path in WHITELISTED_PATHS:
        return True
    if path.startswith(f"{settings.API_V1_STR}/wecom"):
        return True
    if path.startswith("/admin") or path.startswith("/exam"):
        return True
    if path.endswith(".html"):
        return True
    return False

@app.middleware("http")
async def security_and_cache_middleware(request: Request, call_next: Callable) -> JSONResponse:
    client_ip = request.client.host if request.client.host else ""
    path = request.url.path
    response = await call_next(request)

    if path.startswith("/admin") or path.endswith(".html"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"

    if is_allowed_ip(client_ip) or is_whitelisted_path(path):
        return response

    gateway_token = request.headers.get("X-AIIA-Gateway-Auth")
    if gateway_token == settings.GATEWAY_AUTH_TOKEN:
        return response

    logger.warning(f"[SECURITY] Blocked unauthorized access from IP: {client_ip}, path: {path}")
    return JSONResponse(
        status_code=403,
        content={"detail": "Access Denied: Internal AI Engine Protected. Direct external access is forbidden."}
    )

app.include_router(webhook_router, prefix=settings.API_V1_STR + "/wecom")
app.include_router(admin_router, prefix=settings.API_V1_STR + "/admin")

os.makedirs(static_dir, exist_ok=True)
app.mount("/admin", StaticFiles(directory=static_dir, html=True), name="admin_static")

PAGES = {
    "index": "index.html",
    "exam": "exam.html",
    "exam.html": "exam.html"
}

@app.get("/")
async def serve_index():
    return FileResponse(os.path.join(static_dir, "index.html"))

@app.get("/{page}")
async def serve_pages(page: str):
    if page in PAGES:
        return FileResponse(os.path.join(static_dir, PAGES[page]))
    return FileResponse(os.path.join(static_dir, "index.html"))

@app.get("/health")
async def health_check() -> dict:
    return {
        "status": "healthy",
        "llm_target": settings.LLM_API_BASE,
        "rag_persistence": settings.CHROMA_PERSIST_DIR
    }

if __name__ == "__main__":
    faulthandler.enable()
    port = int(os.environ.get("PORT", 8001))
    logger.info(f"Starting server on http://0.0.0.0:{port}")
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False, log_level="info")

handler = app