"""
Universal Spam & Threat Detection — FastAPI Backend
Run: uvicorn backend.main:app --reload --port 8000
"""
import os
import sys

# Add the backend directory to Python path so imports like 'routers' and 'middleware' work
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from routers import text_scan, image_scan, url_scan
from middleware.rate_limiter import RateLimitMiddleware

app = FastAPI(
    title="Universal Spam & Threat Detection API",
    version="1.0.0",
    description="Scans text, images, and URLs for phishing, spam, and malware indicators."
)

# CORS — tighten allow_origins to your domain in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # restrict in production
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

app.add_middleware(RateLimitMiddleware)

# API routes
app.include_router(text_scan.router, prefix="/api/scan", tags=["scan"])
app.include_router(image_scan.router, prefix="/api/scan", tags=["scan"])
app.include_router(url_scan.router,  prefix="/api/scan", tags=["scan"])

# Serve frontend static files
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
app.mount("/static", StaticFiles(directory=os.path.join(frontend_path, "css")), name="css")
app.mount("/js", StaticFiles(directory=os.path.join(frontend_path, "js")), name="js")

@app.get("/")
async def serve_frontend():
    return FileResponse(os.path.join(frontend_path, "index.html"))

@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}
