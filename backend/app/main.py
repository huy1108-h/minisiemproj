from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.database.repository import get_events, get_alerts, get_stats

app = FastAPI(
    title="Mini SIEM",
    description="Security Log Monitoring & Threat Detection Platform",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "project": "Mini SIEM",
        "status": "running",
        "version": "0.1.0"
    }

@app.get("/api/events")
def api_get_events(limit: int = 50):
    return get_events(limit)

@app.get("/api/alerts")
def api_get_alerts(limit: int = 50):
    return get_alerts(limit)

@app.get("/api/stats")
def api_get_stats():
    return get_stats()