"""
Secure FastAPI server for receiving IoT elder-care alerts from Raspberry Pi edge devices.
Part of the Home Rhythm anomaly detection pipeline.

PRIVACY NOTE: This server NEVER receives raw power wattage data. Only evaluated
context strings are transmitted to protect the elder's privacy.
"""

from datetime import datetime
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

# --- Security Configuration ---
# Hardcoded API key for hackathon demo. In production, use environment variables.
API_KEY = "nilm-hackathon-2026-secure-key"
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: Optional[str] = Depends(api_key_header)) -> str:
    """Dependency that validates the API key from request headers."""
    if api_key is None or api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API key",
        )
    return api_key


# --- Pydantic Models ---
class CareAlert(BaseModel):
    """
    Alert model for anomaly notifications from edge devices.

    PRIVACY RULE: Raw power wattage is NEVER transmitted. Only the evaluated
    context string (e.g., "prolonged inactivity detected") is sent to protect
    the elder's privacy and comply with data minimization principles.
    """
    device_id: str = Field(..., description="Unique identifier for the Pi/house")
    timestamp: datetime = Field(..., description="When the anomaly was detected")
    anomaly_type: str = Field(
        ...,
        description="Type of anomaly: skipped_meal, fire_risk, night_wandering, prolonged_inactivity",
    )
    severity: int = Field(..., ge=1, le=5, description="Severity level 1 (low) to 5 (critical)")
    safe_context: str = Field(
        ...,
        description="Human-readable context without raw sensor data",
    )


class AlertResponse(BaseModel):
    """Response model for successful alert submission."""
    status: str
    alert_id: int
    message: str


class DeviceStatus(BaseModel):
    """Status response for mobile app queries."""
    device_id: str
    last_seen: Optional[datetime]
    recent_alerts: list[CareAlert]
    alert_count: int


# --- In-Memory Storage (Mock Database for Hackathon) ---
alerts_db: dict[str, list[CareAlert]] = {}
alert_counter: int = 0


# --- WebSocket Manager ---
class ConnectionManager:
    """Manages WebSocket connections for real-time alert broadcasting."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict) -> None:
        disconnected: list[WebSocket] = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)
        for connection in disconnected:
            if connection in self.active_connections:
                self.active_connections.remove(connection)


ws_manager = ConnectionManager()


# --- FastAPI App ---
app = FastAPI(
    title="Home Rhythm Alert Server",
    description="Secure API for receiving elder-care anomaly alerts from edge devices",
    version="1.0.0",
)

# CORS middleware for frontend connectivity
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Endpoints ---
@app.post(
    "/api/v1/alerts",
    response_model=AlertResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(verify_api_key)],
)
async def receive_alert(alert: CareAlert) -> AlertResponse:
    """
    Secured endpoint for Raspberry Pi to push anomaly alerts.
    Requires valid X-API-Key header.
    """
    global alert_counter
    alert_counter += 1

    # Store alert by device_id
    if alert.device_id not in alerts_db:
        alerts_db[alert.device_id] = []
    alerts_db[alert.device_id].append(alert)

    # Keep only last 50 alerts per device
    if len(alerts_db[alert.device_id]) > 50:
        alerts_db[alert.device_id] = alerts_db[alert.device_id][-50:]

    # Broadcast to connected mobile apps
    await ws_manager.broadcast({
        "type": "new_alert",
        "alert": {
            "device_id": alert.device_id,
            "timestamp": alert.timestamp.isoformat(),
            "anomaly_type": alert.anomaly_type,
            "severity": alert.severity,
            "safe_context": alert.safe_context,
        },
        "alert_id": alert_counter,
    })

    return AlertResponse(
        status="received",
        alert_id=alert_counter,
        message=f"Alert for {alert.device_id} logged successfully",
    )


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """WebSocket endpoint for mobile app to receive real-time alerts."""
    await ws_manager.connect(websocket)
    try:
        total_alerts = sum(len(alerts) for alerts in alerts_db.values())
        await websocket.send_json({
            "type": "connection_established",
            "devices_tracked": len(alerts_db),
            "total_alerts": total_alerts,
        })
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


@app.get("/api/v1/status/{device_id}", response_model=DeviceStatus)
async def get_device_status(device_id: str) -> DeviceStatus:
    """
    Endpoint for mobile app to fetch latest status/alerts for a specific house.
    No API key required - intended for caregiver app access.
    """
    device_alerts = alerts_db.get(device_id, [])
    last_seen = device_alerts[-1].timestamp if device_alerts else None

    return DeviceStatus(
        device_id=device_id,
        last_seen=last_seen,
        recent_alerts=device_alerts[-10:],  # Return last 10 alerts
        alert_count=len(device_alerts),
    )


@app.get("/api/v1/health")
async def health_check() -> dict:
    """Health check endpoint for monitoring."""
    return {"status": "healthy", "devices_tracked": len(alerts_db)}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)
