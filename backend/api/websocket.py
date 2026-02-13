"""WebSocket endpoint for real-time investigation streaming."""

import json
import asyncio
from typing import Dict
from fastapi import WebSocket, WebSocketDisconnect


class InvestigationManager:
    """Manages WebSocket connections for investigation streaming."""

    def __init__(self):
        self._connections: Dict[str, list] = {}  # alert_id -> list of websockets
        self._events: Dict[str, list] = {}  # alert_id -> buffered events

    async def connect(self, websocket: WebSocket, alert_id: str) -> None:
        """Accept a WebSocket connection for an investigation.

        Args:
            websocket: The WebSocket connection.
            alert_id: The investigation alert ID.
        """
        await websocket.accept()
        if alert_id not in self._connections:
            self._connections[alert_id] = []
        self._connections[alert_id].append(websocket)

        # Send any buffered events
        if alert_id in self._events:
            for event in self._events[alert_id]:
                try:
                    await websocket.send_json(event)
                except Exception:
                    break

    def disconnect(self, websocket: WebSocket, alert_id: str) -> None:
        """Remove a WebSocket connection.

        Args:
            websocket: The WebSocket connection.
            alert_id: The investigation alert ID.
        """
        if alert_id in self._connections:
            self._connections[alert_id] = [
                ws for ws in self._connections[alert_id] if ws != websocket
            ]
            if not self._connections[alert_id]:
                del self._connections[alert_id]

    async def broadcast(self, alert_id: str, event: Dict) -> None:
        """Broadcast an event to all WebSocket connections for an investigation.

        Also buffers events for late-connecting clients.

        Args:
            alert_id: The investigation alert ID.
            event: The event data to broadcast.
        """
        # Buffer the event
        if alert_id not in self._events:
            self._events[alert_id] = []
        self._events[alert_id].append(event)

        # Limit buffer size
        if len(self._events[alert_id]) > 200:
            self._events[alert_id] = self._events[alert_id][-200:]

        # Broadcast to connected clients
        if alert_id in self._connections:
            dead_connections = []
            for websocket in self._connections[alert_id]:
                try:
                    await websocket.send_json(event)
                except Exception:
                    dead_connections.append(websocket)

            # Clean up dead connections
            for ws in dead_connections:
                self.disconnect(ws, alert_id)

    def clear_events(self, alert_id: str) -> None:
        """Clear buffered events for an investigation.

        Args:
            alert_id: The investigation alert ID.
        """
        self._events.pop(alert_id, None)

    def get_buffered_events(self, alert_id: str) -> list:
        """Get buffered events for an investigation.

        Args:
            alert_id: The investigation alert ID.

        Returns:
            List of buffered event dicts.
        """
        return self._events.get(alert_id, [])


# Global instance
investigation_manager = InvestigationManager()
