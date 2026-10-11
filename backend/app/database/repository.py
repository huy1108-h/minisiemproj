import hashlib
from datetime import datetime

from backend.app.database.connection import SessionLocal
from backend.app.database.models import Event, Alert


def generate_event_fingerprint(event_data):
    raw = (
        f"{event_data.get('timestamp')}|"
        f"{event_data.get('level')}|"
        f"{event_data.get('user')}|"
        f"{event_data.get('action')}|"
        f"{event_data.get('ip')}"
    )

    return hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()


def save_event(event_data):
    db = SessionLocal()

    try:
        # Tạo fingerprint cho event
        fingerprint = generate_event_fingerprint(event_data)

        # Kiểm tra event này đã tồn tại chưa
        existing_event = (
            db.query(Event)
            .filter(Event.fingerprint == fingerprint)
            .first()
        )

        if existing_event:
            print(
                f"Duplicate event skipped: "
                f"{event_data.get('action')} - {event_data.get('ip')}"
            )
            return None

        # Event chưa tồn tại -> lưu vào database
        event = Event(
            fingerprint=fingerprint,

            timestamp=datetime.strptime(
                event_data["timestamp"],
                "%Y-%m-%d %H:%M:%S"
            ),

            level=event_data["level"],
            user=event_data.get("user"),
            action=event_data["action"],
            ip=event_data.get("ip")
        )

        db.add(event)
        db.commit()
        db.refresh(event)

        return event

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


def save_alert(alert_data):
    db = SessionLocal()

    try:
        alert = Alert(
            rule=alert_data["rule"],
            severity=alert_data["severity"],
            user=alert_data.get("user"),
            ip=alert_data.get("ip"),
            message=alert_data["message"]
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        return alert

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


def get_events(limit=50):
    db = SessionLocal()
    try:
        events = db.query(Event).order_by(Event.timestamp.desc()).limit(limit).all()
        return events
    finally:
        db.close()


def get_alerts(limit=50):
    db = SessionLocal()
    try:
        alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(limit).all()
        return alerts
    finally:
        db.close()


def get_stats():
    db = SessionLocal()
    try:
        total_events = db.query(Event).count()
        total_alerts = db.query(Alert).count()
        return {
            "total_events": total_events,
            "total_alerts": total_alerts
        }
    finally:
        db.close()