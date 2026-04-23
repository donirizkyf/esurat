from fastapi import Request
from sqlalchemy.orm import Session

from app.models import AuditLog


def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def log_audit_event(
    db: Session,
    request: Request,
    user_id: int,
    action: str,
    document_id: str | None = None,
) -> None:
    entry = AuditLog(
        user_id=user_id,
        action=action,
        document_id=document_id,
        ip_address=get_client_ip(request),
    )
    db.add(entry)
    db.commit()
