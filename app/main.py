from pathlib import Path
from uuid import uuid4
from datetime import datetime

import uvicorn
from fastapi import FastAPI, Request, Depends, Form, File, UploadFile, status, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app.audit import log_audit_event
from app.auth import (
    ACCOUNT_ACTIVE,
    ACCOUNT_DEACTIVATED,
    ACCOUNT_PENDING,
    DEFAULT_INTERNAL_STAFF_ROLE,
    INTERNAL_SECTION_OPTIONS,
    INTERNAL_ROLES,
    SERVICE_USER_ROLE,
    get_current_user,
    hash_password,
    is_admin_user,
    is_internal_user,
    is_service_user,
    is_super_admin,
    get_session_secret,
    router as auth_router,
    session_uses_https,
    verify_password,
)
from app.database import Base, engine, get_db
from app import models
from app.receipt import generate_submission_receipt
from app.schema import sync_schema


BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
UPLOADS_DIR = BASE_DIR / "uploads"
OUTPUTS_DIR = BASE_DIR / "outputs"
MAX_UPLOAD_SIZE = 5 * 1024 * 1024
VALID_BAGIAN_OPTIONS = (
    "Perijinan Cukai",
    "Perijinan Pabean",
    "Pelayanan BC25/Ekspor",
)
DEFAULT_BAGIAN = VALID_BAGIAN_OPTIONS[0]
STATUS_LABELS = {
    "PENOMORAN_AGENDA": "status-submitted",
    "VERIFIKASI_PETUGAS": "status-verified",
    "PENOLAKAN": "status-rejected",
    "PENELITIAN_DOKUMEN": "status-processing",
    "SELESAI": "status-complete",
}
VALID_STATUSES = tuple(STATUS_LABELS.keys())
ACCOUNT_STATUS_LABELS = {
    ACCOUNT_PENDING: "status-pending",
    ACCOUNT_ACTIVE: "status-active",
    ACCOUNT_DEACTIVATED: "status-deactivated",
}
VALID_ACCOUNT_STATUSES = tuple(ACCOUNT_STATUS_LABELS.keys())
USER_SCOPE_OPTIONS = ("service_user", "internal")
INTERNAL_ACCOUNT_TYPE_OPTIONS = ("admin", "super_admin")
INTERNAL_STAFF_ROLE_OPTIONS = ("OA", "Monitoring", "PIC", "Staff", "Staff KK")
SUPER_ADMIN_STAFF_ROLE_LABEL = "Semua"
STAFF_ROLE_OA = "OA"
STAFF_ROLE_MONITORING = "Monitoring"
STAFF_ROLE_PIC = "PIC"
STAFF_ROLE_STAFF = "Staff"
STAFF_ROLE_STAFF_KK = "Staff KK"

for directory in (STATIC_DIR, UPLOADS_DIR, OUTPUTS_DIR):
    directory.mkdir(parents=True, exist_ok=True)

sync_schema()
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Sistem Pengajuan Dokumen")
app.add_middleware(
    SessionMiddleware,
    secret_key=get_session_secret(),
    same_site="lax",
    https_only=session_uses_https(),
    max_age=60 * 60 * 8,
    session_cookie="document_submission_session",
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
app.state.templates = templates
app.include_router(auth_router)


def build_home_context(
    request: Request,
    db: Session,
    error: str | None = None,
    form_data: dict[str, str] | None = None,
):
    current_user = get_current_user(request, db)

    return {
        "request": request,
        "app_name": "Sistem Pengajuan Dokumen",
        "current_user": current_user,
        "error": error,
        "bagian_options": VALID_BAGIAN_OPTIONS,
        "form_data": form_data or {
            "bagian": DEFAULT_BAGIAN,
            "subject": "",
            "document_date": "",
            "description": "",
        },
    }


def build_dashboard_context(request: Request, current_user: models.User, db: Session):
    submissions = (
        db.query(models.DocumentSubmission)
        .filter(models.DocumentSubmission.user_id == current_user.id)
        .order_by(models.DocumentSubmission.created_at.desc())
        .all()
    )
    return {
        "request": request,
        "app_name": "Sistem Pengajuan Dokumen",
        "current_user": current_user,
        "submissions": submissions,
        "status_labels": STATUS_LABELS,
    }


def build_profile_context(
    request: Request,
    current_user: models.User,
    *,
    message: str | None = None,
    error: str | None = None,
):
    return {
        "request": request,
        "app_name": "Sistem Pengajuan Dokumen",
        "current_user": current_user,
        "message": message,
        "error": error,
    }


def get_admin_user(request: Request, db: Session) -> models.User | None:
    current_user = get_current_user(request, db)
    if not is_internal_user(current_user):
        return None
    return current_user


def require_admin_role(user: models.User | None) -> None:
    if not is_admin_user(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Akses admin diperlukan.")


def require_super_admin_role(user: models.User | None) -> None:
    if not is_super_admin(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Akses super admin diperlukan.")


def get_staff_function(user: models.User | None) -> str:
    if not user:
        return ""
    if is_super_admin(user):
        return SUPER_ADMIN_STAFF_ROLE_LABEL
    normalized = (user.staff_role or DEFAULT_INTERNAL_STAFF_ROLE).strip()
    if normalized not in INTERNAL_STAFF_ROLE_OPTIONS:
        return DEFAULT_INTERNAL_STAFF_ROLE
    return normalized


def can_route_document(user: models.User | None) -> bool:
    return is_super_admin(user) or get_staff_function(user) == STAFF_ROLE_OA


def can_verify_document(user: models.User | None) -> bool:
    return is_super_admin(user) or get_staff_function(user) == STAFF_ROLE_PIC


def can_upload_response_document(user: models.User | None) -> bool:
    return is_super_admin(user) or get_staff_function(user) in {STAFF_ROLE_STAFF, STAFF_ROLE_STAFF_KK}


def can_complete_document(user: models.User | None) -> bool:
    return can_upload_response_document(user)


def can_monitor_document(user: models.User | None) -> bool:
    return bool(user and is_admin_user(user))


def can_access_internal_scope(user: models.User | None) -> bool:
    return is_super_admin(user)


def build_section_code(section_name: str) -> str:
    tokens = [token for token in "".join(ch if ch.isalnum() else " " for ch in section_name.upper()).split() if token]
    if not tokens:
        return "SURAT"
    return "".join(token[0] if token.isalpha() else token for token in tokens)[:12]


def generate_agenda_number(db: Session, section_name: str) -> str:
    code = build_section_code(section_name)
    today_stamp = datetime.now().strftime("%Y%m%d")
    prefix = f"AGD/{code}/{today_stamp}/"
    existing_count = (
        db.query(models.DocumentSubmission)
        .filter(models.DocumentSubmission.agenda_number.like(f"{prefix}%"))
        .count()
    )
    return f"{prefix}{existing_count + 1:04d}"


def get_submission_progress_label(submission: models.DocumentSubmission) -> str:
    if submission.status == "PENOMORAN_AGENDA":
        return "Menunggu tindakan OA untuk distribusi ke PIC atau Staff"
    if submission.status == "VERIFIKASI_PETUGAS":
        return f"Menunggu verifikasi PIC seksi {submission.assigned_section or submission.bagian}"
    if submission.status == "PENELITIAN_DOKUMEN":
        return f"Sedang diteliti staff seksi {submission.assigned_section or submission.bagian}"
    if submission.status == "PENOLAKAN":
        return "Surat ditolak petugas, pengguna jasa harus unggah surat baru"
    if submission.status == "SELESAI":
        return "Proses surat telah selesai"
    return submission.status


def can_operate_on_section(user: models.User | None, section_name: str | None) -> bool:
    if is_super_admin(user):
        return True
    if not user:
        return False
    if get_staff_function(user) == STAFF_ROLE_STAFF_KK:
        return True
    if not section_name:
        return True
    return (user.section_name or "").strip() == section_name.strip()


def build_admin_dashboard_context(
    request: Request,
    current_user: models.User,
    db: Session,
    selected_status: str = "",
):
    query = db.query(models.DocumentSubmission).join(models.User)
    if selected_status:
        query = query.filter(models.DocumentSubmission.status == selected_status)

    submissions = query.order_by(models.DocumentSubmission.created_at.desc()).all()
    return {
        "request": request,
        "app_name": "Sistem Pengajuan Dokumen",
        "current_user": current_user,
        "submissions": submissions,
        "status_labels": STATUS_LABELS,
        "valid_statuses": VALID_STATUSES,
        "selected_status": selected_status,
        "staff_function": get_staff_function(current_user),
        "can_route_document": can_route_document(current_user),
        "can_verify_document": can_verify_document(current_user),
        "can_upload_response_document": can_upload_response_document(current_user),
        "can_complete_document": can_complete_document(current_user),
        "can_monitor_document": can_monitor_document(current_user),
        "submission_progress_label": get_submission_progress_label,
        "waiting_distribution_count": db.query(models.DocumentSubmission)
        .filter(models.DocumentSubmission.status == "PENOMORAN_AGENDA")
        .count(),
        "waiting_pic_count": db.query(models.DocumentSubmission)
        .filter(models.DocumentSubmission.status == "VERIFIKASI_PETUGAS")
        .count(),
        "waiting_staff_count": db.query(models.DocumentSubmission)
        .filter(models.DocumentSubmission.status == "PENELITIAN_DOKUMEN")
        .count(),
    }


def build_admin_user_management_context(
    request: Request,
    current_user: models.User,
    db: Session,
    user_scope: str = "service_user",
    selected_status: str = "",
    message: str | None = None,
):
    is_internal_scope = user_scope == "internal"
    query = db.query(models.User)
    if is_internal_scope:
        query = query.filter(models.User.role.in_(tuple(INTERNAL_ROLES)))
    else:
        query = query.filter(models.User.role == SERVICE_USER_ROLE)
    if selected_status:
        query = query.filter(models.User.account_status == selected_status)

    users = query.order_by(models.User.created_at.desc()).all()
    return {
        "request": request,
        "app_name": "Sistem Pengajuan Dokumen",
        "current_user": current_user,
        "users": users,
        "user_scope": user_scope,
        "user_scope_options": USER_SCOPE_OPTIONS,
        "page_title": "Daftar Pendaftar Pengguna Jasa" if not is_internal_scope else "Daftar Akun Petugas",
        "page_description": "Pantau semua akun yang baru mendaftar, fokuskan antrean pada akun berstatus pending, lalu approve atau nonaktifkan langsung dari panel admin."
        if not is_internal_scope
        else "Kelola akun petugas berdasarkan jenis akun admin/super admin, lalu atur role kerja dan seksi secara terpisah agar data internal lebih rapi.",
        "valid_account_statuses": VALID_ACCOUNT_STATUSES,
        "selected_status": selected_status,
        "account_status_labels": ACCOUNT_STATUS_LABELS,
        "message": message,
        "can_approve_user": is_admin_user(current_user),
        "can_deactivate_user": is_super_admin(current_user),
        "can_edit_user": is_super_admin(current_user),
        "can_manage_internal_users": is_super_admin(current_user),
        "pending_count": db.query(models.User)
        .filter(
            models.User.role == SERVICE_USER_ROLE,
            models.User.account_status == ACCOUNT_PENDING,
        )
        .count(),
        "internal_count": db.query(models.User)
        .filter(models.User.role.in_(tuple(INTERNAL_ROLES)))
        .count(),
    }


def build_admin_user_detail_context(
    request: Request,
    current_user: models.User,
    managed_user: models.User,
    *,
    message: str | None = None,
    error: str | None = None,
):
    return {
        "request": request,
        "app_name": "Sistem Pengajuan Dokumen",
        "current_user": current_user,
        "managed_user": managed_user,
        "account_status_labels": ACCOUNT_STATUS_LABELS,
        "valid_account_statuses": VALID_ACCOUNT_STATUSES,
        "internal_account_type_options": INTERNAL_ACCOUNT_TYPE_OPTIONS,
        "internal_staff_role_options": INTERNAL_STAFF_ROLE_OPTIONS,
        "super_admin_staff_role_label": SUPER_ADMIN_STAFF_ROLE_LABEL,
        "internal_section_options": INTERNAL_SECTION_OPTIONS,
        "is_service_user_target": managed_user.role == SERVICE_USER_ROLE,
        "message": message,
        "error": error,
        "can_approve_user": is_admin_user(current_user),
        "can_deactivate_user": is_super_admin(current_user),
        "can_change_password": is_super_admin(current_user),
        "can_edit_user": is_super_admin(current_user),
    }


def generate_document_id() -> str:
    return f"DOC-{datetime.now().strftime('%Y%m%d')}-{uuid4().hex[:8].upper()}"


def validate_pdf_upload(file: UploadFile, contents: bytes) -> str | None:
    filename = file.filename or ""
    if not filename.lower().endswith(".pdf") or file.content_type not in {"application/pdf", "application/octet-stream"}:
        return "Hanya file PDF yang diperbolehkan."

    if len(contents) > MAX_UPLOAD_SIZE:
        return "Ukuran PDF harus 5 MB atau lebih kecil."

    if not contents.startswith(b"%PDF"):
        return "File yang diunggah bukan PDF yang valid."

    return None


@app.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    if is_internal_user(current_user):
        return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "index.html", build_home_context(request, db))


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login/pengguna-jasa", status_code=status.HTTP_303_SEE_OTHER)
    if not is_service_user(current_user):
        return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        build_dashboard_context(request, current_user, db),
    )


@app.get("/admin/dashboard", response_class=HTMLResponse)
def admin_dashboard(
    request: Request,
    status_filter: str = "",
    db: Session = Depends(get_db),
):
    current_user = get_admin_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login/petugas", status_code=status.HTTP_303_SEE_OTHER)

    selected_status = status_filter if status_filter in VALID_STATUSES else ""
    return templates.TemplateResponse(
        request,
        "admin_dashboard.html",
        build_admin_dashboard_context(request, current_user, db, selected_status),
    )


@app.get("/admin/users", response_class=HTMLResponse)
def admin_users(
    request: Request,
    scope: str = "service_user",
    status_filter: str = "",
    message: str = "",
    db: Session = Depends(get_db),
):
    current_user = get_admin_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login/petugas", status_code=status.HTTP_303_SEE_OTHER)
    require_admin_role(current_user)

    selected_scope = scope if scope in USER_SCOPE_OPTIONS else "service_user"
    if selected_scope == "internal" and not is_super_admin(current_user):
        selected_scope = "service_user"
    selected_status = status_filter if status_filter in VALID_ACCOUNT_STATUSES else ""
    notice = message.strip() or None
    return templates.TemplateResponse(
        request,
        "admin_users.html",
        build_admin_user_management_context(request, current_user, db, selected_scope, selected_status, notice),
    )


@app.get("/profile", response_class=HTMLResponse)
def profile_page(
    request: Request,
    message: str = "",
    error: str = "",
    db: Session = Depends(get_db),
):
    current_user = get_current_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login/pengguna-jasa", status_code=status.HTTP_303_SEE_OTHER)

    return templates.TemplateResponse(
        request,
        "profile.html",
        build_profile_context(
            request,
            current_user,
            message=message.strip() or None,
            error=error.strip() or None,
        ),
    )


@app.post("/profile/password")
def update_own_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db),
):
    current_user = get_current_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login/pengguna-jasa", status_code=status.HTTP_303_SEE_OTHER)

    if not verify_password(current_password, current_user.password_hash):
        return RedirectResponse(
            url="/profile?error=Kata+sandi+saat+ini+tidak+sesuai",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    if len(new_password) < 8:
        return RedirectResponse(
            url="/profile?error=Kata+sandi+baru+minimal+8+karakter",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    if new_password != confirm_password:
        return RedirectResponse(
            url="/profile?error=Konfirmasi+kata+sandi+baru+tidak+cocok",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    current_user.password_hash = hash_password(new_password)
    db.commit()
    log_audit_event(db, request, current_user.id, "verify", f"PASSWORD-{current_user.id}")

    return RedirectResponse(
        url="/profile?message=Kata+sandi+berhasil+diubah",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.get("/admin/users/{user_id}", response_class=HTMLResponse)
def admin_user_detail(
    user_id: int,
    request: Request,
    message: str = "",
    error: str = "",
    db: Session = Depends(get_db),
):
    current_user = get_admin_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login/petugas", status_code=status.HTTP_303_SEE_OTHER)
    require_admin_role(current_user)

    managed_user = get_managed_user_for_admin(db, user_id, allow_internal=is_super_admin(current_user))
    if not managed_user:
        return RedirectResponse(url="/admin/users", status_code=status.HTTP_303_SEE_OTHER)
    if managed_user.role != SERVICE_USER_ROLE:
        require_super_admin_role(current_user)

    return templates.TemplateResponse(
        request,
        "admin_user_detail.html",
        build_admin_user_detail_context(
            request,
            current_user,
            managed_user,
            message=message.strip() or None,
            error=error.strip() or None,
        ),
    )


@app.get("/documents/{document_id}", response_class=HTMLResponse)
def document_detail(document_id: str, request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login/pengguna-jasa", status_code=status.HTTP_303_SEE_OTHER)
    if not is_service_user(current_user):
        return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    submission = (
        db.query(models.DocumentSubmission)
        .filter(
            models.DocumentSubmission.document_id == document_id,
            models.DocumentSubmission.user_id == current_user.id,
        )
        .first()
    )
    if not submission:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    return templates.TemplateResponse(
        request,
        "document_detail.html",
        {
            "request": request,
            "app_name": "Sistem Pengajuan Dokumen",
            "current_user": current_user,
            "submission": submission,
            "status_labels": STATUS_LABELS,
        },
    )


@app.get("/documents/{document_id}/result")
def download_result_document(document_id: str, request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login/pengguna-jasa", status_code=status.HTTP_303_SEE_OTHER)
    if not is_service_user(current_user):
        return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    submission = (
        db.query(models.DocumentSubmission)
        .filter(
            models.DocumentSubmission.document_id == document_id,
            models.DocumentSubmission.user_id == current_user.id,
        )
        .first()
    )
    if not submission or not submission.result_stored_filename:
        return RedirectResponse(url=f"/documents/{document_id}", status_code=status.HTTP_303_SEE_OTHER)

    result_path = OUTPUTS_DIR / submission.result_stored_filename
    if not result_path.exists():
        return RedirectResponse(url=f"/documents/{document_id}", status_code=status.HTTP_303_SEE_OTHER)

    log_audit_event(db, request, current_user.id, "download", submission.document_id)
    return FileResponse(
        path=result_path,
        media_type="application/pdf",
        filename=submission.result_original_filename or submission.result_stored_filename,
    )


@app.get("/documents/{document_id}/receipt")
def download_receipt_document(document_id: str, request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login/pengguna-jasa", status_code=status.HTTP_303_SEE_OTHER)
    if not is_service_user(current_user):
        return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    submission = (
        db.query(models.DocumentSubmission)
        .filter(
            models.DocumentSubmission.document_id == document_id,
            models.DocumentSubmission.user_id == current_user.id,
        )
        .first()
    )
    if not submission or not submission.receipt_stored_filename:
        return RedirectResponse(url=f"/documents/{document_id}", status_code=status.HTTP_303_SEE_OTHER)

    receipt_path = OUTPUTS_DIR / submission.receipt_stored_filename
    if not receipt_path.exists():
        return RedirectResponse(url=f"/documents/{document_id}", status_code=status.HTTP_303_SEE_OTHER)

    log_audit_event(db, request, current_user.id, "download", submission.document_id)
    return FileResponse(
        path=receipt_path,
        media_type="application/pdf",
        filename=submission.receipt_original_filename or submission.receipt_stored_filename,
    )


@app.get("/admin/documents/{document_id}/file")
def download_admin_original_document(document_id: str, request: Request, db: Session = Depends(get_db)):
    current_user = get_admin_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login/petugas", status_code=status.HTTP_303_SEE_OTHER)

    submission = (
        db.query(models.DocumentSubmission)
        .filter(models.DocumentSubmission.document_id == document_id)
        .first()
    )
    if not submission or not submission.stored_filename:
        return RedirectResponse(url=f"/admin/documents/{document_id}", status_code=status.HTTP_303_SEE_OTHER)

    upload_path = UPLOADS_DIR / submission.stored_filename
    if not upload_path.exists():
        return RedirectResponse(url=f"/admin/documents/{document_id}", status_code=status.HTTP_303_SEE_OTHER)

    log_audit_event(db, request, current_user.id, "download", submission.document_id)
    return FileResponse(
        path=upload_path,
        media_type="application/pdf",
        filename=submission.original_filename or submission.stored_filename,
    )


@app.get("/admin/documents/{document_id}/result")
def download_admin_result_document(document_id: str, request: Request, db: Session = Depends(get_db)):
    current_user = get_admin_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login/petugas", status_code=status.HTTP_303_SEE_OTHER)

    submission = (
        db.query(models.DocumentSubmission)
        .filter(models.DocumentSubmission.document_id == document_id)
        .first()
    )
    if not submission or not submission.result_stored_filename:
        return RedirectResponse(url=f"/admin/documents/{document_id}", status_code=status.HTTP_303_SEE_OTHER)

    result_path = OUTPUTS_DIR / submission.result_stored_filename
    if not result_path.exists():
        return RedirectResponse(url=f"/admin/documents/{document_id}", status_code=status.HTTP_303_SEE_OTHER)

    log_audit_event(db, request, current_user.id, "download", submission.document_id)
    return FileResponse(
        path=result_path,
        media_type="application/pdf",
        filename=submission.result_original_filename or submission.result_stored_filename,
    )


@app.get("/admin/documents/{document_id}", response_class=HTMLResponse)
def admin_document_detail(document_id: str, request: Request, db: Session = Depends(get_db)):
    current_user = get_admin_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login/petugas", status_code=status.HTTP_303_SEE_OTHER)

    submission = (
        db.query(models.DocumentSubmission)
        .join(models.User)
        .filter(models.DocumentSubmission.document_id == document_id)
        .first()
    )
    if not submission:
        return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    return templates.TemplateResponse(
        request,
        "admin_document_detail.html",
        {
            "request": request,
            "app_name": "Sistem Pengajuan Dokumen",
            "current_user": current_user,
            "submission": submission,
            "status_labels": STATUS_LABELS,
            "upload_error": None,
            "staff_function": get_staff_function(current_user),
            "submission_progress": get_submission_progress_label(submission),
            "can_route_document": can_route_document(current_user),
            "can_verify_document": can_verify_document(current_user),
            "can_upload_response_document": can_upload_response_document(current_user),
            "can_complete_document": can_complete_document(current_user),
            "can_download_original": True,
            "can_download_result": bool(submission.result_stored_filename),
            "internal_section_options": INTERNAL_SECTION_OPTIONS,
        },
    )


def get_service_user_for_admin(db: Session, user_id: int) -> models.User | None:
    return (
        db.query(models.User)
        .filter(
            models.User.id == user_id,
            models.User.role == SERVICE_USER_ROLE,
        )
        .first()
    )


def get_managed_user_for_admin(
    db: Session,
    user_id: int,
    *,
    allow_internal: bool = False,
) -> models.User | None:
    query = db.query(models.User).filter(models.User.id == user_id)
    if allow_internal:
        query = query.filter(
            (models.User.role == SERVICE_USER_ROLE) | models.User.role.in_(tuple(INTERNAL_ROLES))
        )
    else:
        query = query.filter(models.User.role == SERVICE_USER_ROLE)
    return query.first()


@app.post("/admin/users/{user_id}/approve")
def approve_service_user(user_id: int, request: Request, db: Session = Depends(get_db)):
    current_user = get_admin_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login/petugas", status_code=status.HTTP_303_SEE_OTHER)
    require_admin_role(current_user)

    service_user = get_service_user_for_admin(db, user_id)
    if service_user:
        service_user.account_status = ACCOUNT_ACTIVE
        db.commit()
        log_audit_event(db, request, current_user.id, "verify", f"USER-{service_user.id}")

    return RedirectResponse(
        url="/admin/users?message=Akun+berhasil+diaktifkan",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.post("/admin/users/{user_id}/deactivate")
def deactivate_service_user(user_id: int, request: Request, db: Session = Depends(get_db)):
    current_user = get_admin_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login/petugas", status_code=status.HTTP_303_SEE_OTHER)
    require_super_admin_role(current_user)

    service_user = get_service_user_for_admin(db, user_id)
    if service_user:
        service_user.account_status = ACCOUNT_DEACTIVATED
        db.commit()
        log_audit_event(db, request, current_user.id, "verify", f"USER-{service_user.id}")

    return RedirectResponse(
        url="/admin/users?message=Status+akun+berhasil+dinonaktifkan",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.post("/admin/users/{user_id}/update")
def update_managed_user(
    user_id: int,
    request: Request,
    username: str = Form(""),
    company_name: str = Form(""),
    email: str = Form(...),
    business_id: str = Form(""),
    pic_name: str = Form(...),
    account_type: str = Form(""),
    staff_role: str = Form(""),
    section_name: str = Form(""),
    account_status: str = Form(...),
    db: Session = Depends(get_db),
):
    current_user = get_admin_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login/petugas", status_code=status.HTTP_303_SEE_OTHER)
    require_super_admin_role(current_user)

    managed_user = get_managed_user_for_admin(db, user_id, allow_internal=True)
    if not managed_user:
        return RedirectResponse(url="/admin/users", status_code=status.HTTP_303_SEE_OTHER)

    username = username.strip().lower()
    company_name = company_name.strip()
    email = email.strip().lower()
    business_id = business_id.strip()
    pic_name = pic_name.strip()
    account_type = account_type.strip()
    staff_role = staff_role.strip()
    section_name = section_name.strip()
    account_status = account_status.strip()

    if not email or "@" not in email:
        return RedirectResponse(
            url=f"/admin/users/{user_id}?error=Email+tidak+valid",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    if not pic_name:
        return RedirectResponse(
            url=f"/admin/users/{user_id}?error=Nama+wajib+diisi",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    if account_status not in VALID_ACCOUNT_STATUSES:
        return RedirectResponse(
            url=f"/admin/users/{user_id}?error=Status+akun+tidak+valid",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    if managed_user.role == SERVICE_USER_ROLE:
        if not company_name or not business_id:
            return RedirectResponse(
                url=f"/admin/users/{user_id}?error=Nama+perusahaan+dan+nomor+izin%2FNIB%2FNPWP+wajib+diisi",
                status_code=status.HTTP_303_SEE_OTHER,
            )
    else:
        if not username:
            return RedirectResponse(
                url=f"/admin/users/{user_id}?error=Username+petugas+wajib+diisi",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        if account_type not in INTERNAL_ACCOUNT_TYPE_OPTIONS:
            return RedirectResponse(
                url=f"/admin/users/{user_id}?error=Jenis+akun+petugas+tidak+valid",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        if account_type == "super_admin":
            staff_role = SUPER_ADMIN_STAFF_ROLE_LABEL
        elif not staff_role:
            staff_role = DEFAULT_INTERNAL_STAFF_ROLE
        elif staff_role not in INTERNAL_STAFF_ROLE_OPTIONS:
            return RedirectResponse(
                url=f"/admin/users/{user_id}?error=Admin+wajib+memiliki+satu+role+kerja+yang+valid",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        if section_name and section_name not in INTERNAL_SECTION_OPTIONS:
            return RedirectResponse(
                url=f"/admin/users/{user_id}?error=Seksi+petugas+tidak+valid",
                status_code=status.HTTP_303_SEE_OTHER,
            )

    existing_email_user = db.query(models.User).filter(models.User.email == email, models.User.id != managed_user.id).first()
    if existing_email_user:
        return RedirectResponse(
            url=f"/admin/users/{user_id}?error=Email+sudah+digunakan+akun+lain",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    if managed_user.role != SERVICE_USER_ROLE:
        existing_username_user = (
            db.query(models.User)
            .filter(models.User.username == username, models.User.id != managed_user.id)
            .first()
        )
        if existing_username_user:
            return RedirectResponse(
                url=f"/admin/users/{user_id}?error=Username+sudah+digunakan+akun+lain",
                status_code=status.HTTP_303_SEE_OTHER,
            )

    managed_user.email = email
    managed_user.pic_name = pic_name
    managed_user.account_status = account_status
    if managed_user.role == SERVICE_USER_ROLE:
        managed_user.company_name = company_name
        managed_user.business_id = business_id
    else:
        managed_user.username = username
        managed_user.role = account_type
        managed_user.staff_role = staff_role or None
        managed_user.section_name = section_name or None

    db.commit()
    log_audit_event(db, request, current_user.id, "verify", f"EDIT-USER-{managed_user.id}")

    target_scope = "service_user" if managed_user.role == SERVICE_USER_ROLE else "internal"
    return RedirectResponse(
        url=f"/admin/users/{user_id}?message=Data+akun+berhasil+diperbarui&scope={target_scope}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.post("/admin/users/{user_id}/password")
def update_service_user_password(
    user_id: int,
    request: Request,
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db),
):
    current_user = get_admin_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login/petugas", status_code=status.HTTP_303_SEE_OTHER)
    require_super_admin_role(current_user)

    managed_user = get_managed_user_for_admin(db, user_id, allow_internal=True)
    if not managed_user:
        return RedirectResponse(url="/admin/users", status_code=status.HTTP_303_SEE_OTHER)

    if len(new_password) < 8:
        return RedirectResponse(
            url=f"/admin/users/{user_id}?error=Kata+sandi+baru+minimal+8+karakter",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    if new_password != confirm_password:
        return RedirectResponse(
            url=f"/admin/users/{user_id}?error=Konfirmasi+kata+sandi+baru+tidak+cocok",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    managed_user.password_hash = hash_password(new_password)
    db.commit()
    log_audit_event(db, request, current_user.id, "verify", f"PASSWORD-{managed_user.id}")

    success_label = "pengguna jasa" if managed_user.role == SERVICE_USER_ROLE else "petugas"
    return RedirectResponse(
        url=f"/admin/users/{user_id}?message=Kata+sandi+{success_label}+berhasil+diubah",
        status_code=status.HTTP_303_SEE_OTHER,
    )


def get_internal_submission(db: Session, document_id: str) -> models.DocumentSubmission | None:
    return (
        db.query(models.DocumentSubmission)
        .join(models.User)
        .filter(models.DocumentSubmission.document_id == document_id)
        .first()
    )


@app.post("/admin/documents/{document_id}/distribute")
def distribute_document(
    document_id: str,
    request: Request,
    target_staff_role: str = Form(...),
    section_name: str = Form(...),
    db: Session = Depends(get_db),
):
    current_user = get_admin_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login/petugas", status_code=status.HTTP_303_SEE_OTHER)
    if not can_route_document(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Hanya OA atau super admin yang dapat mendistribusikan surat.")

    submission = get_internal_submission(db, document_id)
    if not submission:
        return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    cleaned_target = target_staff_role.strip()
    cleaned_section = section_name.strip()
    if cleaned_target not in {STAFF_ROLE_PIC, STAFF_ROLE_STAFF}:
        return RedirectResponse(url=f"/admin/documents/{document_id}", status_code=status.HTTP_303_SEE_OTHER)
    if cleaned_section not in INTERNAL_SECTION_OPTIONS:
        return RedirectResponse(url=f"/admin/documents/{document_id}", status_code=status.HTTP_303_SEE_OTHER)
    if submission.status in {"PENOLAKAN", "SELESAI"}:
        return RedirectResponse(url=f"/admin/documents/{document_id}", status_code=status.HTTP_303_SEE_OTHER)

    submission.assigned_section = cleaned_section
    submission.assigned_staff_role = cleaned_target
    submission.admin_notes = None
    if cleaned_target == STAFF_ROLE_PIC:
        submission.status = "VERIFIKASI_PETUGAS"
        submission.agenda_number = None
    else:
        submission.status = "PENELITIAN_DOKUMEN"
        submission.agenda_number = generate_agenda_number(db, cleaned_section)

    db.commit()
    log_audit_event(db, request, current_user.id, "verify", submission.document_id)
    return RedirectResponse(url=f"/admin/documents/{document_id}", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/documents/{document_id}/verify-accept")
def verify_document_accept(document_id: str, request: Request, db: Session = Depends(get_db)):
    current_user = get_admin_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login/petugas", status_code=status.HTTP_303_SEE_OTHER)
    if not can_verify_document(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Hanya PIC atau super admin yang dapat memverifikasi surat.")

    submission = get_internal_submission(db, document_id)
    if not submission:
        return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    if submission.status != "VERIFIKASI_PETUGAS":
        return RedirectResponse(url=f"/admin/documents/{document_id}", status_code=status.HTTP_303_SEE_OTHER)
    if not can_operate_on_section(current_user, submission.assigned_section):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="PIC hanya dapat memverifikasi surat pada seksinya.")

    submission.status = "PENELITIAN_DOKUMEN"
    submission.assigned_staff_role = STAFF_ROLE_STAFF
    submission.agenda_number = submission.agenda_number or generate_agenda_number(db, submission.assigned_section or submission.bagian)
    submission.admin_notes = None
    db.commit()
    log_audit_event(db, request, current_user.id, "verify", submission.document_id)
    return RedirectResponse(url=f"/admin/documents/{document_id}", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/documents/{document_id}/reject")
def reject_document(
    document_id: str,
    request: Request,
    notes: str = Form(...),
    db: Session = Depends(get_db),
):
    current_user = get_admin_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login/petugas", status_code=status.HTTP_303_SEE_OTHER)
    if not (can_route_document(current_user) or can_verify_document(current_user)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Hanya OA, PIC, atau super admin yang dapat menolak surat.")

    submission = get_internal_submission(db, document_id)
    if not submission:
        return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    if submission.status not in {"PENOMORAN_AGENDA", "VERIFIKASI_PETUGAS"}:
        return RedirectResponse(url=f"/admin/documents/{document_id}", status_code=status.HTTP_303_SEE_OTHER)
    if can_verify_document(current_user) and not can_operate_on_section(current_user, submission.assigned_section):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="PIC hanya dapat menolak surat pada seksinya.")

    cleaned_notes = notes.strip()
    if cleaned_notes:
        submission.status = "PENOLAKAN"
        submission.admin_notes = cleaned_notes
        submission.assigned_staff_role = get_staff_function(current_user) or submission.assigned_staff_role
        submission.agenda_number = None
        db.commit()
        log_audit_event(db, request, current_user.id, "verify", submission.document_id)

    return RedirectResponse(url=f"/admin/documents/{document_id}", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/documents/{document_id}/result", response_class=HTMLResponse)
async def upload_result_document(
    document_id: str,
    request: Request,
    result_file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    current_user = get_admin_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login/petugas", status_code=status.HTTP_303_SEE_OTHER)
    if not can_upload_response_document(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Hanya Staff atau super admin yang dapat mengunggah surat jawaban.")

    submission = get_internal_submission(db, document_id)
    if not submission:
        return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    if submission.status != "PENELITIAN_DOKUMEN":
        return RedirectResponse(url=f"/admin/documents/{document_id}", status_code=status.HTTP_303_SEE_OTHER)
    if not can_operate_on_section(current_user, submission.assigned_section):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Staff hanya dapat mengunggah jawaban untuk surat pada seksinya.")

    contents = await result_file.read()
    validation_error = validate_pdf_upload(result_file, contents)
    if validation_error:
        return templates.TemplateResponse(
            request,
            "admin_document_detail.html",
            {
                "request": request,
                "app_name": "Sistem Pengajuan Dokumen",
                "current_user": current_user,
                "submission": submission,
                "status_labels": STATUS_LABELS,
                "upload_error": validation_error,
                "staff_function": get_staff_function(current_user),
                "submission_progress": get_submission_progress_label(submission),
                "can_route_document": can_route_document(current_user),
                "can_verify_document": can_verify_document(current_user),
                "can_upload_response_document": can_upload_response_document(current_user),
                "can_complete_document": can_complete_document(current_user),
                "can_download_original": True,
                "can_download_result": bool(submission.result_stored_filename),
                "internal_section_options": INTERNAL_SECTION_OPTIONS,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    stored_filename = f"{document_id}-result-{uuid4().hex}.pdf"
    output_path = OUTPUTS_DIR / stored_filename
    output_path.write_bytes(contents)

    submission.result_original_filename = result_file.filename or "result.pdf"
    submission.result_stored_filename = stored_filename
    submission.status = "SELESAI"
    db.commit()

    return RedirectResponse(
        url=f"/admin/documents/{document_id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.post("/admin/documents/{document_id}/complete")
def complete_document(document_id: str, request: Request, db: Session = Depends(get_db)):
    current_user = get_admin_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login/petugas", status_code=status.HTTP_303_SEE_OTHER)
    if not can_complete_document(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Hanya Staff, Staff KK, atau super admin yang dapat menyelesaikan surat.")

    submission = get_internal_submission(db, document_id)
    if not submission:
        return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    if submission.status != "PENELITIAN_DOKUMEN":
        return RedirectResponse(url=f"/admin/documents/{document_id}", status_code=status.HTTP_303_SEE_OTHER)
    if not can_operate_on_section(current_user, submission.assigned_section):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Staff hanya dapat menyelesaikan surat pada seksinya.")

    submission.status = "SELESAI"
    db.commit()
    log_audit_event(db, request, current_user.id, "verify", submission.document_id)
    return RedirectResponse(url=f"/admin/documents/{document_id}", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/documents/upload", response_class=HTMLResponse)
async def upload_document(
    request: Request,
    bagian: str = Form(...),
    subject: str = Form(...),
    document_date: str = Form(...),
    description: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    current_user = get_current_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login/pengguna-jasa", status_code=status.HTTP_303_SEE_OTHER)
    if not is_service_user(current_user):
        return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    bagian = bagian.strip()
    subject = subject.strip()
    description = description.strip()
    form_data = {
        "bagian": bagian or DEFAULT_BAGIAN,
        "subject": subject,
        "document_date": document_date,
        "description": description,
    }

    if bagian not in VALID_BAGIAN_OPTIONS:
        context = build_home_context(request, db, error="Silakan pilih bagian yang valid.", form_data=form_data)
        return templates.TemplateResponse(request, "index.html", context, status_code=status.HTTP_400_BAD_REQUEST)

    if not subject or not description:
        context = build_home_context(
            request,
            db,
            error="Perihal dan deskripsi wajib diisi.",
            form_data=form_data,
        )
        return templates.TemplateResponse(request, "index.html", context, status_code=status.HTTP_400_BAD_REQUEST)

    try:
        parsed_date = datetime.strptime(document_date, "%Y-%m-%d").date()
    except ValueError:
        context = build_home_context(
            request,
            db,
            error="Silakan isi tanggal dokumen yang valid.",
            form_data=form_data,
        )
        return templates.TemplateResponse(request, "index.html", context, status_code=status.HTTP_400_BAD_REQUEST)

    contents = await file.read()
    validation_error = validate_pdf_upload(file, contents)
    if validation_error:
        context = build_home_context(request, db, error=validation_error, form_data=form_data)
        return templates.TemplateResponse(request, "index.html", context, status_code=status.HTTP_400_BAD_REQUEST)

    document_id = generate_document_id()
    stored_filename = f"{document_id}-{uuid4().hex}.pdf"
    upload_path = UPLOADS_DIR / stored_filename
    upload_path.write_bytes(contents)

    submission_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    receipt_stored_filename = f"{document_id}-receipt.pdf"
    receipt_path = OUTPUTS_DIR / receipt_stored_filename
    generate_submission_receipt(
        output_path=receipt_path,
        document_id=document_id,
        username=current_user.username,
        bagian=bagian,
        document_date=parsed_date.strftime("%Y-%m-%d"),
        subject=subject,
        status="PENOMORAN_AGENDA",
        timestamp=submission_timestamp,
    )

    submission = models.DocumentSubmission(
        user_id=current_user.id,
        document_id=document_id,
        bagian=bagian,
        subject=subject,
        document_date=parsed_date,
        description=description,
        original_filename=file.filename or "dokumen.pdf",
        stored_filename=stored_filename,
        receipt_original_filename=f"receipt-{document_id}.pdf",
        receipt_stored_filename=receipt_stored_filename,
        status="PENOMORAN_AGENDA",
        assigned_section=bagian,
        assigned_staff_role=STAFF_ROLE_OA,
    )
    db.add(submission)
    db.commit()
    log_audit_event(db, request, current_user.id, "upload", submission.document_id)

    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
