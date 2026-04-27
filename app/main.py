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
    INTERNAL_SECTION_OPTIONS,
    MONITORING_ROLES,
    SERVICE_USER_ROLE,
    get_current_user,
    hash_password,
    is_admin_user,
    is_monitoring_user,
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
    "DIAJUKAN": "status-submitted",
    "DIVERIFIKASI": "status-verified",
    "DITOLAK": "status-rejected",
    "DITERIMA": "status-accepted",
    "DIPROSES": "status-processing",
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
INTERNAL_STAFF_ROLE_OPTIONS = ("OA", "Monitoring", "PIC", "Staff")

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
    if not is_monitoring_user(current_user):
        return None
    return current_user


def require_admin_role(user: models.User | None) -> None:
    if not is_admin_user(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Akses admin diperlukan.")


def require_super_admin_role(user: models.User | None) -> None:
    if not is_super_admin(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Akses super admin diperlukan.")


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
        query = query.filter(models.User.role.in_(tuple(MONITORING_ROLES)))
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
        "can_manage_internal_users": is_super_admin(current_user),
        "pending_count": db.query(models.User)
        .filter(
            models.User.role == SERVICE_USER_ROLE,
            models.User.account_status == ACCOUNT_PENDING,
        )
        .count(),
        "internal_count": db.query(models.User)
        .filter(models.User.role.in_(tuple(MONITORING_ROLES)))
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
    if is_monitoring_user(current_user):
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
    require_admin_role(current_user)

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
            "can_reject_document": True,
            "can_approve_document": is_admin_user(current_user),
            "can_process_document": is_admin_user(current_user),
            "can_upload_result": is_admin_user(current_user),
            "can_download_original": is_admin_user(current_user),
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
            (models.User.role == SERVICE_USER_ROLE) | models.User.role.in_(tuple(MONITORING_ROLES))
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
        if staff_role and staff_role not in INTERNAL_STAFF_ROLE_OPTIONS:
            return RedirectResponse(
                url=f"/admin/users/{user_id}?error=Role+kerja+petugas+tidak+valid",
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


@app.post("/admin/documents/{document_id}/approve")
def approve_document(document_id: str, request: Request, db: Session = Depends(get_db)):
    current_user = get_admin_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login/petugas", status_code=status.HTTP_303_SEE_OTHER)
    require_admin_role(current_user)

    submission = (
        db.query(models.DocumentSubmission)
        .filter(models.DocumentSubmission.document_id == document_id)
        .first()
    )
    if submission:
        submission.status = "DITERIMA"
        submission.admin_notes = None
        db.commit()
        log_audit_event(db, request, current_user.id, "verify", submission.document_id)

    return RedirectResponse(
        url=f"/admin/documents/{document_id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.post("/admin/documents/{document_id}/process")
def process_document(document_id: str, request: Request, db: Session = Depends(get_db)):
    current_user = get_admin_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login/petugas", status_code=status.HTTP_303_SEE_OTHER)
    require_admin_role(current_user)

    submission = (
        db.query(models.DocumentSubmission)
        .filter(models.DocumentSubmission.document_id == document_id)
        .first()
    )
    if submission:
        submission.status = "DIPROSES"
        db.commit()
        log_audit_event(db, request, current_user.id, "verify", submission.document_id)

    return RedirectResponse(
        url=f"/admin/documents/{document_id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


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

    submission = (
        db.query(models.DocumentSubmission)
        .filter(models.DocumentSubmission.document_id == document_id)
        .first()
    )
    cleaned_notes = notes.strip()
    if submission and cleaned_notes:
        submission.status = "DITOLAK"
        submission.admin_notes = cleaned_notes
        db.commit()
        log_audit_event(db, request, current_user.id, "verify", submission.document_id)

    return RedirectResponse(
        url=f"/admin/documents/{document_id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


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
    require_admin_role(current_user)

    submission = (
        db.query(models.DocumentSubmission)
        .join(models.User)
        .filter(models.DocumentSubmission.document_id == document_id)
        .first()
    )
    if not submission:
        return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)

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
        status="DIAJUKAN",
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
        status="DIAJUKAN",
    )
    db.add(submission)
    db.commit()
    log_audit_event(db, request, current_user.id, "upload", submission.document_id)

    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
