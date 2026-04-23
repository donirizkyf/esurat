import os

import bcrypt
from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import or_, func
from sqlalchemy.orm import Session

from app.audit import log_audit_event
from app.database import get_db
from app.models import User


router = APIRouter(tags=["authentication"])

SERVICE_USER_ROLE = "service_user"
MONITORING_ROLES = {"monitoring", "admin", "super_admin"}
ADMIN_ROLES = {"admin", "super_admin"}
SELF_REGISTRATION_ROLES = {
    SERVICE_USER_ROLE,
    "monitoring",
    "admin",
    "super_admin",
}
INTERNAL_REGISTRATION_ROLES = MONITORING_ROLES
ACCOUNT_ACTIVE = "ACTIVE"
ACCOUNT_PENDING = "PENDING"
ACCOUNT_DEACTIVATED = "DEACTIVATED"


def get_templates(request: Request) -> Jinja2Templates:
    return request.app.state.templates


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def get_current_user(request: Request, db: Session) -> User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return db.query(User).filter(User.id == user_id).first()


def is_service_user(user: User | None) -> bool:
    return bool(user and user.role == SERVICE_USER_ROLE)


def is_monitoring_user(user: User | None) -> bool:
    return bool(user and user.role in MONITORING_ROLES)


def is_admin_user(user: User | None) -> bool:
    return bool(user and user.role in ADMIN_ROLES)


def is_super_admin(user: User | None) -> bool:
    return bool(user and user.role == "super_admin")


def get_registration_status() -> str:
    return ACCOUNT_PENDING


def normalize_internal_username(value: str) -> str:
    return value.strip().lower()


def get_internal_registration_code(role: str) -> str:
    if role == "super_admin":
        return os.getenv("SUPER_ADMIN_REGISTRATION_CODE", "").strip()
    return os.getenv("PETUGAS_REGISTRATION_CODE", "").strip()


def get_registration_label(role: str) -> str:
    labels = {
        SERVICE_USER_ROLE: "Pengguna Jasa",
        "monitoring": "Petugas Monitoring",
        "admin": "Admin",
        "super_admin": "Super Admin",
    }
    return labels.get(role, "Akun")


def redirect_after_login(user: User) -> str:
    if is_monitoring_user(user):
        return "/admin/dashboard"
    return "/dashboard"


def render_register(
    request: Request,
    templates: Jinja2Templates,
    *,
    register_type: str = "service_user",
    error: str | None = None,
    success: str | None = None,
    form_data: dict | None = None,
    status_code: int = status.HTTP_200_OK,
):
    return templates.TemplateResponse(
        request,
        "register.html",
        {
            "request": request,
            "register_type": register_type,
            "error": error,
            "success": success,
            "form_data": form_data or {},
        },
        status_code=status_code,
    )


def render_login(
    request: Request,
    templates: Jinja2Templates,
    *,
    login_type: str,
    error: str | None = None,
    success: str | None = None,
    form_data: dict | None = None,
    status_code: int = status.HTTP_200_OK,
):
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "request": request,
            "error": error,
            "success": success,
            "login_type": login_type,
            "form_data": form_data or {},
        },
        status_code=status_code,
    )


@router.get("/register")
def register_page(request: Request, templates: Jinja2Templates = Depends(get_templates)):
    return RedirectResponse(url="/register/pengguna-jasa", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/register/pengguna-jasa")
def register_service_user_page(request: Request, templates: Jinja2Templates = Depends(get_templates)):
    return render_register(
        request,
        templates,
        register_type="service_user",
        form_data={"role": SERVICE_USER_ROLE},
    )


@router.get("/register/petugas")
def register_internal_user_page(request: Request, templates: Jinja2Templates = Depends(get_templates)):
    return render_register(
        request,
        templates,
        register_type="internal",
        form_data={"role": "monitoring"},
    )


@router.post("/register")
def register_user(
    request: Request,
    role: str = Form(SERVICE_USER_ROLE),
    username: str = Form(""),
    company_name: str = Form(""),
    email: str = Form(...),
    business_id: str = Form(""),
    pic_name: str = Form(...),
    password: str = Form(...),
    registration_code: str = Form(""),
    db: Session = Depends(get_db),
    templates: Jinja2Templates = Depends(get_templates),
):
    role = role.strip()
    username = normalize_internal_username(username) if role in INTERNAL_REGISTRATION_ROLES else username.strip()
    company_name = company_name.strip()
    email = email.strip().lower()
    business_id = business_id.strip()
    pic_name = pic_name.strip()
    registration_code = registration_code.strip()

    form_data = {
        "role": role,
        "username": username,
        "company_name": company_name,
        "email": email,
        "business_id": business_id,
        "pic_name": pic_name,
        "registration_code": registration_code,
    }
    register_type = "internal" if role in INTERNAL_REGISTRATION_ROLES else "service_user"

    if role not in SELF_REGISTRATION_ROLES:
        return render_register(
            request,
            templates,
            register_type=register_type,
            error="Role pendaftaran tidak valid.",
            form_data=form_data,
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if not email or not pic_name:
        return render_register(
            request,
            templates,
            register_type=register_type,
            error="Email dan nama PIC wajib diisi.",
            form_data=form_data,
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if role == SERVICE_USER_ROLE and not all([company_name, business_id]):
        return render_register(
            request,
            templates,
            register_type=register_type,
            error="Untuk akun perusahaan, nama perusahaan dan nomor izin/NIB/NPWP wajib diisi.",
            form_data=form_data,
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if role in INTERNAL_REGISTRATION_ROLES and not username:
        return render_register(
            request,
            templates,
            register_type=register_type,
            error="Username wajib diisi untuk akun petugas.",
            form_data=form_data,
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if "@" not in email:
        return render_register(
            request,
            templates,
            register_type=register_type,
            error="Email tidak valid.",
            form_data=form_data,
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if len(password) < 8:
        return render_register(
            request,
            templates,
            register_type=register_type,
            error="Kata sandi minimal 8 karakter.",
            form_data=form_data,
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    expected_registration_code = get_internal_registration_code(role)
    if role in INTERNAL_REGISTRATION_ROLES:
        if not expected_registration_code:
            return render_register(
                request,
                templates,
                register_type=register_type,
                error="Pendaftaran akun internal belum diaktifkan. Set environment variable kode registrasi terlebih dahulu.",
                form_data=form_data,
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        if registration_code != expected_registration_code:
            return render_register(
                request,
                templates,
                register_type=register_type,
                error="Kode registrasi internal tidak valid.",
                form_data=form_data,
                status_code=status.HTTP_403_FORBIDDEN,
            )

    existing_user = db.query(User).filter(User.email == email).first()
    existing_username = None
    if username:
        existing_username = db.query(User).filter(func.lower(User.username) == username).first()

    if existing_user or existing_username:
        return render_register(
            request,
            templates,
            register_type=register_type,
            error="Email atau username sudah terdaftar.",
            form_data=form_data,
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    account_status = ACCOUNT_ACTIVE if role in INTERNAL_REGISTRATION_ROLES else get_registration_status()
    user = User(
        username=username or email,
        company_name=company_name if role == SERVICE_USER_ROLE else None,
        email=email,
        business_id=business_id if role == SERVICE_USER_ROLE else None,
        pic_name=pic_name,
        password_hash=hash_password(password),
        role=role,
        account_status=account_status,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    if account_status == ACCOUNT_ACTIVE:
        request.session.clear()
        request.session["user_id"] = user.id
        request.session["role"] = user.role
        request.session["username"] = user.username or user.pic_name or user.company_name or user.email
        log_audit_event(db, request, user.id, "login")
        return RedirectResponse(url=redirect_after_login(user), status_code=status.HTTP_303_SEE_OTHER)

    return render_register(
        request,
        templates,
        register_type=register_type,
        success=f"Pendaftaran {get_registration_label(role)} berhasil. Akun Anda menunggu verifikasi petugas sebelum bisa digunakan.",
    )


@router.get("/login")
def login_redirect():
    return RedirectResponse(url="/login/pengguna-jasa", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/login/pengguna-jasa")
def service_login_page(request: Request, templates: Jinja2Templates = Depends(get_templates)):
    return render_login(request, templates, login_type="service_user")


@router.post("/login/pengguna-jasa")
def service_login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
    templates: Jinja2Templates = Depends(get_templates),
):
    email = email.strip().lower()
    form_data = {"email": email}
    user = (
        db.query(User)
        .filter(User.email == email, User.role == SERVICE_USER_ROLE)
        .first()
    )

    if not user or not verify_password(password, user.password_hash):
        return render_login(
            request,
            templates,
            login_type="service_user",
            error="Email atau kata sandi tidak valid.",
            form_data=form_data,
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    if user.account_status != ACCOUNT_ACTIVE:
        return render_login(
            request,
            templates,
            login_type="service_user",
            error="Akun Anda masih menunggu verifikasi petugas.",
            form_data=form_data,
            status_code=status.HTTP_403_FORBIDDEN,
        )

    request.session.clear()
    request.session["user_id"] = user.id
    request.session["role"] = user.role
    request.session["username"] = user.pic_name or user.company_name or user.email
    log_audit_event(db, request, user.id, "login")

    return RedirectResponse(url=redirect_after_login(user), status_code=status.HTTP_303_SEE_OTHER)


@router.get("/login/petugas")
def monitoring_login_page(request: Request, templates: Jinja2Templates = Depends(get_templates)):
    return render_login(request, templates, login_type="monitoring")


@router.post("/login/petugas")
def monitoring_login(
    request: Request,
    identifier: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
    templates: Jinja2Templates = Depends(get_templates),
):
    identifier = identifier.strip()
    normalized_identifier = identifier.lower()
    form_data = {"identifier": identifier}
    user = (
        db.query(User)
        .filter(
            User.role.in_(MONITORING_ROLES),
            or_(func.lower(User.username) == normalized_identifier, User.email == normalized_identifier),
        )
        .first()
    )

    if not user or not verify_password(password, user.password_hash):
        return render_login(
            request,
            templates,
            login_type="monitoring",
            error="Akun petugas atau kata sandi tidak valid.",
            form_data=form_data,
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    if user.account_status != ACCOUNT_ACTIVE:
        return render_login(
            request,
            templates,
            login_type="monitoring",
            error="Akun petugas belum aktif.",
            form_data=form_data,
            status_code=status.HTTP_403_FORBIDDEN,
        )

    request.session.clear()
    request.session["user_id"] = user.id
    request.session["role"] = user.role
    request.session["username"] = user.username or user.pic_name or user.email
    log_audit_event(db, request, user.id, "login")

    return RedirectResponse(url=redirect_after_login(user), status_code=status.HTTP_303_SEE_OTHER)


@router.get("/logout")
def logout_user(request: Request):
    request.session.clear()
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)


def get_session_secret() -> str:
    return os.getenv("SESSION_SECRET_KEY", "change-this-session-secret-in-production")


def session_uses_https() -> bool:
    return os.getenv("SESSION_HTTPS_ONLY", "false").lower() == "true"
