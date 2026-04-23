import argparse
import sys

from app.auth import ACCOUNT_ACTIVE, ACCOUNT_DEACTIVATED, ACCOUNT_PENDING, hash_password
from app.database import Base, SessionLocal, engine
from app.models import User
from app.schema import sync_schema


INTERNAL_ROLES = {"monitoring", "admin", "super_admin"}
ALL_ROLES = {"service_user", *INTERNAL_ROLES}
ALL_STATUSES = {ACCOUNT_ACTIVE, ACCOUNT_PENDING, ACCOUNT_DEACTIVATED}


def normalize_email(value: str) -> str:
    return value.strip().lower()


def default_internal_email(username: str) -> str:
    return f"{username.strip().lower()}@internal.local"


def get_user_by_identifier(db, identifier: str) -> User | None:
    normalized = identifier.strip().lower()
    return (
        db.query(User)
        .filter((User.username == identifier.strip()) | (User.email == normalized))
        .first()
    )


def create_user(args) -> int:
    db = SessionLocal()
    try:
        email = normalize_email(args.email) if args.email else default_internal_email(args.username)
        existing = db.query(User).filter((User.username == args.username) | (User.email == email)).first()
        if existing:
            print(f"Gagal: user dengan username/email tersebut sudah ada ({existing.username} / {existing.email}).")
            return 1

        user = User(
            username=args.username,
            email=email,
            company_name=args.company_name,
            business_id=args.business_id,
            pic_name=args.pic_name,
            password_hash=hash_password(args.password),
            role=args.role,
            account_status=args.status,
        )
        db.add(user)
        db.commit()
        print(f"OK create: username={user.username} email={user.email} role={user.role} status={user.account_status}")
        return 0
    finally:
        db.close()


def update_role(args) -> int:
    db = SessionLocal()
    try:
        user = get_user_by_identifier(db, args.identifier)
        if not user:
            print("Gagal: user tidak ditemukan.")
            return 1

        user.role = args.role
        if args.activate:
            user.account_status = ACCOUNT_ACTIVE
        db.commit()
        print(f"OK role: username={user.username} email={user.email} role={user.role} status={user.account_status}")
        return 0
    finally:
        db.close()


def set_status(args) -> int:
    db = SessionLocal()
    try:
        user = get_user_by_identifier(db, args.identifier)
        if not user:
            print("Gagal: user tidak ditemukan.")
            return 1

        user.account_status = args.status
        db.commit()
        print(f"OK status: username={user.username} email={user.email} status={user.account_status}")
        return 0
    finally:
        db.close()


def list_users(_args) -> int:
    db = SessionLocal()
    try:
        users = db.query(User).order_by(User.role.asc(), User.created_at.asc()).all()
        if not users:
            print("Belum ada user.")
            return 0

        print("username | email | role | status")
        for user in users:
            print(f"{user.username or '-'} | {user.email} | {user.role} | {user.account_status}")
        return 0
    finally:
        db.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Kelola akun internal sistem pengajuan dokumen.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    create_parser = subparsers.add_parser("create", help="Buat user baru.")
    create_parser.add_argument("--username", required=True)
    create_parser.add_argument("--password", required=True)
    create_parser.add_argument("--role", choices=sorted(ALL_ROLES), required=True)
    create_parser.add_argument("--status", choices=sorted(ALL_STATUSES), default=ACCOUNT_ACTIVE)
    create_parser.add_argument("--email")
    create_parser.add_argument("--company-name")
    create_parser.add_argument("--business-id")
    create_parser.add_argument("--pic-name")
    create_parser.set_defaults(handler=create_user)

    role_parser = subparsers.add_parser("set-role", help="Ubah role user.")
    role_parser.add_argument("--identifier", required=True, help="Username atau email.")
    role_parser.add_argument("--role", choices=sorted(ALL_ROLES), required=True)
    role_parser.add_argument("--activate", action="store_true")
    role_parser.set_defaults(handler=update_role)

    status_parser = subparsers.add_parser("set-status", help="Ubah status akun user.")
    status_parser.add_argument("--identifier", required=True, help="Username atau email.")
    status_parser.add_argument("--status", choices=sorted(ALL_STATUSES), required=True)
    status_parser.set_defaults(handler=set_status)

    list_parser = subparsers.add_parser("list", help="Lihat semua user.")
    list_parser.set_defaults(handler=list_users)
    return parser


def main() -> int:
    sync_schema()
    Base.metadata.create_all(bind=engine)
    parser = build_parser()
    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
