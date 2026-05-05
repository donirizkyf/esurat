from sqlalchemy import Column, Date, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=True)
    company_name = Column(String(255), nullable=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    business_id = Column(String(100), nullable=True)
    pic_name = Column(String(255), nullable=True)
    staff_role = Column(String(50), nullable=True)
    section_name = Column(String(150), nullable=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(30), nullable=False, default="service_user")
    account_status = Column(String(20), nullable=False, default="PENDING")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    submissions = relationship("DocumentSubmission", back_populates="user")


class DocumentSubmission(Base):
    __tablename__ = "document_submissions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    document_id = Column(String(32), unique=True, index=True, nullable=False)
    bagian = Column(String(100), nullable=False, default="Perijinan Cukai")
    subject = Column(String(255), nullable=False)
    document_date = Column(Date, nullable=False)
    description = Column(Text, nullable=False)
    original_filename = Column(String(255), nullable=False)
    stored_filename = Column(String(255), nullable=False)
    receipt_original_filename = Column(String(255), nullable=True)
    receipt_stored_filename = Column(String(255), nullable=True)
    result_original_filename = Column(String(255), nullable=True)
    result_stored_filename = Column(String(255), nullable=True)
    agenda_number = Column(String(100), nullable=True, index=True)
    assigned_section = Column(String(150), nullable=True)
    assigned_staff_role = Column(String(50), nullable=True)
    status = Column(String(50), nullable=False, default="DIAJUKAN")
    admin_notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    user = relationship("User", back_populates="submissions")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    action = Column(String(50), nullable=False)
    document_id = Column(String(32), nullable=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    ip_address = Column(String(64), nullable=False)
